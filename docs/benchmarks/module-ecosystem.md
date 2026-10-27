# Module ecosystem benchmark note

How capabilities arrive after the kernel stops growing: the module
ecosystem -- manifest, registry index, CLI, signatures, lock
([architecture.md Sec 15.2](../architecture.md); ADR-002, ADR-003,
ADR-009). Rod ships today the seams (the `ICapabilityModule` contract,
the implant handler overlay, the in-tree module host with `hostenum` as
the reference pair) and the `rod mod` suite over them: `init`,
`search`, `info`, `install`, `verify`, `publish`, the
`rod-module.toml` manifest, the `rod-registry` static git index, and a
lock file recording what landed. The field's module ecosystems are the
benchmark; so are the general-purpose package managers whose
distribution shape the registry deliberately ports (the Homebrew tap).
The index's governance is decided: an organization tap under the GitHub
organization ADR-011 creates, third-party taps available by
construction.

## The tools

| Tool | Product shape at the interaction layer | License |
|------|----------------------------------------|---------|
| Mythic | Per-agent and per-C2-profile repositories, each versioned on its own; installing an agent means docker-compose services against the Mythic server; the UI browses whatever is loaded | BSD-3-Clause (per project repository); ecosystem repositories vary, each checked |
| Sliver (Armory) | An in-client catalog command: search, install, update of extensions fetched from armory repositories; versions managed client-side | GPLv3 (framework); conclusions only, never code |
| Cobalt Strike | Aggressor scripts loaded into the teamserver; the Community Kit is a curated listing page of third-party tooling; BOFs as a compile-target format | Proprietary (Fortra); published product behavior only |
| Metasploit | The module library as the product's bulk: thousands of modules in-tree, `search` over rich metadata (rank, disclosure date, author), one repo ships everything | BSD-3-Clause (Rapid7) |
| Havoc | Teamserver-side Python extensions loaded from files; per-operator scripts rather than a shared catalog | GPL-3.0 |
| Homebrew | The tap: a git repository *is* the index, one file per package; install and update are git fetch plus script evaluation; third-party taps are just more repositories | BSD-2-Clause (package manager) |
| Cargo | The package workflow's grammar: manifest per crate, registry index, `Cargo.lock` pinning exact versions and checksums; the registry is a standing service | MIT OR Apache-2.0 |

## Adopt

- **The git repository as the whole registry** (Homebrew's tap shape).
  No server, no database, no standing component; a mirror is optional
  static hosting. This is not a preference -- it is the hard constraint
  (Sec 15) that no ecosystem above satisfies: Mythic's carrier is
  compose services, Cargo's is a registry service. Rod's index is
  `rod-registry`, one JSON file per module, contributed by pull request
  -- the lowest contribution threshold the field knows (ADR-002).
- **One self-describing manifest per module repository** (Mythic's
  independently versioned agent repositories; Cargo's manifest).
  `rod-module.toml` carries name, version, entry kind, compatibility
  matrix, OPSEC metadata, ATT&CK techniques, license -- the package
  answers every question the catalog and the installer ask, so the
  index is a pointer set, not a second source of truth (ADR-009).
- **Search-time metadata richness** (Metasploit's `search`; Armory's
  catalog listing). An operator picking a module sees the OPSEC marks
  and the ATT&CK techniques before installing anything; the catalog is a
  decision surface, not a name list. Lands in the CLI output and in the
  UI, where the contract trilogy's schema renders the task form and the
  output taxonomy routes results to the panels for any registered verb
  (ADR-003, ADR-013 -- shipped).
- **Install-time verification and a lock file** (Cargo's lock with
  checksums). `rod mod install name@version` verifies the package
  digest and the signature before anything lands; the lock file
  records digest, signature, and key fingerprint per module, and
  `rod mod verify` re-proves an installed tree against it -- the
  same reconciling posture a deployment owes everything it runs.
- **Explicit, versioned installs** (Cargo's `name@version` grammar).
  Engagements want reproducible stacks: the lock pins what an
  engagement ran with, and upgrades are a deliberate command, never a
  background fetch.

## Skip

- **A running registry service or database** (crates.io, npm's shape).
  Violates the standing-component constraint (Sec 15); the git index
  with an optional static mirror replaces it entirely.
- **Container-per-module packaging** (Mythic's agents as compose
  services). A second deployment shape Rod will not carry: a module is
  a manifest, an assembly, or a handler file the existing process loads
  through its config-listed path, not a service fleet to orchestrate
  (Sec 15.1).
- **The in-tree monolithic module library** (Metasploit's thousands of
  modules shipping with the framework). Breadth grows in the module
  layer and the registry, quality before quantity, from zero with no
  carry-over (Sec 15.2): no BOF/COFF execution layer, no Armory
  migration. The tree ships reference modules only.
- **Install-time code execution** (package-manager install hooks).
  Installing is fetch, hash, verify, extract -- no script runs as part
  of it. The trust chain is signatures, not the package's own code
  (ADR-002), and a module's code runs inside the engagement's
  authorization, never at install time.
- **Automatic background updates** (package managers' auto-update
  posture). An engagement's module set is deliberate state; the lock
  file is the operator's record and `rod mod install` the only thing
  that changes it.

## Divergences Rod already owns

Every tool above vouches by platform: Mythic trusts the containers it is
handed, Armory trusts the repositories it clones, Metasploit trusts its
own tree. Rod's registry vouches for nothing -- the signature does:
every entry carries the publisher's Ed25519 public key and a signature
over the manifest's canonical form plus every payload digest, pinned
per module name in the lock at first install, and re-provable offline
by `rod mod verify` against any installed tree. No benchmark tool
carries OPSEC metadata in its package format either ("lands on disk" /
"memory only" as catalog fields, ADR-009) or checks a compatibility
matrix -- implant class, platform, arch, minimum teamserver, and the
per-verb floors of the version matrix -- before letting a version land
(ADR-003's third contract). And none ships the typed contracts the
trilogy adds on top: parameter schemas that render the tasking form for
a verb the UI has never met, and an output taxonomy that routes any
module's structured results into the credential, file, process, and
topology panels (ADR-003 -- shipped). The catalog states
what a module does to the target before an operator ever fetches it;
the field's catalogs state what a module does at most.
