//! Security-descriptor parsing for the `acls` scope: the DACL out of a
//! directory object's `nTSecurityDescriptor`, its ACEs' masks and
//! trustee SIDs, and the names the escalation reads key on. Pure
//! byte-walking over the self-relative descriptor Windows serves
//! ([MS-DTYP] -- little-endian, unlike the BER the LDAP wire carries):
//! revision header, the four section offsets, the DACL's ACE array.
//!
//! The sweep reports grants only (ACCESS_ALLOWED and
//! ACCESS_ALLOWED_OBJECT ACEs): a deny ACE grants nothing, and listing
//! denials would drown the read in rows no escalation path follows.

/// One grant ACE off a DACL: its access mask, its object type when the
/// ACE is an object ACE scoping a specific extended right or property,
/// and the trustee SID bytes.
pub(crate) struct Ace {
    pub inherited: bool,
    pub mask: u32,
    pub object_type: Option<[u8; 16]>,
    pub trustee: Vec<u8>,
}

/// The grant ACEs of a self-relative descriptor's DACL. Every malformed
/// shape -- wrong revision, absent DACL, truncated walk -- answers the
/// empty list: the sweep reports no ACL rather than a guessed one.
pub(crate) fn allowed_aces(descriptor: &[u8]) -> Vec<Ace> {
    let mut aces = Vec::new();
    if descriptor.len() < 20 || descriptor[0] != 1 {
        return aces;
    }
    let offset = u32::from_le_bytes([
        descriptor[16],
        descriptor[17],
        descriptor[18],
        descriptor[19],
    ]);
    if offset == 0 {
        return aces;
    }
    let acl = descriptor.get(offset as usize..).unwrap_or(&[]);
    if acl.len() < 8 {
        return aces;
    }
    let count = u16::from_le_bytes([acl[4], acl[5]]) as usize;
    let mut at = 8;
    for _ in 0..count {
        let Some(header) = acl.get(at..at + 4) else {
            break;
        };
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        if size < 8 {
            break; // an ACE smaller than header plus mask cannot be walked
        }
        let Some(ace) = acl.get(at..at + size) else {
            break;
        };
        at += size;
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        // 0x00 allowed, 0x05 allowed-object; every other ACE type is
        // not a grant and steps aside by size.
        let (object_type, sid_at) = match header[0] {
            0x00 => (None, 8),
            0x05 => {
                if ace.len() < 12 {
                    continue;
                }
                let flags = u32::from_le_bytes([ace[8], ace[9], ace[10], ace[11]]);
                let mut cursor = 12;
                let mut object_type = None;
                if flags & 0x1 != 0 {
                    object_type = ace.get(cursor..cursor + 16).and_then(|g| g.try_into().ok());
                    cursor += 16;
                }
                if flags & 0x2 != 0 {
                    cursor += 16;
                }
                (object_type, cursor)
            }
            _ => continue,
        };
        if let Some(sid) = ace.get(sid_at..) {
            aces.push(Ace {
                inherited: header[1] & 0x10 != 0,
                mask,
                object_type,
                trustee: sid.to_vec(),
            });
        }
    }
    aces
}

/// A SID rendered to its string form (`S-1-5-21-...`): revision 1,
/// big-endian authority, little-endian subauthorities ([MS-DTYP]).
/// Trailing bytes past the subauthority count are ignored -- the ACE's
/// own size, not the SID's, delimits it on the wire.
pub(crate) fn sid_string(sid: &[u8]) -> Option<String> {
    if sid.len() < 8 || sid[0] != 1 {
        return None;
    }
    let count = sid[1] as usize;
    if sid.len() < 8 + count * 4 {
        return None;
    }
    let authority = u64::from_be_bytes([0, 0, sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]]);
    let mut text = format!("S-1-{authority}");
    for index in 0..count {
        let at = 8 + index * 4;
        let rid = u32::from_le_bytes([sid[at], sid[at + 1], sid[at + 2], sid[at + 3]]);
        text.push_str(&format!("-{rid}"));
    }
    Some(text)
}

/// The escalation-relevant generic rights an access mask carries, in
/// canonical order. The control-access bit (0x100) is not here: its
/// meaning depends on whether the ACE scopes an object type, so the
/// caller renders it.
pub(crate) fn generic_rights(mask: u32) -> Vec<&'static str> {
    let mut rights = Vec::new();
    let table: [(u32, &str); 6] = [
        (0x10000000, "GenericAll"),
        (0x40000000, "GenericWrite"),
        (0x00040000, "WriteDacl"),
        (0x00080000, "WriteOwner"),
        (0x00000020, "WriteProperty"),
        (0x00000010, "Self"),
    ];
    for (bit, name) in table {
        if mask & bit == bit {
            rights.push(name);
        }
    }
    rights
}

/// The name of a control-access object type: the extended rights whose
/// grants are the escalation reads (DCSync's replication trio, forced
/// password reset) and the member-property write. An unknown GUID
/// renders as itself -- unnamed, not unnamed-and-skipped, since an
/// exotic right is still a right the operator should see.
pub(crate) fn object_right(guid: &[u8; 16]) -> String {
    let known = match guid_string(guid).as_str() {
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" => Some("DS-Replication-Get-Changes"),
        "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2" => {
            Some("DS-Replication-Get-Changes-In-Filtered-Set")
        }
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" => Some("DS-Replication-Get-Changes-All"),
        "00299570-246d-11d0-a768-00aa006e0529" => Some("User-Force-Change-Password"),
        "bf9679c0-0de6-11d0-a285-00aa003049e2" => Some("Write-Members"),
        _ => None,
    };
    known
        .map(str::to_string)
        .unwrap_or_else(|| format!("extended:{}", guid_string(guid)))
}

/// A GUID in its canonical string form: the first three groups
/// little-endian, the last two big-endian -- the mixed order [MS-DTYP]
/// serialization uses and directory tooling prints.
pub(crate) fn guid_string(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{}",
        guid[8],
        guid[9],
        guid[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// The absolute well-known SIDs the escalation reads meet: named once
/// here rather than resolved against the directory (which does not hold
/// them under the domain naming context).
pub(crate) fn well_known(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-1-0" => Some("Everyone"),
        "S-1-5-11" => Some("Authenticated-Users"),
        "S-1-5-18" => Some("SYSTEM"),
        "S-1-5-32-544" => Some("Builtin-Administrators"),
        _ => None,
    }
}

/// The domain-relative RIDs whose names matter to an escalation read:
/// when the trustee SID sits under the domain's own SID, its last
/// subauthority names the principal's role.
pub(crate) fn domain_rid(sid: &str, domain_sid: &str) -> Option<&'static str> {
    let rid = sid.strip_prefix(domain_sid)?.strip_prefix('-')?;
    match rid {
        "512" => Some("Domain-Admins"),
        "513" => Some("Domain-Users"),
        "516" => Some("Domain-Controllers"),
        "519" => Some("Enterprise-Admins"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one self-relative descriptor: revision 1, owner, group,
    /// and SACL absent, the DACL built from the ACE bytes handed in.
    fn descriptor_with_count(count: u16, aces: &[u8]) -> Vec<u8> {
        let acl = [
            &[2u8, 0][..],
            &((aces.len() + 8) as u16).to_le_bytes()[..],
            &count.to_le_bytes()[..],
            &[0, 0][..],
            aces,
        ]
        .concat();
        let mut out = vec![1u8, 0];
        out.extend_from_slice(&0u16.to_le_bytes()); // control
        out.extend_from_slice(&0u32.to_le_bytes()); // owner offset: absent
        out.extend_from_slice(&0u32.to_le_bytes()); // group offset: absent
        out.extend_from_slice(&0u32.to_le_bytes()); // sacl offset: absent
        out.extend_from_slice(&20u32.to_le_bytes()); // dacl offset: right after the header
        out.extend_from_slice(&acl);
        out
    }

    fn allowed_ace(mask: u32, trustee: &[u8]) -> Vec<u8> {
        let size = 4 + 4 + trustee.len();
        [
            &[0x00u8, 0x00][..],
            &(size as u16).to_le_bytes()[..],
            &mask.to_le_bytes()[..],
            trustee,
        ]
        .concat()
    }

    fn denied_ace(mask: u32, trustee: &[u8]) -> Vec<u8> {
        let size = 4 + 4 + trustee.len();
        [
            &[0x01u8, 0x00][..],
            &(size as u16).to_le_bytes()[..],
            &mask.to_le_bytes()[..],
            trustee,
        ]
        .concat()
    }

    fn object_ace(mask: u32, object_type: [u8; 16], trustee: &[u8]) -> Vec<u8> {
        let size = 4 + 4 + 4 + 16 + trustee.len();
        [
            &[0x05u8, 0x00][..],
            &(size as u16).to_le_bytes()[..],
            &mask.to_le_bytes()[..],
            &0x1u32.to_le_bytes()[..], // AceObjectType present, InheritedObjectType absent
            &object_type[..],
            trustee,
        ]
        .concat()
    }

    fn domain_admins_sid() -> Vec<u8> {
        // S-1-5-21-1000-2000-512, built by hand: revision 1, four
        // subauthorities (21, 1000, 2000, 512), little-endian RIDs.
        [
            &[1u8, 4][..],
            &[0, 0, 0, 0, 0, 5][..], // authority 5
            &21u32.to_le_bytes()[..],
            &1000u32.to_le_bytes()[..],
            &2000u32.to_le_bytes()[..],
            &512u32.to_le_bytes()[..],
        ]
        .concat()
    }

    /// The Authenticated Users SID (S-1-5-11), built by hand: revision
    /// 1, one subauthority, authority 5, RID 11 little-endian.
    fn authenticated_users_sid() -> Vec<u8> {
        [
            &[1u8, 1][..],
            &[0, 0, 0, 0, 0, 5][..],
            &11u32.to_le_bytes()[..],
        ]
        .concat()
    }

    #[test]
    fn a_dacls_grants_walk_out_of_the_descriptor() {
        let generic_all = 0x10000000u32;
        let aces = [
            allowed_ace(generic_all, &domain_admins_sid()),
            denied_ace(generic_all, b"\x01\x05ignored"), // denials step aside by size
            object_ace(0x100, dcsync_guid(), &authenticated_users_sid()),
        ]
        .concat();
        let descriptor = descriptor_with_count(3, &aces);
        let grants = allowed_aces(&descriptor);
        assert_eq!(grants.len(), 2, "the deny ACE is not a grant");
        assert_eq!(grants[0].mask, generic_all);
        assert_eq!(
            sid_string(&grants[0].trustee).as_deref(),
            Some("S-1-5-21-1000-2000-512")
        );
        assert!(grants[0].object_type.is_none());
        assert_eq!(grants[1].mask, 0x100);
        assert_eq!(sid_string(&grants[1].trustee).as_deref(), Some("S-1-5-11"));
        let guid = grants[1].object_type.expect("object ACE carries its type");
        assert_eq!(guid_string(&guid), "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
    }

    #[test]
    fn inherited_aces_mark_their_flag() {
        let mut ace = allowed_ace(0x40000, b"\x01\x05\x00...");
        ace[1] = 0x10; // INHERITED_ACE
        let descriptor = descriptor_with_count(1, &ace);
        let grants = allowed_aces(&descriptor);
        assert_eq!(grants.len(), 1);
        assert!(grants[0].inherited);
    }

    #[test]
    fn malformed_descriptors_answer_no_aces_not_guesses() {
        assert!(allowed_aces(&[]).is_empty());
        assert!(allowed_aces(&[0u8; 19]).is_empty()); // short header
        let mut no_dacl = vec![1u8, 0];
        no_dacl.resize(20, 0); // revision right, dacl offset zero: absent
        assert!(allowed_aces(&no_dacl).is_empty());
        let mut wrong_revision = descriptor_with_count(0, &[]);
        wrong_revision[0] = 2;
        assert!(allowed_aces(&wrong_revision).is_empty());
        // A truncated ACE walk stops at the break, keeping prior grants.
        let whole = [
            allowed_ace(0x20, &authenticated_users_sid()),
            allowed_ace(0x20, b"\x01\x05"),
        ]
        .concat();
        let mut truncated = descriptor_with_count(2, &whole);
        truncated.truncate(truncated.len() - 2); // cut the last ACE mid-SID
        assert_eq!(allowed_aces(&truncated).len(), 1);
    }

    fn dcsync_guid() -> [u8; 16] {
        // 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 in [MS-DTYP] mixed order:
        // first three groups little-endian.
        [
            0xad, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2,
            0xdc, 0xd2,
        ]
    }

    #[test]
    fn masks_name_their_generic_rights() {
        assert_eq!(generic_rights(0x10000000), vec!["GenericAll"]);
        assert_eq!(
            generic_rights(0x40000 | 0x80000),
            vec!["WriteDacl", "WriteOwner"]
        );
        assert!(
            generic_rights(0x80000000).is_empty(),
            "GenericRead is not an escalation right"
        );
        // 0x100 renders only through the object-type-aware caller.
        assert!(generic_rights(0x100).is_empty());
    }

    #[test]
    fn object_rights_name_the_escalation_guids() {
        assert_eq!(
            object_right(&dcsync_guid()),
            "DS-Replication-Get-Changes-All"
        );
        // An unknown GUID stands as itself, prefixed so the row says it
        // is an extended right the table does not name.
        let unknown = [7u8; 16];
        assert_eq!(
            object_right(&unknown),
            format!("extended:{}", guid_string(&unknown))
        );
    }

    #[test]
    fn sids_render_in_the_canonical_form() {
        assert_eq!(
            sid_string(&domain_admins_sid()).as_deref(),
            Some("S-1-5-21-1000-2000-512")
        );
        assert_eq!(
            sid_string(b"\x01\x02\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x0b\x00\x00\x00")
                .as_deref(),
            Some("S-1-5-11-11")
        );
        assert_eq!(
            sid_string(b"\x02\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00"),
            None,
            "revision"
        );
        assert_eq!(sid_string(b"\x01\x02\x00\x00"), None, "truncated");
        // The Everyone SID, whose authority digit is small enough to
        // exercise the 48-bit authority read.
        assert_eq!(
            sid_string(b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00").as_deref(),
            Some("S-1-1-0")
        );
    }

    #[test]
    fn trustee_names_resolve_through_the_well_known_and_rid_tables() {
        assert_eq!(well_known("S-1-1-0"), Some("Everyone"));
        assert_eq!(well_known("S-1-5-11"), Some("Authenticated-Users"));
        assert_eq!(well_known("S-1-5-21-1000-2000-999"), None);
        assert_eq!(
            domain_rid("S-1-5-21-1000-2000-512", "S-1-5-21-1000-2000"),
            Some("Domain-Admins")
        );
        // A RID under another domain's SID is not this domain's role.
        assert_eq!(domain_rid("S-1-5-21-9999-512", "S-1-5-21-1000-2000"), None);
        assert_eq!(
            domain_rid("S-1-5-21-1000-2000-1103", "S-1-5-21-1000-2000"),
            None
        );
    }
}
