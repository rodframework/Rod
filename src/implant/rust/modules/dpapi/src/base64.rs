//! The base64 codec the verb rides (the module's whole encoding
//! surface, hand-rolled so the module owes the loader no dependency
//! for it): DPAPI blobs cross the task grammar as text, and the
//! unsealed plaintext rides back the same way when it is not text
//! itself. Standard alphabet, `=` padding, strict -- whitespace and
//! other alphabets refuse rather than decode half a blob.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decodes strict standard base64: `=` padding only at the end, no
/// whitespace, no alternative alphabets.
pub(crate) fn decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err("the blob is not valid base64 (length)".to_string());
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return Err("the blob is not valid base64 (padding)".to_string());
    }
    // Padding may only sit at the very end.
    if bytes[..bytes.len() - padding].contains(&b'=') {
        return Err("the blob is not valid base64 (padding)".to_string());
    }

    let mut decoded = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (group_index, group) in bytes.chunks(4).enumerate() {
        // Padding rides only the final group; earlier groups are full.
        let skipped = if group_index == groups - 1 {
            padding
        } else {
            0
        };
        let mut accumulated: u32 = 0;
        for (index, byte) in group.iter().enumerate() {
            let value = if index >= 4 - skipped {
                0
            } else {
                ALPHABET
                    .iter()
                    .position(|candidate| candidate == byte)
                    .ok_or_else(|| "the blob is not valid base64 (alphabet)".to_string())?
            };
            accumulated = (accumulated << 6) | value as u32;
        }
        decoded.push((accumulated >> 16) as u8);
        decoded.push((accumulated >> 8) as u8);
        decoded.push(accumulated as u8);
    }
    decoded.truncate(bytes.len() / 4 * 3 - padding);
    Ok(decoded)
}

/// Encodes standard base64 with `=` padding.
pub(crate) fn encode(plain: &[u8]) -> String {
    let mut text = String::with_capacity(plain.len().div_ceil(3) * 4);
    for group in plain.chunks(3) {
        let mut accumulated: u32 = (group[0] as u32) << 16;
        if group.len() > 1 {
            accumulated |= (group[1] as u32) << 8;
        }
        if group.len() > 2 {
            accumulated |= group[2] as u32;
        }
        text.push(ALPHABET[(accumulated >> 18) as usize & 0x3F] as char);
        text.push(ALPHABET[(accumulated >> 12) as usize & 0x3F] as char);
        text.push(if group.len() > 1 {
            ALPHABET[(accumulated >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        text.push(if group.len() > 2 {
            ALPHABET[accumulated as usize & 0x3F] as char
        } else {
            '='
        });
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_codec_round_trips_the_rfc_vectors() {
        for (plain, text) in [
            (&b"Man"[..], "TWFu"),
            (&b"Ma"[..], "TWE="),
            (&b"M"[..], "TQ=="),
            (b"any carnal pleasure.", "YW55IGNhcm5hbCBwbGVhc3VyZS4="),
            (b"Sure.", "U3VyZS4="),
        ] {
            assert_eq!(encode(plain), text);
            assert_eq!(decode(text).unwrap(), plain);
        }
    }

    #[test]
    fn arbitrary_bytes_round_trip() {
        let plain: Vec<u8> = (0u16..255).map(|value| value as u8).collect();
        assert_eq!(decode(&encode(&plain)).unwrap(), plain);
    }

    #[test]
    fn malformed_input_refuses_naming_the_flaw() {
        assert!(decode("").unwrap_err().contains("length"));
        assert!(decode("TQ=").unwrap_err().contains("length"));
        assert!(decode("T Q=").unwrap_err().contains("alphabet"));
        assert!(decode("T-Q=").unwrap_err().contains("alphabet"));
        assert!(decode("T=Q=").unwrap_err().contains("padding"));
        assert!(decode("TQ==TQ==").unwrap_err().contains("padding"));
        // The output half never emits what the input half refuses.
        assert!(decode(&encode(b"x")).is_ok());
    }
}
