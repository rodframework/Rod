//! The portable-executable import reader (the module's whole parse
//! surface): the DLL names a binary imports, read out of its own bytes
//! with no platform call at all -- the file arrives as a slice, so
//! this half runs and its tests pin it on any host. Only the loading
//! of the file sits behind `cfg(windows)`, and the Windows crosses the
//! CI lane builds prove that half compiles.
//!
//! The reader walks the documented layout exactly -- DOS header to NT
//! headers to the optional header's second data directory to the
//! section table that turns RVAs into file offsets to the import
//! descriptor array -- and refuses at every boundary: a truncated or
//! malformed image is an error naming the offender, never a guessed
//! import list. Delay-loaded imports ride a later directory than the
//! one this reader walks; they are this module's later widening, not
//! v1.0's surface.

/// The DLL names the image imports, as the names sit in the file
/// (case untouched -- the loader compares case-insensitively, and so
/// do the callers that match a seat against this list).
pub(crate) fn import_names(image: &[u8]) -> Result<Vec<String>, String> {
    let import_rva = import_table_rva(image)?;
    if import_rva == 0 {
        // No import table: an image that loads nothing from elsewhere
        // has no seat to claim.
        return Ok(Vec::new());
    }
    let sections = SectionTable::read(image)?;

    let mut names = Vec::new();
    let mut offset = sections.file_offset(image, import_rva)?;
    loop {
        let descriptor = read_slice(image, offset, 20, "an import descriptor")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_rva = u32_at(descriptor, 12);
        let name_offset = sections.file_offset(image, name_rva)?;
        let name = read_ascii_z(image, name_offset)?;
        if !name.is_empty() {
            names.push(name);
        }
        offset += 20;
    }
    Ok(names)
}

/// Walks the headers to the import table's RVA: DOS signature, NT
/// signature, the optional header's kind (whose fixed part differs
/// between PE32 and PE32+), then the second data directory.
fn import_table_rva(image: &[u8]) -> Result<u32, String> {
    if read_slice(image, 0, 2, "the DOS header")? != b"MZ" {
        return Err("not a portable executable: the DOS signature is absent".to_string());
    }
    let nt_offset = u32_at(image, 0x3C) as usize;
    if read_slice(image, nt_offset, 4, "the NT signature")? != b"PE\0\0" {
        return Err("not a portable executable: the PE signature is absent".to_string());
    }

    let file_header = nt_offset + 4;
    let optional = file_header + 20;
    let directories = optional
        + match u16_at(image, optional) {
            0x210B => 96,
            0x20B => 112,
            other => {
                return Err(format!(
                    "not a portable executable: unknown optional-header magic 0x{other:X}"
                ))
            }
        };
    // The second directory (index 1) is the import table.
    Ok(u32_at(
        read_slice(image, directories + 8, 4, "the import directory")?,
        0,
    ))
}

/// The section table: the loader's own map from RVAs to file offsets.
struct SectionTable {
    offset: usize,
    count: usize,
}

impl SectionTable {
    fn read(image: &[u8]) -> Result<SectionTable, String> {
        let nt_offset = u32_at(image, 0x3C) as usize;
        let file_header = nt_offset + 4;
        let count = u16_at(image, file_header + 2) as usize;
        let optional_size = u16_at(image, file_header + 16) as usize;
        let offset = file_header + 20 + optional_size;
        let end = offset
            .checked_add(
                count
                    .checked_mul(40)
                    .ok_or("the section table overflows the file")?,
            )
            .ok_or("the section table overflows the file")?;
        if end > image.len() {
            return Err("truncated image: the section table runs past the file".to_string());
        }
        Ok(SectionTable { offset, count })
    }

    /// The file offset an RVA lands on, through the section that
    /// carries it. An RVA outside every section refuses -- guessing an
    /// identity mapping is how a reader silently invents imports.
    fn file_offset(&self, image: &[u8], rva: u32) -> Result<usize, String> {
        for index in 0..self.count {
            let header = self.offset + index * 40;
            // The fields the map needs: virtual size (8), virtual
            // address (12), raw size (16), raw pointer (20).
            let virtual_size = u32_at(image, header + 8);
            let virtual_address = u32_at(image, header + 12);
            let raw_size = u32_at(image, header + 16);
            let raw_pointer = u32_at(image, header + 20);
            let span = virtual_size.max(raw_size);
            if raw_size == 0 {
                continue;
            }
            if virtual_address <= rva && rva < virtual_address + span {
                return Ok((rva - virtual_address + raw_pointer) as usize);
            }
        }
        Err(format!(
            "malformed image: RVA 0x{rva:X} lies outside every section"
        ))
    }
}

fn read_slice<'a>(
    image: &'a [u8],
    offset: usize,
    length: usize,
    what: &str,
) -> Result<&'a [u8], String> {
    let end = offset.checked_add(length).ok_or("truncated image")?;
    image
        .get(offset..end)
        .ok_or_else(|| format!("truncated image: {what} runs past the file"))
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// An imported name: bytes the linker wrote, read to the NUL. Import
/// names are ASCII by construction; anything longer than absurd or
/// past the file's end refuses rather than truncating.
fn read_ascii_z(image: &[u8], offset: usize) -> Result<String, String> {
    let rest = image
        .get(offset..)
        .ok_or("truncated image: an imported name runs past the file")?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("truncated image: an imported name has no terminator")?;
    if end > 256 {
        return Err("malformed image: an imported name is absurdly long".to_string());
    }
    Ok(rest[..end].iter().map(|byte| *byte as char).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but honest PE32+ image the tests shape at will: one
    /// section mapping RVA 0x1000.. to file offset 0x200, an import
    /// directory with the names the caller chooses.
    fn minimal_image(names: &[&str]) -> Vec<u8> {
        let import_rva = 0x1000;
        // Layout the names after the descriptor array so each name's
        // RVA is known when the descriptors are written.
        let descriptors = names.len() + 1; // plus the all-zero terminator
        let names_file_offset = 0x200 + descriptors * 20;
        let names_rva = import_rva + (names_file_offset - 0x200) as u32;

        let mut name_bytes: Vec<u8> = Vec::new();
        let mut rvas = Vec::new();
        for name in names {
            rvas.push(names_rva + name_bytes.len() as u32);
            name_bytes.extend_from_slice(name.as_bytes());
            name_bytes.push(0);
        }

        let mut image = vec![0u8; names_file_offset.max(0x400) + name_bytes.len()];
        image[0] = b'M';
        image[1] = b'Z';
        image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());

        let nt = 0x40;
        image[nt..nt + 4].copy_from_slice(b"PE\0\0");
        image[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
        image[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes()); // one section
        let optional_size = 240u16; // PE32+ fixed part + 16 directories
        image[nt + 20..nt + 22].copy_from_slice(&optional_size.to_le_bytes());

        let optional = nt + 24;
        image[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        let directories = optional + 112;
        image[directories + 8..directories + 12].copy_from_slice(&import_rva.to_le_bytes());
        image[directories + 12..directories + 16]
            .copy_from_slice(&((descriptors * 20) as u32).to_le_bytes());

        // The section: RVA 0x1000 lands at file offset 0x200.
        let section = optional + optional_size as usize;
        image[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // address
        image[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw pointer

        // The named import descriptors at 0x200, then the all-zero
        // terminator, then the names at the offset their RVAs claim.
        let mut at = 0x200;
        for rva in rvas {
            image[at + 12..at + 16].copy_from_slice(&rva.to_le_bytes());
            at += 20;
        }
        let at = names_file_offset;
        image[at..at + name_bytes.len()].copy_from_slice(&name_bytes);
        image
    }

    #[test]
    fn the_imports_read_as_the_linker_wrote_them() {
        let image = minimal_image(&["KERNEL32.dll", "VERSION.DLL", "USER32.dll"]);
        assert_eq!(
            import_names(&image).unwrap(),
            vec!["KERNEL32.dll", "VERSION.DLL", "USER32.dll"]
        );
    }

    #[test]
    fn an_image_without_an_import_table_reads_empty() {
        let mut image = minimal_image(&[]);
        // Zero the directory's rva: no imports declared.
        let optional = 0x40 + 24;
        image[optional + 112 + 8..optional + 112 + 12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(import_names(&image).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn malformed_images_refuse_naming_the_offender() {
        // Not MZ.
        let mut image = minimal_image(&["VERSION.DLL"]);
        image[0] = b'X';
        assert!(import_names(&image).unwrap_err().contains("DOS signature"));

        // Not PE.
        let mut image = minimal_image(&["VERSION.DLL"]);
        image[0x40] = b'X';
        assert!(import_names(&image).unwrap_err().contains("PE signature"));

        // The NT offset runs past the file.
        let mut image = minimal_image(&["VERSION.DLL"]);
        image[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(import_names(&image).unwrap_err().contains("truncated"));

        // The import RVA lies outside every section.
        let mut image = minimal_image(&["VERSION.DLL"]);
        let optional = 0x40 + 24;
        image[optional + 112 + 8..optional + 112 + 12].copy_from_slice(&0x9000u32.to_le_bytes());
        assert!(import_names(&image)
            .unwrap_err()
            .contains("outside every section"));

        // Truncated mid-image.
        let image = minimal_image(&["VERSION.DLL"]);
        assert!(import_names(&image[..0x210])
            .unwrap_err()
            .contains("truncated"));
    }
}
