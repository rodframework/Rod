//! The portable-executable section reader (the module's whole parse
//! surface): the `.text` span of an image -- ntdll's executable code
//! -- read out of the image's own bytes with no platform call at all.
//! Both images arrive as slices (the disk copy as the file read it,
//! the mapped copy as the module's base pointer spans it), so this
//! half runs and its tests pin it on any host. Only the reads behind
//! the slices sit behind `cfg(windows)`, and the Windows crosses the
//! CI lane builds prove that half compiles.
//!
//! The reader walks the documented layout exactly -- DOS header to NT
//! headers to the section table -- and refuses at every boundary: a
//! truncated or malformed image is an error naming the offender, and
//! two images that are not one build refuse before either could
//! rewrite the other, never a guessed restore.

/// The section a fresh copy rewrites, as the section table names it:
/// eight bytes, NUL-padded, the linker's own spelling.
const TEXT_NAME: &[u8] = b".text\0\0\0";

/// The one section this module addresses: ntdll's code, as the
/// section header carries it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TextSection {
    /// How many bytes the section spans once mapped (the loader's
    /// unit, tail rounded up past what the file carries).
    pub virtual_size: u32,
    /// Where the section sits in the image, off its base.
    pub rva: u32,
    /// How many bytes of it the file carries.
    pub raw_size: u32,
    /// Where those bytes sit in the file.
    pub raw_pointer: u32,
}

/// The `.text` section header out of an image's own bytes. The span
/// the two views share is `min(virtual_size, raw_size)`: the bytes
/// the file actually carries.
pub(crate) fn text_section(image: &[u8]) -> Result<TextSection, String> {
    let layout = layout(image)?;
    for index in 0..layout.count {
        let header = layout.sections + index * 40;
        if read_slice(image, header, 8, "a section name")? != TEXT_NAME {
            continue;
        }
        return Ok(TextSection {
            virtual_size: u32_at(image, header + 8),
            rva: u32_at(image, header + 12),
            raw_size: u32_at(image, header + 16),
            raw_pointer: u32_at(image, header + 20),
        });
    }
    Err(
        "malformed image: no .text section -- the image carries no code this \
         module addresses"
            .to_string(),
    )
}

/// The disk copy's `.text` bytes, as they sit in the file: the slice
/// plus the section it read. A section past the file's end refuses
/// rather than handing back half its bytes.
pub(crate) fn disk_text(image: &[u8]) -> Result<(&[u8], TextSection), String> {
    let section = text_section(image)?;
    let length = spanned(&section)?;
    let offset = section.raw_pointer as usize;
    let end = offset
        .checked_add(length)
        .ok_or("malformed image: the .text extent overflows the file")?;
    let bytes = image
        .get(offset..end)
        .ok_or("truncated image: .text runs past the file")?;
    Ok((bytes, section))
}

/// Where the same section sits in a mapped image: its offset from the
/// base and its length. The mapped span runs off the RVA -- the
/// loader's own map -- bounded by the mapped length the caller holds.
pub(crate) fn mapped_text(
    section: &TextSection,
    mapped_len: usize,
) -> Result<(usize, usize), String> {
    let length = spanned(section)?;
    let offset = section.rva as usize;
    let end = offset
        .checked_add(length)
        .ok_or("malformed image: the .text extent overflows the image")?;
    if end > mapped_len {
        return Err("truncated image: the mapped .text runs past the image".to_string());
    }
    Ok((offset, length))
}

/// How far the mapping runs, off the optional header's own field
/// (`SizeOfImage`, at the same offset for PE32 and PE32+): the fact
/// that turns a module base pointer into a slice.
pub(crate) fn size_of_image(image: &[u8]) -> Result<usize, String> {
    let layout = layout(image)?;
    let optional = layout.nt + 24;
    Ok(u32_at(
        read_slice(
            image,
            optional + 56,
            4,
            "the optional header's size of image",
        )?,
        0,
    ) as usize)
}

/// Whether the disk copy and the mapped image are one build: the
/// fields two builds of one library practically never share -- the
/// machine, the section count, the linker timestamp, the image size.
/// A mismatch (a patch-Tuesday drift between the disk file and what
/// the loader mapped) refuses: a restore across builds writes wrong
/// bytes with every appearance of success.
pub(crate) fn same_build(disk: &[u8], mapped: &[u8]) -> Result<(), String> {
    let disk_layout = layout(disk)?;
    let mapped_layout = layout(mapped)?;
    let mismatch = |what: &str| {
        format!(
            "the disk copy and the mapped image disagree on {what} -- different \
             ntdll builds; a restore would write wrong bytes"
        )
    };

    if u16_at(disk, disk_layout.nt + 4) != u16_at(mapped, mapped_layout.nt + 4) {
        return Err(mismatch("the machine"));
    }
    if disk_layout.count != mapped_layout.count {
        return Err(mismatch("the section count"));
    }
    if u32_at(disk, disk_layout.nt + 8) != u32_at(mapped, mapped_layout.nt + 8) {
        return Err(mismatch("the linker timestamp"));
    }
    let size = |image: &[u8], layout: &Layout| -> Result<u32, String> {
        Ok(u32_at(
            read_slice(
                image,
                layout.nt + 24 + 56,
                4,
                "the optional header's size of image",
            )?,
            0,
        ))
    };
    if size(disk, &disk_layout)? != size(mapped, &mapped_layout)? {
        return Err(mismatch("the image size"));
    }
    Ok(())
}

/// How many bytes differ between the disk `.text` and the mapped one
/// -- the read the bare task reports. Spans that disagree in length
/// refuse: builds the fingerprint did not tell apart.
pub(crate) fn differences(disk_text: &[u8], mapped_text: &[u8]) -> Result<usize, String> {
    if disk_text.len() != mapped_text.len() {
        return Err(format!(
            "the two .text copies disagree in length ({} on disk, {} mapped) -- \
             builds the fingerprint did not tell apart",
            disk_text.len(),
            mapped_text.len()
        ));
    }
    Ok(disk_text
        .iter()
        .zip(mapped_text)
        .filter(|(left, right)| left != right)
        .count())
}

/// The span the two views share: the bytes the file actually carries.
fn spanned(section: &TextSection) -> Result<usize, String> {
    let length = section.virtual_size.min(section.raw_size) as usize;
    if length == 0 {
        return Err("malformed image: the .text section carries no bytes".to_string());
    }
    Ok(length)
}

/// Where an image's headers sit: the NT offset and the section table
/// it carries.
struct Layout {
    /// Where the NT signature sits; the file header follows it.
    nt: usize,
    /// Where the section table sits, one 40-byte header per section.
    sections: usize,
    count: usize,
}

fn layout(image: &[u8]) -> Result<Layout, String> {
    if read_slice(image, 0, 2, "the DOS header")? != b"MZ" {
        return Err("not a portable executable: the DOS signature is absent".to_string());
    }
    let nt = u32_at(image, 0x3C) as usize;
    if read_slice(image, nt, 4, "the NT signature")? != b"PE\0\0" {
        return Err("not a portable executable: the PE signature is absent".to_string());
    }
    let file_header = nt + 4;
    let optional = file_header + 20;
    match u16_at(read_slice(image, optional, 2, "the optional header")?, 0) {
        0x10B | 0x20B => {}
        other => {
            return Err(format!(
                "not a portable executable: unknown optional-header magic 0x{other:X}"
            ))
        }
    }
    let count = u16_at(image, file_header + 2) as usize;
    let optional_size = u16_at(image, file_header + 16) as usize;
    let sections = optional + optional_size;
    let end = sections
        .checked_add(
            count
                .checked_mul(40)
                .ok_or("the section table overflows the file")?,
        )
        .ok_or("the section table overflows the file")?;
    if end > image.len() {
        return Err("truncated image: the section table runs past the file".to_string());
    }
    Ok(Layout {
        nt,
        sections,
        count,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but honest PE32+ image the tests shape at will: one
    /// `.text` section mapping RVA 0x1000.. to file offset 0x200,
    /// carrying the bytes the caller chooses, with the header fields
    /// the fingerprint reads (machine, timestamp, image size) set to
    /// named values the tests vary.
    fn minimal_image(text: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 0x400 + text.len()];
        image[0] = b'M';
        image[1] = b'Z';
        image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());

        let nt = 0x40;
        image[nt..nt + 4].copy_from_slice(b"PE\0\0");
        image[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
        image[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes()); // one section
        image[nt + 8..nt + 12].copy_from_slice(&0x5EED_1234u32.to_le_bytes()); // timestamp
        let optional_size = 240u16; // PE32+ fixed part + 16 directories
        image[nt + 20..nt + 22].copy_from_slice(&optional_size.to_le_bytes());

        let optional = nt + 24;
        image[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        image[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image

        // The section: RVA 0x1000 lands at file offset 0x200.
        let section = optional + optional_size as usize;
        image[section..section + 8].copy_from_slice(TEXT_NAME);
        image[section + 8..section + 12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&(text.len() as u32).to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());

        image[0x200..0x200 + text.len()].copy_from_slice(text);
        image
    }

    #[test]
    fn the_text_reads_where_the_section_table_says() {
        let text = [0xCCu8; 32];
        let image = minimal_image(&text);
        let (bytes, section) = disk_text(&image).unwrap();
        assert_eq!(bytes, &text[..]);
        assert_eq!(section.rva, 0x1000);
        assert_eq!(section.raw_pointer, 0x200);
        assert_eq!(section.virtual_size, 32);
        assert_eq!(section.raw_size, 32);

        // The mapped view: the same span, off the RVA, inside the
        // image size the headers carry.
        let (offset, length) = mapped_text(&section, size_of_image(&image).unwrap()).unwrap();
        assert_eq!((offset, length), (0x1000, 32));
        assert_eq!(size_of_image(&image).unwrap(), 0x3000);
    }

    #[test]
    fn the_span_is_what_the_file_carries() {
        // Virtual size past raw: the shared span is the raw bytes.
        let mut image = minimal_image(&[0x90; 16]);
        let section = optional_end(&image);
        image[section + 8..section + 12].copy_from_slice(&48u32.to_le_bytes());
        let (bytes, read) = disk_text(&image).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(read.virtual_size, 48);
        assert_eq!(read.raw_size, 16);

        // Raw past virtual: the shared span is the mapped extent --
        // a restore must never write past where the loader mapped.
        let mut image = minimal_image(&[0x90; 16]);
        let section = optional_end(&image);
        image[section + 16..section + 20].copy_from_slice(&48u32.to_le_bytes());
        let (bytes, read) = disk_text(&image).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(read.raw_size, 48);

        // No bytes at all: the section refuses.
        let image = minimal_image(&[]);
        let error = disk_text(&image).unwrap_err();
        assert!(error.contains("carries no bytes"), "{error}");
    }

    #[test]
    fn an_image_without_a_text_section_refuses() {
        let mut image = minimal_image(&[0xCC; 8]);
        let section = optional_end(&image);
        image[section..section + 8].copy_from_slice(b".rdata\0\0");
        let error = disk_text(&image).unwrap_err();
        assert!(error.contains("no .text section"), "{error}");
    }

    #[test]
    fn malformed_and_truncated_images_refuse_naming_the_offender() {
        // Not MZ.
        let mut image = minimal_image(&[0xCC; 8]);
        image[0] = b'X';
        assert!(disk_text(&image).unwrap_err().contains("DOS signature"));

        // Not PE.
        let mut image = minimal_image(&[0xCC; 8]);
        image[0x40] = b'X';
        assert!(disk_text(&image).unwrap_err().contains("PE signature"));

        // Unknown optional-header magic.
        let mut image = minimal_image(&[0xCC; 8]);
        image[0x40 + 24..0x40 + 26].copy_from_slice(&0x999u16.to_le_bytes());
        assert!(disk_text(&image)
            .unwrap_err()
            .contains("optional-header magic"));

        // The section table runs past the file.
        let mut image = minimal_image(&[0xCC; 8]);
        image[0x40 + 4 + 2..0x40 + 4 + 4].copy_from_slice(&400u16.to_le_bytes());
        assert!(disk_text(&image)
            .unwrap_err()
            .contains("section table runs past"));

        // The .text bytes run past the file.
        let image = minimal_image(&[0xCC; 64]);
        assert!(disk_text(&image[..0x210])
            .unwrap_err()
            .contains("runs past the file"));

        // The mapped .text runs past the mapped image.
        let image = minimal_image(&[0xCC; 64]);
        let (_, section) = disk_text(&image).unwrap();
        let error = mapped_text(&section, 0x1000 + 8).unwrap_err();
        assert!(error.contains("mapped .text runs past"), "{error}");
    }

    #[test]
    fn two_images_of_one_build_agree_even_when_their_text_differs() {
        // The mapped copy carries hooks the disk copy does not: one
        // build, two views -- exactly the case the verb addresses.
        let disk = minimal_image(&[0x48, 0x8B, 0x44, 0x24, 0x10, 0xC3]);
        let mut mapped = disk.clone();
        mapped[0x200] = 0xE9;
        mapped[0x201] = 0x11;
        assert!(same_build(&disk, &mapped).is_ok());
    }

    #[test]
    fn builds_the_fingerprint_tells_apart_refuse() {
        // A patch-Tuesday drift: timestamp and image size both move.
        let disk = minimal_image(&[0xCC; 16]);
        let mut mapped = disk.clone();
        mapped[0x40 + 8..0x40 + 12].copy_from_slice(&0x5EED_5678u32.to_le_bytes());
        let error = same_build(&disk, &mapped).unwrap_err();
        assert!(error.contains("linker timestamp"), "{error}");
        assert!(error.contains("wrong bytes"), "{error}");

        let mut mapped = disk.clone();
        mapped[0x40 + 24 + 56..0x40 + 24 + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        assert!(same_build(&disk, &mapped)
            .unwrap_err()
            .contains("image size"));

        let mut mapped = disk.clone();
        mapped[0x40 + 4..0x40 + 6].copy_from_slice(&0xAA64u16.to_le_bytes());
        assert!(same_build(&disk, &mapped).unwrap_err().contains("machine"));

        let mut mapped = disk.clone();
        mapped[0x40 + 4 + 2..0x40 + 4 + 4].copy_from_slice(&2u16.to_le_bytes());
        assert!(same_build(&disk, &mapped)
            .unwrap_err()
            .contains("section count"));
    }

    #[test]
    fn the_differing_count_is_the_read_the_task_reports() {
        let disk = [0x48, 0x8B, 0x44, 0x24, 0x10, 0xC3];
        assert_eq!(differences(&disk, &disk).unwrap(), 0);

        let mut hooked = disk;
        hooked[0] = 0xE9;
        hooked[1] = 0x67;
        assert_eq!(differences(&disk, &hooked).unwrap(), 2);

        // A length the fingerprint let past refuses here, named.
        let error = differences(&disk, &disk[..4]).unwrap_err();
        assert!(error.contains("disagree in length"), "{error}");
        assert!(error.contains("6 on disk, 4 mapped"), "{error}");
    }

    /// Where the section table's single header sits in the builder's
    /// image: after the file header and the full optional header.
    fn optional_end(image: &[u8]) -> usize {
        let nt = u32_at(image, 0x3C) as usize;
        let optional_size = u16_at(image, nt + 4 + 16) as usize;
        nt + 24 + optional_size
    }
}
