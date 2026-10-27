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

/// One named function's extent in a mapped image: where its body
/// starts and how far it runs. The export table names no lengths, so
/// the extent is the span to the next export's address -- the table's
/// own ordering, bounded by the bytes the file actually carries.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FunctionSpan {
    /// The export's RVA, where the body starts.
    pub rva: u32,
    /// How many bytes the extent spans.
    pub length: u32,
}

/// A named export's extent, read out of a mapped image's own export
/// table (where RVAs address directly): the name binary-searched in
/// the sorted name table, the ordinal through to its address, the
/// body bounded by the next export's. A forwarder (an address inside
/// the export directory itself) and an export that does not live in
/// `.text` refuse named -- the one names another library, the other
/// is data the verb does not address.
pub(crate) fn function_extent(image: &[u8], name: &str) -> Result<FunctionSpan, String> {
    let directory = export_directory(image)?;
    let rva = export_rva(image, &directory, name)?;
    if rva >= directory.rva && rva < directory.rva + directory.size {
        return Err(format!("{name} is a forwarder, not a body"));
    }
    let section = text_section(image)?;
    let span = spanned(&section)?;
    let text_end = section.rva + span as u32;
    if rva < section.rva || rva >= text_end {
        return Err(format!(
            "{name} does not export from .text -- its body is not code this \
             verb addresses"
        ));
    }
    // The next export address past this one: the table's own order.
    // The highest export's extent runs to .text's carried end.
    let mut next = text_end;
    for index in 0..directory.functions {
        let entry = address_at(image, &directory, index)?;
        if entry > rva && entry < next {
            next = entry;
        }
    }
    Ok(FunctionSpan {
        rva,
        length: next - rva,
    })
}

/// A disk-layout image's file offset for an RVA: the section that
/// carries the address, translated through its own raw pointer. An
/// address in a section's zero-padded tail or in no section at all
/// refuses named -- no file byte backs it.
pub(crate) fn rva_to_offset(image: &[u8], rva: u32) -> Result<usize, String> {
    let layout = layout(image)?;
    for index in 0..layout.count {
        let header = layout.sections + index * 40;
        let virtual_size = u32_at(image, header + 8);
        let virtual_address = u32_at(image, header + 12);
        let raw_size = u32_at(image, header + 16);
        let raw_pointer = u32_at(image, header + 20);
        let span = virtual_size.max(raw_size);
        if rva < virtual_address || rva - virtual_address >= span {
            continue;
        }
        let within = rva - virtual_address;
        return if within < raw_size {
            Ok(raw_pointer as usize + within as usize)
        } else {
            Err(format!(
                "the address {rva:#x} sits in a section's zero-padded tail -- no \
                 file byte backs it"
            ))
        };
    }
    Err(format!(
        "the address {rva:#x} sits in no section the image carries"
    ))
}

/// The export directory, as the data directory's first entry names
/// it. The directory entry's offset is the one field the optional
/// header's two shapes place apart (PE32 at 96, PE32+ at 112), so the
/// magic the layout already checked picks it.
struct ExportDirectory {
    rva: u32,
    size: u32,
    base_ordinal: u32,
    functions: u32,
    addresses: u32,
    name_table: u32,
    ordinal_table: u32,
}

fn export_directory(image: &[u8]) -> Result<ExportDirectory, String> {
    let layout = layout(image)?;
    let optional = layout.nt + 24;
    let magic = u16_at(read_slice(image, optional, 2, "the optional header")?, 0);
    let directories = optional + if magic == 0x20B { 112 } else { 96 };
    let rva = u32_at(
        read_slice(image, directories, 4, "the export directory")?,
        0,
    );
    let size = u32_at(
        read_slice(image, directories + 4, 4, "the export directory")?,
        0,
    );
    if rva == 0 {
        return Err("malformed image: no export table -- the image names no \
                    function this verb could address"
            .to_string());
    }
    let at =
        |offset: u32, what: &str| -> Result<u32, String> { u32_at_rva(image, rva + offset, what) };
    Ok(ExportDirectory {
        rva,
        size,
        base_ordinal: at(16, "the export directory's ordinal base")?,
        functions: at(20, "the export directory's function count")?,
        addresses: at(28, "the export directory's address table")?,
        name_table: at(32, "the export directory's name table")?,
        ordinal_table: at(36, "the export directory's ordinal table")?,
    })
}

/// One named export's address, through the sorted name table (the
/// spec's own guarantee the binary search rides) and the ordinal it
/// indexes. A name the table does not carry refuses named, quoted.
fn export_rva(image: &[u8], directory: &ExportDirectory, name: &str) -> Result<u32, String> {
    let mut low = 0u32;
    let mut high = directory.names(image)?;
    while low < high {
        let mid = low + (high - low) / 2;
        let entry = u32_at_rva(image, directory.name_table + mid * 4, "the name table")?;
        match compare_name(image, entry, name) {
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
            std::cmp::Ordering::Equal => {
                let ordinal = u16_at_rva(
                    image,
                    directory.ordinal_table + mid * 2,
                    "the ordinal table",
                )?;
                let index = ordinal
                    .checked_sub(directory.base_ordinal as u16)
                    .ok_or("malformed image: an export ordinal below the table's base")?
                    as u32;
                if index >= directory.functions {
                    return Err(
                        "malformed image: an export ordinal past the address table".to_string()
                    );
                }
                return address_at(image, directory, index);
            }
        }
    }
    Err(format!("no export named '{name}'"))
}

/// The address table's entry at an index, bounds-checked against the
/// image the table lives in.
fn address_at(image: &[u8], directory: &ExportDirectory, index: u32) -> Result<u32, String> {
    u32_at_rva(image, directory.addresses + index * 4, "the address table")
}

impl ExportDirectory {
    /// How many names the name table carries.
    fn names(&self, image: &[u8]) -> Result<u32, String> {
        u32_at_rva(image, self.rva + 24, "the export directory's name count")
    }
}

/// A NUL-terminated ASCII name at an RVA, compared against a wanted
/// name without materializing it. The comparison stops at the first
/// difference or the table's own NUL; a wanted name past the image's
/// end compares greater -- a truncated image, named by the reads
/// around it.
fn compare_name(image: &[u8], rva: u32, wanted: &str) -> std::cmp::Ordering {
    let mut offset = rva as usize;
    for wanted_byte in wanted.bytes().chain(std::iter::once(0)) {
        let Some(&byte) = image.get(offset) else {
            return std::cmp::Ordering::Greater;
        };
        match byte.cmp(&wanted_byte) {
            std::cmp::Ordering::Equal => offset += 1,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// A bounds-checked u16 read at an RVA.
fn u16_at_rva(image: &[u8], rva: u32, what: &str) -> Result<u16, String> {
    let offset = rva as usize;
    let end = offset
        .checked_add(2)
        .ok_or("malformed image: an export table address overflows")?;
    let bytes = image
        .get(offset..end)
        .ok_or_else(|| format!("truncated image: {what} runs past the image"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// A bounds-checked u32 read at an RVA.
fn u32_at_rva(image: &[u8], rva: u32, what: &str) -> Result<u32, String> {
    let offset = rva as usize;
    let end = offset
        .checked_add(4)
        .ok_or("malformed image: an export table address overflows")?;
    let bytes = image
        .get(offset..end)
        .ok_or_else(|| format!("truncated image: {what} runs past the image"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
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

    /// A two-section image -- `.text` at RVA 0x1000 (file 0x200),
    /// `.rdata` at RVA 0x2000 (file 0x400) -- carrying an export
    /// directory the caller's `(name, rva)` entries populate. The
    /// builder writes the name table sorted, as the spec promises and
    /// the binary search rides, with identity ordinals over a zero
    /// base; the addresses go in as given, out of order included.
    fn exported_image(text: &[u8], exports: &[(&str, u32)]) -> Vec<u8> {
        let mut sorted: Vec<(&str, u32)> = exports.to_vec();
        sorted.sort_unstable_by(|left, right| left.0.cmp(right.0));

        let count = sorted.len();
        let addresses = 0x2000 + 40;
        let ordinals = addresses + 4 * count as u32;
        let names = ordinals + 2 * count as u32;
        let mut name_bytes = Vec::new();
        let mut name_rvas = Vec::new();
        for (name, _) in &sorted {
            // The bytes sit after the name table's own row of pointers.
            name_rvas.push(names + 4 * count as u32 + name_bytes.len() as u32);
            name_bytes.extend(name.bytes());
            name_bytes.push(0);
        }
        let rdata = 40 + 10 * count + name_bytes.len();
        let image_size = (0x2000 + (rdata as u32) + 0xFFF) & !0xFFF;

        // The builder lays the image out as the loader maps it -- every
        // part at its own RVA, the raw pointers mirroring the virtual
        // addresses -- so the export reads address it directly.
        let mut image = vec![0u8; image_size as usize];
        image[0] = b'M';
        image[1] = b'Z';
        image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let nt = 0x40;
        image[nt..nt + 4].copy_from_slice(b"PE\0\0");
        image[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        image[nt + 6..nt + 8].copy_from_slice(&2u16.to_le_bytes()); // two sections
        image[nt + 8..nt + 12].copy_from_slice(&0x5EED_1234u32.to_le_bytes());
        let optional_size = 240u16;
        image[nt + 20..nt + 22].copy_from_slice(&optional_size.to_le_bytes());
        let optional = nt + 24;
        image[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        image[optional + 56..optional + 60].copy_from_slice(&image_size.to_le_bytes());
        // The export directory's data directory entry (PE32+ offset).
        image[optional + 112..optional + 116].copy_from_slice(&0x2000u32.to_le_bytes());
        image[optional + 116..optional + 120].copy_from_slice(&(rdata as u32).to_le_bytes());

        let section = optional + optional_size as usize;
        image[section..section + 8].copy_from_slice(TEXT_NAME);
        image[section + 8..section + 12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&(text.len() as u32).to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        let rdata_header = section + 40;
        image[rdata_header..rdata_header + 8].copy_from_slice(b".rdata\0\0");
        image[rdata_header + 8..rdata_header + 12].copy_from_slice(&(rdata as u32).to_le_bytes());
        image[rdata_header + 12..rdata_header + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        image[rdata_header + 16..rdata_header + 20].copy_from_slice(&(rdata as u32).to_le_bytes());
        image[rdata_header + 20..rdata_header + 24].copy_from_slice(&0x2000u32.to_le_bytes());

        image[0x1000..0x1000 + text.len()].copy_from_slice(text);

        // The export directory, at .rdata's start -- every part at its
        // own RVA, the tables the directory's fields point to.
        let dir = 0x2000;
        image[dir + 16..dir + 20].copy_from_slice(&0u32.to_le_bytes()); // ordinal base
        image[dir + 20..dir + 24].copy_from_slice(&(count as u32).to_le_bytes());
        image[dir + 24..dir + 28].copy_from_slice(&(count as u32).to_le_bytes());
        image[dir + 28..dir + 32].copy_from_slice(&addresses.to_le_bytes());
        image[dir + 32..dir + 36].copy_from_slice(&names.to_le_bytes());
        image[dir + 36..dir + 40].copy_from_slice(&ordinals.to_le_bytes());
        for (index, (_, rva)) in sorted.iter().enumerate() {
            let at = addresses as usize + 4 * index;
            image[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            let at = ordinals as usize + 2 * index;
            image[at..at + 2].copy_from_slice(&(index as u16).to_le_bytes());
            let at = names as usize + 4 * index;
            image[at..at + 4].copy_from_slice(&name_rvas[index].to_le_bytes());
        }
        let at = names as usize + 4 * count;
        image[at..at + name_bytes.len()].copy_from_slice(&name_bytes);
        image
    }

    #[test]
    fn a_named_function_reads_its_extent_out_of_the_export_table() {
        // Three bodies in .text at 0x1000, 0x1010, 0x1030; the text
        // carries 0x40 bytes. Each extent runs to the next export's
        // address; the highest runs to the bytes the file carries.
        let image = exported_image(
            &[0xCC; 0x40],
            &[("Beta", 0x1010), ("Alpha", 0x1000), ("Gamma", 0x1030)],
        );
        assert_eq!(
            function_extent(&image, "Alpha").unwrap(),
            FunctionSpan {
                rva: 0x1000,
                length: 0x10
            }
        );
        assert_eq!(
            function_extent(&image, "Beta").unwrap(),
            FunctionSpan {
                rva: 0x1010,
                length: 0x20
            }
        );
        assert_eq!(
            function_extent(&image, "Gamma").unwrap(),
            FunctionSpan {
                rva: 0x1030,
                length: 0x10
            }
        );

        // Two names over one address -- an alias -- hand back the one
        // extent both names share.
        let image = exported_image(&[0xCC; 0x10], &[("One", 0x1000), ("Two", 0x1000)]);
        assert_eq!(
            function_extent(&image, "One").unwrap(),
            function_extent(&image, "Two").unwrap()
        );

        // The lookup is exact: the sorted table's binary search misses
        // a name the image does not carry, case included.
        let error = function_extent(&image, "beta").unwrap_err();
        assert!(error.contains("no export named 'beta'"), "{error}");
    }

    #[test]
    fn forwarders_and_data_exports_refuse_named() {
        // The directory spans 0x2000..0x2000+size; an address inside
        // it is a forwarder, and an address in .rdata past it is data.
        let image = exported_image(
            &[0xCC; 0x10],
            &[("Real", 0x1000), ("Fwd", 0x2010), ("Data", 0x20F0)],
        );
        let forwarder = function_extent(&image, "Fwd").unwrap_err();
        assert!(forwarder.contains("forwarder"), "{forwarder}");
        let data = function_extent(&image, "Data").unwrap_err();
        assert!(data.contains("does not export from .text"), "{data}");
        assert!(function_extent(&image, "Real").is_ok());
    }

    #[test]
    fn an_image_without_an_export_table_refuses() {
        let image = minimal_image(&[0xCC; 8]);
        let error = function_extent(&image, "Anything").unwrap_err();
        assert!(error.contains("no export table"), "{error}");
    }

    #[test]
    fn disk_translation_walks_the_sections_own_tables() {
        // The builder lays its parts at their RVAs, so its raw pointers
        // mirror them: the translation over it is the identity.
        let image = exported_image(&[0xCC; 0x10], &[("Alpha", 0x1000)]);
        assert_eq!(rva_to_offset(&image, 0x1008).unwrap(), 0x1008);
        assert_eq!(rva_to_offset(&image, 0x2008).unwrap(), 0x2008);

        // A disk twin -- the same headers with the raw pointers a file
        // carries -- translates through the delta each section's own
        // table names.
        let mut image = image;
        let section = optional_end(&image);
        image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 60..section + 64].copy_from_slice(&0x400u32.to_le_bytes());
        assert_eq!(rva_to_offset(&image, 0x1008).unwrap(), 0x208);
        assert_eq!(rva_to_offset(&image, 0x2008).unwrap(), 0x408);

        // Below every section: the headers carry no file byte.
        let headers = rva_to_offset(&image, 0x40).unwrap_err();
        assert!(headers.contains("no section"), "{headers}");

        // A section's zero-padded tail: virtual size past what the
        // file carries maps to no file byte.
        let mut image = exported_image(&[0xCC; 0x10], &[("Alpha", 0x1000)]);
        let section = optional_end(&image);
        image[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
        let tail = rva_to_offset(&image, 0x1080).unwrap_err();
        assert!(tail.contains("zero-padded tail"), "{tail}");
    }
}
