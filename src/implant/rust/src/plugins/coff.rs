//! The Windows COFF object loader -- the coff-v1 loading contract
//! (architecture.md Sec 5.4): the plugin seam's third shape. A BOF is a
//! single COFF object the linker never bound -- its relocations name
//! symbols a host resolves at load time -- so the loader parses the
//! object, lays its sections in one RWX allocation, applies the
//! symbol-table-driven relocations, resolves every external against a
//! Beacon-compatible host table, and calls the corpus's `go(args, len)`
//! entry with the packed argument buffer beside it.
//!
//! The pure half of this module -- parse, place, relocate, the host
//! API, the argument grammar -- is host-blind and carries the tests;
//! the Windows half (allocation, library resolution, the entry call) is
//! `#[cfg(windows)]` alone. The bound corpus is mingw-w64's `gcc -c`
//! output for x64 and x86 objects; the host API family and the
//! argument grammar are documented in extending/modules.md.

use std::alloc::Layout;
use std::cell::{Cell, RefCell};

// --- The object grammar -------------------------------------------------------

const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_I386: u16 = 0x14c;

const HEADER_LEN: usize = 20;
const SECTION_HEADER_LEN: usize = 40;
const SYMBOL_LEN: usize = 18;
const RELOCATION_LEN: usize = 10;
/// The section ceiling the PE grammar itself carries; an object past it
/// is not a shape any linker emits.
const MAX_SECTIONS: usize = 96;
/// Sections land on 16-byte steps in the mapped image -- the alignment
/// the corpus's code assumptions (jump targets, string literals) never
/// see past.
const SECTION_ALIGNMENT: usize = 16;

const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;

const IMAGE_SYM_ABSOLUTE: i16 = -1;
const IMAGE_SYM_DEBUG: i16 = -2;

/// One bound object: the sections, their relocations, and the symbol
/// table with auxiliary entries held as `None` slots so relocation
/// indices (which count them) keep their file meaning.
pub(crate) struct Coff {
    machine: u16,
    sections: Vec<CoffSection>,
    symbols: Vec<Option<CoffSymbol>>,
}

pub(crate) struct CoffSection {
    name: String,
    /// The section's raw bytes in the object file.
    raw: std::ops::Range<usize>,
    relocs: Vec<CoffReloc>,
    /// The section's slot size in the mapped image; zero for the
    /// sections the linker directives discard.
    mapped: usize,
}

pub(crate) struct CoffSymbol {
    name: String,
    section: i16,
    value: u32,
}

pub(crate) struct CoffReloc {
    offset: u32,
    symbol: u32,
    kind: u16,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Coff, String> {
    if bytes.starts_with(b"!<arch>\n") {
        return Err(
            "module.load: an archive is not a BOF; publish the single object the linker emitted"
                .into(),
        );
    }
    if bytes.len() < HEADER_LEN {
        return Err("module.load: the object is shorter than a COFF header".into());
    }
    let machine = read_u16(bytes, 0);
    if machine == 0xffff {
        return Err(
            "module.load: a big-object COFF (past 65,534 symbols) is outside coff-v1".into(),
        );
    }
    if machine != MACHINE_AMD64 && machine != MACHINE_I386 {
        return Err(format!(
            "module.load: machine 0x{machine:x} is not one this loader binds (x64 and x86 objects alone)"
        ));
    }
    if read_u16(bytes, 16) != 0 {
        return Err(
            "module.load: the bytes carry an optional header; a BOF is a bare object".into(),
        );
    }

    let section_count = read_u16(bytes, 2) as usize;
    if section_count > MAX_SECTIONS {
        return Err(format!(
            "module.load: the object declares {section_count} sections; the grammar allows {MAX_SECTIONS}"
        ));
    }
    let sections_at = HEADER_LEN;
    let sections_end = sections_at + section_count * SECTION_HEADER_LEN;
    if sections_end > bytes.len() {
        return Err("module.load: the section table runs past the object".into());
    }

    let symbol_table_at = read_u32(bytes, 8) as usize;
    let symbol_count = read_u32(bytes, 12) as usize;
    let Some(symbol_bytes) = symbol_count.checked_mul(SYMBOL_LEN) else {
        return Err("module.load: the symbol table size overflows the object".into());
    };
    let Some(symbol_table_end) = symbol_table_at.checked_add(symbol_bytes) else {
        return Err("module.load: the symbol table size overflows the object".into());
    };
    if symbol_table_at != 0 && symbol_table_end > bytes.len() {
        return Err("module.load: the symbol table runs past the object".into());
    }
    if symbol_table_at == 0 && symbol_count != 0 {
        return Err("module.load: the object names symbols but carries no table".into());
    }

    // The string table starts where the symbol table ends: its first
    // word is its own size, strings ride NUL-terminated behind it.
    let mut strings = None;
    if symbol_count != 0 {
        if symbol_table_end + 4 > bytes.len() {
            return Err("module.load: the string table is missing".into());
        }
        let declared = read_u32(bytes, symbol_table_end) as usize;
        if declared < 4 || symbol_table_end + declared > bytes.len() {
            return Err("module.load: the string table runs past the object".into());
        }
        strings = Some((symbol_table_end, declared));
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let at = sections_at + index * SECTION_HEADER_LEN;
        let size_of_raw = read_u32(bytes, at + 16) as usize;
        let raw_at = read_u32(bytes, at + 20) as usize;
        let reloc_count = read_u16(bytes, at + 32) as usize;
        let reloc_at = read_u32(bytes, at + 24) as usize;
        let characteristics = read_u32(bytes, at + 36);

        if characteristics & IMAGE_SCN_LNK_NRELOC_OVFL != 0 {
            return Err(format!(
                "module.load: section {index} overflows the relocation count; outside coff-v1"
            ));
        }
        // The linker directives name what the linker strips: debug
        // sections and comment sections never join the image, and their
        // relocations go with them.
        let discarded = characteristics & (IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_LNK_INFO) != 0;
        if !discarded {
            let Some(raw_end) = raw_at.checked_add(size_of_raw) else {
                return Err(format!(
                    "module.load: section {index}'s data overflows the object"
                ));
            };
            if raw_end > bytes.len() {
                return Err(format!(
                    "module.load: section {index}'s data runs past the object"
                ));
            }
        }
        let mut relocs = Vec::new();
        if !discarded && reloc_count != 0 {
            let Some(relocs_end) = reloc_at.checked_add(reloc_count * RELOCATION_LEN) else {
                return Err(format!(
                    "module.load: section {index}'s relocations overflow the object"
                ));
            };
            if reloc_at + reloc_count * RELOCATION_LEN > bytes.len() || relocs_end > bytes.len() {
                return Err(format!(
                    "module.load: section {index}'s relocations run past the object"
                ));
            }
            for entry in 0..reloc_count {
                let at = reloc_at + entry * RELOCATION_LEN;
                relocs.push(CoffReloc {
                    offset: read_u32(bytes, at),
                    symbol: read_u32(bytes, at + 4),
                    kind: read_u16(bytes, at + 8),
                });
            }
        }
        sections.push(CoffSection {
            name: section_name(bytes, at, strings),
            raw: if discarded {
                0..0
            } else {
                raw_at..raw_at + size_of_raw
            },
            relocs,
            mapped: if discarded { 0 } else { size_of_raw },
        });
    }

    let mut symbols = Vec::with_capacity(symbol_count);
    let mut walked = 0usize;
    while walked < symbol_count {
        let at = symbol_table_at + walked * SYMBOL_LEN;
        let name_bytes = &bytes[at..at + 8];
        let name = if name_bytes[..4] == [0, 0, 0, 0] {
            let (table_at, table_len) =
                strings.ok_or("module.load: a symbol names a string table the object lacks")?;
            string_table_name(bytes, table_at, table_len, read_u32(bytes, at + 4) as usize)?
        } else {
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            String::from_utf8_lossy(&name_bytes[..end]).into_owned()
        };
        symbols.push(Some(CoffSymbol {
            name,
            section: read_i16(bytes, at + 12),
            value: read_u32(bytes, at + 8),
        }));
        // The entry's own aux count walks the table past the shapes the
        // loader never reads.
        let aux = bytes[at + 17] as usize;
        walked += 1 + aux;
        for _ in 0..aux {
            symbols.push(None);
        }
    }

    Ok(Coff {
        machine,
        sections,
        symbols,
    })
}

fn section_name(bytes: &[u8], at: usize, strings: Option<(usize, usize)>) -> String {
    let name_bytes = &bytes[at..at + 8];
    if name_bytes[0] == b'/' {
        let digits = String::from_utf8_lossy(&name_bytes[1..]).into_owned();
        let Ok(offset) = digits.trim_end_matches('\0').parse::<usize>() else {
            return String::new();
        };
        let Some((table_at, table_len)) = strings else {
            return String::new();
        };
        return string_table_name(bytes, table_at, table_len, offset).unwrap_or_default();
    }
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    String::from_utf8_lossy(&name_bytes[..end]).into_owned()
}

fn string_table_name(
    bytes: &[u8],
    table_at: usize,
    table_len: usize,
    offset: usize,
) -> Result<String, String> {
    if offset >= table_len {
        return Err("module.load: a symbol name points past the string table".into());
    }
    let start = table_at + offset;
    let end = bytes[start..table_at + table_len]
        .iter()
        .position(|&b| b == 0)
        .map(|at| start + at)
        .ok_or("module.load: a symbol name is not terminated in the string table")?;
    Ok(String::from_utf8_lossy(&bytes[start..end]).into_owned())
}

/// Where each kept section lands in the mapped image, and the image's
/// total size: sections march on the shared alignment, discarded ones
/// hold `None`.
pub(crate) fn placements(coff: &Coff) -> (usize, Vec<Option<usize>>) {
    let mut cursor = 0usize;
    let mut offsets = Vec::with_capacity(coff.sections.len());
    for section in &coff.sections {
        if section.mapped == 0 && section.raw.is_empty() {
            offsets.push(None);
            continue;
        }
        offsets.push(Some(cursor));
        cursor += align_up(section.mapped.max(1), SECTION_ALIGNMENT);
    }
    (cursor, offsets)
}

/// Copies every kept section's raw bytes into its slot. The image is a
/// plain buffer here -- the Windows half hands it the allocation.
pub(crate) fn copy_sections(
    image: &mut [u8],
    bytes: &[u8],
    coff: &Coff,
    offsets: &[Option<usize>],
) {
    for (index, section) in coff.sections.iter().enumerate() {
        let Some(at) = offsets[index] else { continue };
        if section.raw.is_empty() {
            continue;
        }
        let to = &mut image[at..at + section.raw.len()];
        to.copy_from_slice(&bytes[section.raw.clone()]);
    }
}

/// Applies every kept section's relocations against the placed image.
/// Symbols the object defines resolve through the placements; symbols it
/// leaves undefined reach the `resolve` closure -- the host API and the
/// `MODULE$Function` dynamic references, on the Windows floor.
pub(crate) fn apply_relocations(
    image: &mut [u8],
    image_base: usize,
    coff: &Coff,
    offsets: &[Option<usize>],
    resolve: &mut dyn FnMut(&CoffSymbol) -> Result<usize, String>,
) -> Result<(), String> {
    for (index, section) in coff.sections.iter().enumerate() {
        let Some(placement) = offsets[index] else {
            continue;
        };
        let section_base = image_base + placement;
        for reloc in &section.relocs {
            let symbol = coff
                .symbols
                .get(reloc.symbol as usize)
                .and_then(|held| held.as_ref())
                .ok_or_else(|| {
                    format!(
                        "module.load: a relocation names symbol {} outside the table",
                        reloc.symbol
                    )
                })?;
            // The symbol's own address: defined in a section, absolute,
            // or external. SECREL and SECTION additionally need the
            // defining section, which an external cannot offer.
            let target = match symbol.section {
                1..=i16::MAX => {
                    let Some(at) = offsets[(symbol.section - 1) as usize] else {
                        return Err(format!(
                            "module.load: a relocation names '{}', defined in a discarded section",
                            symbol.name
                        ));
                    };
                    image_base + at + symbol.value as usize
                }
                IMAGE_SYM_ABSOLUTE => symbol.value as usize,
                IMAGE_SYM_DEBUG => {
                    return Err(format!(
                        "module.load: a relocation names the debug symbol '{}'",
                        symbol.name
                    ))
                }
                _ => resolve(symbol)?,
            };
            // The slot has two faces: its offset in the image buffer
            // (the write's index) and its runtime address (the REL32
            // displacements and ADDR32NB reads). A corrupt offset that
            // would write past its own section is refused, not trusted
            // to land in a neighbor.
            let slot_index = placement + reloc.offset as usize;
            let slot_address = section_base + reloc.offset as usize;
            let fits = |width: usize| -> Result<(), String> {
                if reloc.offset as usize + width > section.mapped
                    || slot_index + width > image.len()
                {
                    return Err(slot_past_image(&symbol.name));
                }
                Ok(())
            };
            match (coff.machine, reloc.kind) {
                (MACHINE_AMD64, 1) | (MACHINE_I386, 1) => {
                    fits(8)?;
                    image[slot_index..slot_index + 8].copy_from_slice(&target.to_le_bytes()[..8]);
                }
                (MACHINE_AMD64, 2) | (MACHINE_AMD64, 3) | (MACHINE_I386, 6) | (MACHINE_I386, 7) => {
                    // ADDR32/ADDR32NB (x64) and DIR32/DIR32NB (x86): the
                    // NB pair is the image-relative read.
                    fits(4)?;
                    let value = if reloc.kind == 3 || reloc.kind == 7 {
                        target.wrapping_sub(image_base) as u32
                    } else {
                        target as u32
                    };
                    image[slot_index..slot_index + 4].copy_from_slice(&value.to_le_bytes());
                }
                (MACHINE_AMD64, 4..=9) => {
                    fits(4)?;
                    let extra = (reloc.kind - 4) as usize;
                    let displacement =
                        (target as i64).wrapping_sub((slot_address + 4 + extra) as i64) as u32;
                    image[slot_index..slot_index + 4].copy_from_slice(&displacement.to_le_bytes());
                }
                (MACHINE_I386, 20) => {
                    fits(4)?;
                    let displacement =
                        (target as i64).wrapping_sub((slot_address + 4) as i64) as u32;
                    image[slot_index..slot_index + 4].copy_from_slice(&displacement.to_le_bytes());
                }
                (_, 10) => {
                    // The 16-bit section index of the defining section.
                    if !(1..=i16::MAX).contains(&symbol.section) {
                        return Err(format!(
                            "module.load: a SECTION relocation against '{}', which no section defines",
                            symbol.name
                        ));
                    }
                    fits(2)?;
                    let index = symbol.section as u16;
                    image[slot_index..slot_index + 2].copy_from_slice(&index.to_le_bytes());
                }
                (_, 11) => {
                    if !(1..=i16::MAX).contains(&symbol.section) {
                        return Err(format!(
                            "module.load: a SECREL relocation against '{}', which no section defines",
                            symbol.name
                        ));
                    }
                    let at = offsets[(symbol.section - 1) as usize]
                        .ok_or_else(|| slot_past_image(&symbol.name))?;
                    fits(4)?;
                    let value = target.wrapping_sub(image_base + at) as u32;
                    image[slot_index..slot_index + 4].copy_from_slice(&value.to_le_bytes());
                }
                _ => {
                    return Err(format!(
                        "module.load: unsupported relocation type {} on machine 0x{:x} (section '{}', symbol '{}')",
                        reloc.kind, coff.machine, section.name, symbol.name
                    ))
                }
            }
        }
    }
    Ok(())
}

fn slot_past_image(name: &str) -> String {
    format!("module.load: a relocation slot for '{name}' runs past the image")
}

/// The entry symbol the corpus names: `go` on x64, the underscored C
/// symbol on x86 -- both with the `go(args, len)` calling shape.
pub(crate) fn entry(coff: &Coff) -> Result<(usize, u32), String> {
    let wanted = if coff.machine == MACHINE_AMD64 {
        "go"
    } else {
        "_go"
    };
    for held in coff.symbols.iter().flatten() {
        if held.name == wanted && (1..=i16::MAX).contains(&held.section) {
            let section = &coff.sections[(held.section - 1) as usize];
            if held.value as usize > section.mapped {
                return Err(format!(
                    "module.load: the entry '{wanted}' sits past its section"
                ));
            }
            return Ok(((held.section - 1) as usize, held.value));
        }
    }
    Err(format!(
        "module.load: the object declares no '{wanted}' entry; coff-v1 calls the corpus's go(args, len) convention"
    ))
}

// --- The argument grammar -----------------------------------------------------

/// Packs the task's argument text into the blob the entry receives:
/// a u32 body size, then the typed entries -- integers and shorts as
/// their raw widths, strings and bytes as a u32 length plus the data
/// (a string's length counts its NUL). The `BeaconData*` family below
/// walks the same shape.
pub(crate) fn pack_arguments(text: &str) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut rest = text.trim_start();
    if rest.is_empty() {
        body.extend_from_slice(&0u32.to_le_bytes());
        return Ok(body);
    }
    while !rest.is_empty() {
        let (token, tail) = split_token(rest)?;
        match token {
            Token::Int(value) => body.extend_from_slice(&value.to_le_bytes()),
            Token::Short(value) => body.extend_from_slice(&value.to_le_bytes()),
            Token::String(bytes) => {
                body.extend_from_slice(&((bytes.len() + 1) as u32).to_le_bytes());
                body.extend_from_slice(&bytes);
                body.push(0);
            }
            Token::Bytes(bytes) => {
                body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                body.extend_from_slice(&bytes);
            }
        }
        rest = tail.trim_start();
    }
    let mut blob = Vec::with_capacity(4 + body.len());
    blob.extend_from_slice(&(body.len() as u32).to_le_bytes());
    blob.extend_from_slice(&body);
    Ok(blob)
}

enum Token {
    Int(i32),
    Short(i16),
    String(Vec<u8>),
    Bytes(Vec<u8>),
}

fn split_token(text: &str) -> Result<(Token, &str), String> {
    let Some((kind, value)) = text.split_once(':') else {
        return Err(format!(
            "the argument '{text}' is not a typed token (i: w: s:\"...\" b:hex)"
        ));
    };
    match kind {
        "i" => {
            let digits = value.split_whitespace().next().unwrap_or("");
            let parsed: i32 = digits.parse().map_err(|_| bad_number("i", digits))?;
            Ok((Token::Int(parsed), &value[digits.len()..]))
        }
        "w" => {
            let digits = value.split_whitespace().next().unwrap_or("");
            let parsed: i16 = digits.parse().map_err(|_| bad_number("w", digits))?;
            Ok((Token::Short(parsed), &value[digits.len()..]))
        }
        "s" => {
            let mut bytes = Vec::new();
            let mut rest = value
                .strip_prefix('"')
                .ok_or_else(|| format!("an s: argument must open a quote: '{text}'"))?;
            loop {
                let Some(at) = rest.find(['\\', '"']) else {
                    return Err(format!("an s: argument never closes its quote: '{text}'"));
                };
                bytes.extend_from_slice(&rest.as_bytes()[..at]);
                match &rest[at..at + 1] {
                    "\"" => return Ok((Token::String(bytes), &rest[at + 1..])),
                    _ => {
                        let escaped = rest[at + 1..].chars().next().ok_or_else(|| {
                            format!("an s: argument ends on a bare backslash: '{text}'")
                        })?;
                        let mut encoded = [0u8; 4];
                        bytes.extend_from_slice(escaped.encode_utf8(&mut encoded).as_bytes());
                        rest = &rest[at + 1 + escaped.len_utf8()..];
                    }
                }
            }
        }
        "b" => {
            let digits = value.split_whitespace().next().unwrap_or("");
            if digits.len() % 2 != 0 {
                return Err(format!("a b: argument needs even-length hex: '{digits}'"));
            }
            let mut bytes = Vec::with_capacity(digits.len() / 2);
            let pair = digits.as_bytes();
            let mut at = 0;
            while at < pair.len() {
                let high = hex_digit(pair[at])
                    .ok_or_else(|| format!("a b: argument carries non-hex '{digits}'"))?;
                let low = hex_digit(pair[at + 1])
                    .ok_or_else(|| format!("a b: argument carries non-hex '{digits}'"))?;
                bytes.push(high << 4 | low);
                at += 2;
            }
            Ok((Token::Bytes(bytes), &value[digits.len()..]))
        }
        other => Err(format!(
            "the argument kind '{other}:' is not one the loader packs (i: w: s: b:)"
        )),
    }
}

fn bad_number(kind: &str, digits: &str) -> String {
    format!("the {kind}: argument '{digits}' is not a decimal number")
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// --- The Beacon-compatible host API -------------------------------------------

/// The error callback kind: the one line type that flags a run failed.
/// Every other kind the corpus prints through (0x0 output, 0x1e OEM,
/// 0x20 UTF8) is output.
const CALLBACK_ERROR: i32 = 0xd;

/// One run's output ceiling: a BOF that prints without bound cannot
/// grow the session's memory without end.
const MAX_OUTPUT: usize = 1 << 20;

/// The argument parser a BOF holds on its own stack, `beacon.h`'s
/// `datap`: the original buffer, the cursor, the bytes left, and the
/// buffer's own size.
#[repr(C)]
pub(crate) struct Datap {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

/// The format accumulator `beacon.h`'s `formatS` names: our allocation,
/// the cursor, the bytes written, and the capacity.
#[repr(C)]
pub(crate) struct Formatp {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

const FORMAT_ALIGNMENT: usize = 16;

/// The host context one dispatch runs under: the accumulated output and
/// the error flag a `CALLBACK_ERROR` line raises. A thread-local
/// pointer binds it, so concurrent BOFs on different modules hold
/// independent contexts by construction.
#[derive(Default)]
struct Host {
    out: RefCell<Vec<u8>>,
    err: Cell<bool>,
}

thread_local! {
    static HOST: Cell<*const Host> = const { Cell::new(std::ptr::null()) };
}

fn emit(kind: i32, data: &[u8]) {
    HOST.with(|cell| {
        let host = cell.get();
        if host.is_null() {
            return;
        }
        let host = unsafe { &*host };
        if kind == CALLBACK_ERROR {
            host.err.set(true);
        }
        let mut out = host.out.borrow_mut();
        let room = MAX_OUTPUT.saturating_sub(out.len());
        out.extend_from_slice(&data[..data.len().min(room)]);
    });
}

/// Reads a NUL-terminated string off BOF memory, bounded: a format
/// string or an appended text without its terminator cannot walk the
/// host's address space.
unsafe fn cstr(ptr: *const u8) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    let mut len = 0usize;
    unsafe {
        while len < MAX_OUTPUT && *ptr.add(len) != 0 {
            len += 1;
        }
        std::slice::from_raw_parts(ptr, len).to_vec()
    }
}

unsafe extern "C" fn beacon_output(kind: i32, data: *const u8, len: i32) {
    if data.is_null() || len < 0 {
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    emit(kind, bytes);
}

// The fixed-arity stand-in for the corpus's variadic prints: stable
// Rust cannot define a C-variadic function, and both calling shapes
// (Win64 and i386 cdecl) lay the first arguments in registers and the
// rest on the caller's stack -- a callee that names six pointer-wide
// slots past the format reads exactly the slots the caller filled.
// Consumption follows the directives alone, so a slot past what the
// caller passed is never read.
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn beacon_printf(
    kind: usize,
    format: *const u8,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) {
    let slots = [a2, a3, a4, a5, a6, a7];
    let mut next = 0usize;
    let text = format_vargs(&unsafe { cstr(format) }, &mut || {
        let held = slots.get(next).copied();
        next += 1;
        held
    });
    match text {
        Ok(text) => emit(kind as i32, text.as_bytes()),
        Err(cause) => emit(
            kind as i32,
            format!("[coff-v1] format refused: {cause}\n").as_bytes(),
        ),
    }
}

unsafe extern "C" fn beacon_data_parse(parser: *mut Datap, buffer: *mut u8, size: i32) {
    if parser.is_null() {
        return;
    }
    unsafe {
        // The blob's leading size word is not an argument.
        (*parser).original = buffer;
        (*parser).buffer = if buffer.is_null() {
            std::ptr::null_mut()
        } else {
            buffer.add(4)
        };
        (*parser).size = size;
        (*parser).length = size.saturating_sub(4);
    }
}

/// Takes `count` bytes off the parser, or exhausts it.
unsafe fn take(parser: &mut Datap, count: usize) -> Option<*mut u8> {
    if parser.length < count as i32 {
        parser.length = 0;
        parser.buffer = parser.original.wrapping_add(parser.size.max(0) as usize);
        return None;
    }
    let at = parser.buffer;
    parser.buffer = unsafe { at.add(count) };
    parser.length -= count as i32;
    Some(at)
}

unsafe extern "C" fn beacon_data_int(parser: *mut Datap) -> i32 {
    let Some(parser) = (unsafe { parser.as_mut() }) else {
        return 0;
    };
    match unsafe { take(parser, 4) } {
        Some(at) => unsafe { (at as *const u32).read_unaligned() as i32 },
        None => 0,
    }
}

unsafe extern "C" fn beacon_data_short(parser: *mut Datap) -> i16 {
    let Some(parser) = (unsafe { parser.as_mut() }) else {
        return 0;
    };
    match unsafe { take(parser, 2) } {
        Some(at) => unsafe { (at as *const u16).read_unaligned() as i16 },
        None => 0,
    }
}

unsafe extern "C" fn beacon_data_length(parser: *mut Datap) -> i32 {
    (unsafe { parser.as_ref() }).map_or(0, |parser| parser.length.max(0))
}

/// Takes one length-prefixed entry off the parser: the data pointer and
/// the length it carried.
unsafe fn take_blob(parser: &mut Datap) -> Option<(*mut u8, u32)> {
    let at = unsafe { take(parser, 4)? };
    let length = unsafe { (at as *const u32).read_unaligned() };
    if length as i64 > parser.length as i64 {
        parser.length = 0;
        return None;
    }
    unsafe { take(parser, length as usize) }.map(|at| (at, length))
}

unsafe extern "C" fn beacon_data_string(parser: *mut Datap) -> *mut u8 {
    let Some(parser) = (unsafe { parser.as_mut() }) else {
        return std::ptr::null_mut();
    };
    unsafe { take_blob(parser) }
        .map(|(at, _)| at)
        .unwrap_or(std::ptr::null_mut())
}

unsafe extern "C" fn beacon_data_extract(parser: *mut Datap, size: *mut i32) -> *mut u8 {
    let Some(parser) = (unsafe { parser.as_mut() }) else {
        return std::ptr::null_mut();
    };
    match unsafe { take_blob(parser) } {
        Some((at, length)) => {
            if !size.is_null() {
                unsafe { *size = length as i32 };
            }
            at
        }
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn beacon_format_alloc(format: *mut Formatp, size: i32) {
    if format.is_null() || size < 0 {
        return;
    }
    // One spare byte rides the allocation so ToString can always
    // terminate in place.
    let capacity = size as usize;
    let Ok(layout) = Layout::from_size_align(capacity + 1, FORMAT_ALIGNMENT) else {
        return;
    };
    let block = unsafe { std::alloc::alloc_zeroed(layout) };
    unsafe {
        *format = Formatp {
            original: block,
            buffer: block,
            length: 0,
            size: capacity as i32,
        };
    }
}

unsafe extern "C" fn beacon_format_reset(format: *mut Formatp) {
    let Some(format) = (unsafe { format.as_mut() }) else {
        return;
    };
    unsafe {
        let used = format.length.max(0) as usize;
        if !format.original.is_null() {
            std::ptr::write_bytes(format.original, 0, used);
        }
        format.buffer = format.original;
        format.length = 0;
    }
}

unsafe extern "C" fn beacon_format_free(format: *mut Formatp) {
    let Some(held) = (unsafe { format.as_mut() }) else {
        return;
    };
    if held.original.is_null() {
        return;
    }
    let capacity = held.size.max(0) as usize;
    if let Ok(layout) = Layout::from_size_align(capacity + 1, FORMAT_ALIGNMENT) {
        unsafe { std::alloc::dealloc(held.original, layout) };
    }
    held.original = std::ptr::null_mut();
    held.buffer = std::ptr::null_mut();
    held.length = 0;
    held.size = 0;
}

unsafe fn format_put(format: *mut Formatp, bytes: &[u8]) {
    let Some(held) = (unsafe { format.as_mut() }) else {
        return;
    };
    if held.original.is_null() {
        return;
    }
    let capacity = held.size.max(0) as usize;
    let room = capacity.saturating_sub(held.length.max(0) as usize);
    let take = bytes.len().min(room);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), held.buffer, take);
        held.buffer = held.buffer.add(take);
    }
    held.length += take as i32;
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn beacon_format_append(
    format: *mut Formatp,
    text: *const u8,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) {
    format_shim(format, text, [a2, a3, a4, a5, a6, a7]);
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn beacon_format_printf(
    format: *mut Formatp,
    format_text: *const u8,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) {
    format_shim(format, format_text, [a2, a3, a4, a5, a6, a7]);
}

fn format_shim(format: *mut Formatp, text: *const u8, slots: [usize; 6]) {
    let mut next = 0usize;
    let held = format_vargs(&unsafe { cstr(text) }, &mut || {
        let slot = slots.get(next).copied();
        next += 1;
        slot
    });
    match held {
        Ok(text) => unsafe { format_put(format, text.as_bytes()) },
        Err(cause) => unsafe {
            format_put(
                format,
                format!("[coff-v1] format refused: {cause}\n").as_bytes(),
            )
        },
    }
}

unsafe extern "C" fn beacon_format_append_string(format: *mut Formatp, text: *const u8) {
    let text = unsafe { cstr(text) };
    unsafe { format_put(format, &text) };
}

unsafe extern "C" fn beacon_format_int(format: *mut Formatp, value: i32) {
    unsafe { format_put(format, value.to_string().as_bytes()) };
}

unsafe extern "C" fn beacon_format_short(format: *mut Formatp, value: i16) {
    unsafe { format_put(format, value.to_string().as_bytes()) };
}

unsafe extern "C" fn beacon_format_length(format: *mut Formatp) -> i32 {
    (unsafe { format.as_ref() }).map_or(0, |held| held.length.max(0))
}

unsafe extern "C" fn beacon_format_to_string(format: *mut Formatp, size: *mut i32) -> *mut u8 {
    let Some(held) = (unsafe { format.as_mut() }) else {
        return std::ptr::null_mut();
    };
    if !size.is_null() {
        unsafe { *size = held.length };
    }
    if held.original.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { *held.buffer = 0 };
    held.original
}

unsafe extern "C" fn to_wide_char(source: *const u8, destination: *mut u16, max: i32) {
    if source.is_null() || destination.is_null() || max < 1 {
        return;
    }
    let bytes = unsafe { cstr(source) };
    let text = String::from_utf8_lossy(&bytes);
    let max = max as usize;
    let mut written = 0usize;
    for unit in text.encode_utf16() {
        if written + 1 >= max {
            break;
        }
        unsafe { *destination.add(written) = unit };
        written += 1;
    }
    unsafe { *destination.add(written) = 0 };
}

/// The host API table the loader binds `Beacon*` and `toWideChar`
/// names against: the data, output, and format families alone.
fn host_apis() -> Vec<(&'static str, usize)> {
    vec![
        ("BeaconOutput", beacon_output as *const () as usize),
        ("BeaconPrintf", beacon_printf as *const () as usize),
        ("BeaconDataParse", beacon_data_parse as *const () as usize),
        ("BeaconDataInt", beacon_data_int as *const () as usize),
        ("BeaconDataShort", beacon_data_short as *const () as usize),
        ("BeaconDataLength", beacon_data_length as *const () as usize),
        ("BeaconDataString", beacon_data_string as *const () as usize),
        (
            "BeaconDataExtract",
            beacon_data_extract as *const () as usize,
        ),
        (
            "BeaconFormatAlloc",
            beacon_format_alloc as *const () as usize,
        ),
        (
            "BeaconFormatReset",
            beacon_format_reset as *const () as usize,
        ),
        ("BeaconFormatFree", beacon_format_free as *const () as usize),
        (
            "BeaconFormatAppend",
            beacon_format_append as *const () as usize,
        ),
        (
            "BeaconFormatAppendString",
            beacon_format_append_string as *const () as usize,
        ),
        (
            "BeaconFormatPrintf",
            beacon_format_printf as *const () as usize,
        ),
        ("BeaconFormatInt", beacon_format_int as *const () as usize),
        (
            "BeaconFormatShort",
            beacon_format_short as *const () as usize,
        ),
        (
            "BeaconFormatLength",
            beacon_format_length as *const () as usize,
        ),
        (
            "BeaconFormatToString",
            beacon_format_to_string as *const () as usize,
        ),
        ("toWideChar", to_wide_char as *const () as usize),
    ]
}

/// What one external name resolves to, after the loader's `__imp_` and
/// underscore peels.
enum External {
    Host(&'static str),
    Kernel32(&'static str),
    System { module: String, function: String },
}

/// The kernel32 entry points the corpus imports bare (mingw links them
/// without a `MODULE$` prefix); every other system API rides the
/// dynamic reference.
const KERNEL32_PASSTHROUGH: &[&str] = &[
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetModuleHandleA",
    "FreeLibrary",
];

/// The Beacon API families coff-v1 refuses by name rather than binding
/// to a stub: the token and process-injection halves need the
/// impersonation and spawn plumbing the loader does not carry, and an
/// SEH handler external announces an exception frame this host does
/// not field. The refusal names the symbol so a build against the
/// supported family can proceed.
const REFUSED_EXTERNALS: &[&str] = &[
    "BeaconUseToken",
    "BeaconRevertToken",
    "BeaconIsAdmin",
    "BeaconGetSpawnTo",
    "BeaconSpawnTemporaryProcess",
    "BeaconInjectProcess",
    "BeaconInjectTemporaryProcess",
    "BeaconCleanupProcess",
    "BeaconGetCustomUserData",
    "BeaconGetOutputData",
    "__C_specific_handler",
    "___C_specific_handler",
];

fn classify_external(raw: &str, machine: u16) -> Result<External, String> {
    let mut name = raw.strip_prefix("__imp_").unwrap_or(raw);
    if machine == MACHINE_I386 {
        name = name.strip_prefix('_').unwrap_or(name);
    }
    if let Some((module, function)) = name.split_once('$') {
        let function = function.split('@').next().unwrap_or(function);
        if module.is_empty() || function.is_empty() {
            return Err(format!(
                "module.load: unresolved external '{raw}': a dynamic reference needs its MODULE$Function pair"
            ));
        }
        return Ok(External::System {
            module: module.to_string(),
            function: function.to_string(),
        });
    }
    if let Some(held) = KERNEL32_PASSTHROUGH.iter().find(|&&held| held == name) {
        return Ok(External::Kernel32(held));
    }
    if REFUSED_EXTERNALS.contains(&name) {
        return Err(format!(
            "module.load: unresolved external '{raw}': coff-v1 hosts the data, output, and format families alone (extending/modules.md)"
        ));
    }
    if let Some((held, _)) = host_apis().iter().find(|(held, _)| *held == name) {
        return Ok(External::Host(held));
    }
    Err(format!(
        "module.load: unresolved external '{raw}': not a host API name nor a MODULE$Function reference"
    ))
}

// --- The format engine --------------------------------------------------------

/// The conversions the corpus prints with: the integer, string, char,
/// and pointer families with their flags, widths, precisions, and
/// length modifiers. Floats and wide strings are refused by name -- a
/// misread argument is worse than a diagnostic.
fn format_vargs(format: &[u8], next: &mut dyn FnMut() -> Option<usize>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = format;
    while let Some(&first) = rest.first() {
        if first != b'%' {
            let end = rest.iter().position(|&b| b == b'%').unwrap_or(rest.len());
            out.push_str(&String::from_utf8_lossy(&rest[..end]));
            rest = &rest[end..];
            continue;
        }
        rest = &rest[1..];
        let Some(&second) = rest.first() else {
            return Err("the format ends on a bare %".into());
        };
        if second == b'%' {
            out.push('%');
            rest = &rest[1..];
            continue;
        }
        let mut minus = false;
        let mut plus = false;
        let mut space = false;
        let mut zero = false;
        let mut alt = false;
        loop {
            match rest.first() {
                Some(b'-') => minus = true,
                Some(b'+') => plus = true,
                Some(b' ') => space = true,
                Some(b'0') => zero = true,
                Some(b'#') => alt = true,
                _ => break,
            }
            rest = &rest[1..];
        }
        let mut width = None;
        if rest.first() == Some(&b'*') {
            let held = next().ok_or("%* asks for an argument the call did not carry")?;
            let held = held as i32;
            if held < 0 {
                minus = true;
            }
            width = Some(held.unsigned_abs() as usize);
            rest = &rest[1..];
        } else {
            let digits = leading_digits(rest);
            if !digits.is_empty() {
                width = Some(parse_digits(digits).ok_or("the format's width does not parse")?);
                rest = &rest[digits.len()..];
            }
        }
        let mut precision = None;
        if rest.first() == Some(&b'.') {
            rest = &rest[1..];
            if rest.first() == Some(&b'*') {
                let held = next().ok_or("%.* asks for an argument the call did not carry")?;
                precision = Some((held as i32).max(0) as usize);
                rest = &rest[1..];
            } else {
                let digits = leading_digits(rest);
                precision = Some(parse_digits(digits).unwrap_or(0));
                rest = &rest[digits.len()..];
            }
        }
        let mut longs = 0usize;
        let mut halves = 0usize;
        let mut wide = false;
        match rest.first() {
            Some(b'l') => {
                longs = 1 + rest[1..].starts_with(b"l") as usize;
                rest = &rest[longs..];
            }
            Some(b'h') => {
                halves = 1 + rest[1..].starts_with(b"h") as usize;
                rest = &rest[halves..];
            }
            Some(b'z') => {
                wide = true;
                rest = &rest[1..];
            }
            Some(b'I') if rest[1..].starts_with(b"64") => {
                wide = true;
                rest = &rest[3..];
            }
            Some(b'I') if rest[1..].starts_with(b"32") => {
                rest = &rest[3..];
            }
            _ => {}
        }
        let Some(&conversion) = rest.first() else {
            return Err("the format ends before its conversion".into());
        };
        rest = &rest[1..];
        let spec = Spec {
            minus,
            plus,
            space,
            zero,
            alt,
            width,
            precision,
        };
        match conversion {
            b'd' | b'i' | b'u' | b'x' | b'X' | b'o' => {
                let raw = next().ok_or("the format asks for an argument the call did not carry")?;
                let signed = conversion == b'd' || conversion == b'i';
                let (negative, magnitude) = interpret(raw, longs, halves, wide, signed);
                let base = match conversion {
                    b'o' => 8,
                    b'x' | b'X' => 16,
                    _ => 10,
                };
                render_number(
                    &mut out,
                    &spec,
                    negative,
                    magnitude,
                    base,
                    conversion == b'X',
                );
            }
            b'c' => {
                let raw = next().ok_or("the format asks for an argument the call did not carry")?;
                let text = char::from(raw as u8).to_string();
                render_text(&mut out, &spec, &text);
            }
            b's' => {
                if longs != 0 || halves != 0 {
                    return Err("the %ls/%hs string conversions are outside coff-v1".into());
                }
                let raw = next().ok_or("the format asks for an argument the call did not carry")?;
                let text = String::from_utf8_lossy(&unsafe { cstr(raw as *const u8) }).into_owned();
                render_text(&mut out, &spec, &text);
            }
            b'p' => {
                let raw = next().ok_or("the format asks for an argument the call did not carry")?;
                let text = format!("0x{raw:x}");
                render_text(&mut out, &spec, &text);
            }
            other => {
                let text = char::from(other);
                return Err(format!("the conversion %{text} is outside coff-v1"));
            }
        }
    }
    Ok(out)
}

struct Spec {
    minus: bool,
    plus: bool,
    space: bool,
    zero: bool,
    alt: bool,
    width: Option<usize>,
    precision: Option<usize>,
}

/// Reinterprets one raw argument under the directive's length: the
/// default and `l`/`I32` shapes are 32-bit, `ll`/`z`/`I64` the pointer
/// width, `h`/`hh` the narrowed reads. A set sign bit returns the
/// two's-complement magnitude (the width's own power of two minus the
/// value, which `wrapping_neg` states exactly).
fn interpret(raw: usize, longs: usize, halves: usize, wide: bool, signed: bool) -> (bool, u64) {
    if halves != 0 {
        let bits = if halves == 2 { 8 } else { 16 };
        let mask = (1u64 << bits) - 1;
        let value = (raw as u64) & mask;
        let sign_bit = 1u64 << (bits - 1);
        if signed && value & sign_bit != 0 {
            return (true, value.wrapping_neg() & mask);
        }
        return (false, value);
    }
    if wide || longs >= 2 {
        let value = raw as u64;
        if signed && value >> 63 != 0 {
            return (true, value.wrapping_neg());
        }
        return (false, value);
    }
    // The default and single `l` shapes are the 32-bit Windows `int`
    // and `long`.
    let value = (raw as u32) as u64;
    if signed && value >> 31 != 0 {
        return (true, (value as u32).wrapping_neg() as u64);
    }
    (false, value)
}

fn render_number(
    out: &mut String,
    spec: &Spec,
    negative: bool,
    magnitude: u64,
    base: u32,
    upper: bool,
) {
    let mut digits = String::new();
    let mut value = magnitude;
    loop {
        let digit = char::from_digit((value % base as u64) as u32, base)
            .unwrap_or('0')
            .to_ascii_uppercase();
        digits.insert(
            0,
            if upper {
                digit
            } else {
                digit.to_ascii_lowercase()
            },
        );
        value /= base as u64;
        if value == 0 {
            break;
        }
    }
    // A precision sets the least digit count (and prints nothing for a
    // bare zero); without one an integer shows at least one digit.
    let min_digits = spec.precision.unwrap_or(1);
    if magnitude == 0 && spec.precision == Some(0) {
        digits.clear();
    } else if digits.len() < min_digits {
        let pad = min_digits - digits.len();
        digits.insert_str(0, &"0".repeat(pad));
    }
    let sign = if negative {
        "-"
    } else if spec.plus {
        "+"
    } else if spec.space {
        " "
    } else {
        ""
    };
    let prefix = if spec.alt && base == 16 && magnitude != 0 {
        if upper {
            "0X"
        } else {
            "0x"
        }
    } else if spec.alt && base == 8 && !digits.starts_with('0') {
        "0"
    } else {
        ""
    };
    let width = spec.width.unwrap_or(0);
    let length = sign.len() + prefix.len() + digits.len();
    if length < width && !spec.minus && spec.zero && spec.precision.is_none() {
        let pad = "0".repeat(width - length);
        out.push_str(sign);
        out.push_str(prefix);
        out.push_str(&pad);
        out.push_str(&digits);
    } else if length < width && !spec.minus {
        let pad = " ".repeat(width - length);
        out.push_str(&pad);
        out.push_str(sign);
        out.push_str(prefix);
        out.push_str(&digits);
    } else {
        out.push_str(sign);
        out.push_str(prefix);
        out.push_str(&digits);
        if length < width {
            out.push_str(&" ".repeat(width - length));
        }
    }
}

fn render_text(out: &mut String, spec: &Spec, text: &str) {
    // A precision truncates by bytes the way C does, stepped back to a
    // char boundary so the truncation cannot split a code point.
    let held = match spec.precision {
        Some(precision) => {
            let mut cut = precision.min(text.len());
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            &text[..cut]
        }
        None => text,
    };
    let width = spec.width.unwrap_or(0);
    if held.len() < width {
        let pad = " ".repeat(width - held.len());
        if spec.minus {
            out.push_str(held);
            out.push_str(&pad);
        } else {
            out.push_str(&pad);
            out.push_str(held);
        }
    } else {
        out.push_str(held);
    }
}

fn parse_digits(digits: &[u8]) -> Option<usize> {
    std::str::from_utf8(digits).ok()?.parse().ok()
}

fn leading_digits(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn align_up(value: usize, to: usize) -> usize {
    (value + to - 1) & !(to - 1)
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn read_i16(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

// --- The Windows floor: allocation, resolution, the entry call -----------------

#[cfg(windows)]
pub(crate) mod host {
    use std::collections::HashMap;
    use std::ffi::CString;

    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    use crate::plugins::{Library, RunStatus, ABI_VERSION};

    use super::{
        apply_relocations, classify_external, copy_sections, entry, host_apis, pack_arguments,
        parse, placements, External, Host, HOST,
    };

    // The object machine this build binds: the process shape decides,
    // the way the PE map's machine check does.
    #[cfg(target_arch = "x86_64")]
    const HOST_MACHINE: u16 = super::MACHINE_AMD64;
    #[cfg(target_arch = "x86")]
    const HOST_MACHINE: u16 = super::MACHINE_I386;

    /// One loaded BOF: the image allocation (kept for its lifetime --
    /// the unload posture is the PE map's own: a BOF has no unload
    /// callback, and freeing pages under a handler the corpus still
    /// holds is worse than the leak) and the entry the dispatch calls.
    pub(crate) struct CoffLibrary {
        handle: String,
        base: *mut u8,
        entry: unsafe extern "C" fn(*const u8, u32),
    }

    // The allocation and the entry are raw addresses; dispatch holds
    // the module lock for the run's duration.
    unsafe impl Send for CoffLibrary {}

    impl CoffLibrary {
        pub(crate) fn load(handle: &str, bytes: &[u8]) -> Result<Box<dyn Library>, String> {
            #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
            {
                return Err(
                    "module.load: coff-v1 serves the x86 shapes; this build hosts none".into(),
                );
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            {
                let object = parse(bytes)?;
                if object.machine != HOST_MACHINE {
                    return Err(format!(
                        "module.load: the object's machine 0x{:x} is not this build's 0x{:x}",
                        object.machine, HOST_MACHINE
                    ));
                }
                let (size, offsets) = placements(&object);
                if size == 0 {
                    return Err("module.load: the object carries no loadable sections".into());
                }

                // Every external resolves before anything is allocated:
                // a BOF the host cannot bind refuses whole, named.
                let mut resolved: HashMap<String, usize> = HashMap::new();
                for symbol in object.symbols.iter().flatten() {
                    if symbol.section != 0 {
                        continue;
                    }
                    if resolved.contains_key(&symbol.name) {
                        continue;
                    }
                    let address = resolve(&symbol.name, object.machine)?;
                    resolved.insert(symbol.name.clone(), address);
                }

                let base = unsafe {
                    VirtualAlloc(
                        std::ptr::null(),
                        size,
                        MEM_RESERVE | MEM_COMMIT,
                        PAGE_EXECUTE_READWRITE,
                    )
                } as *mut u8;
                if base.is_null() {
                    return Err("module.load: the image allocation failed".into());
                }
                let image = unsafe { std::slice::from_raw_parts_mut(base, size) };
                copy_sections(image, bytes, &object, &offsets);
                let mut resolve = |symbol: &super::CoffSymbol| -> Result<usize, String> {
                    resolved.get(&symbol.name).copied().ok_or_else(|| {
                        format!("module.load: unresolved external '{}'", symbol.name)
                    })
                };
                apply_relocations(image, base as usize, &object, &offsets, &mut resolve)?;

                let (section, value) = entry(&object)?;
                let Some(placement) = offsets[section] else {
                    return Err("module.load: the entry sits in a discarded section".into());
                };
                let at = unsafe { base.add(placement + value as usize) };
                let entry: unsafe extern "C" fn(*const u8, u32) =
                    unsafe { std::mem::transmute(at) };
                Ok(Box::new(CoffLibrary {
                    handle: handle.to_string(),
                    base,
                    entry,
                }))
            }
        }
    }

    fn resolve(name: &str, machine: u16) -> Result<usize, String> {
        Ok(match classify_external(name, machine)? {
            External::Host(held) => host_apis()
                .iter()
                .find(|(candidate, _)| *candidate == held)
                .map(|(_, address)| *address)
                .expect("classify validated the name"),
            External::Kernel32(function) => proc_address(b"kernel32.dll\0", function, name)?,
            External::System { module, function } => {
                let mut bytes = module.into_bytes();
                bytes.push(0);
                proc_address(&bytes, &function, name)?
            }
        })
    }

    fn proc_address(module: &[u8], function: &str, raw: &str) -> Result<usize, String> {
        let library = unsafe { LoadLibraryA(module.as_ptr()) };
        if library.is_null() {
            return Err(format!(
                "module.load: unresolved external '{raw}': the '{}' module did not load",
                String::from_utf8_lossy(module.trim_ascii_end())
            ));
        }
        let Ok(name) = CString::new(function.as_bytes()) else {
            return Err(format!(
                "module.load: unresolved external '{raw}': the export name carries a NUL"
            ));
        };
        let Some(address) = (unsafe { GetProcAddress(library, name.as_ptr().cast()) }) else {
            return Err(format!(
                "module.load: unresolved external '{raw}': the module carries no export '{function}'"
            ));
        };
        Ok(address as usize)
    }

    impl Library for CoffLibrary {
        // A BOF carries no rod_plugin_abi export; the staged-carriage
        // contract the version names stands in for the absent call.
        fn abi(&self) -> Result<u32, String> {
            Ok(ABI_VERSION)
        }

        // The registry falls back to the task's handle when the module
        // declares none -- the honest answer for a BOF, which cannot.
        fn name(&self) -> String {
            String::new()
        }

        fn verb_count(&self) -> u32 {
            1
        }

        fn verb_name(&self, index: u32) -> Option<String> {
            (index == 0).then(|| format!("{}.go", self.handle))
        }

        fn run(&self, index: u32, arguments: &str) -> RunStatus {
            if index != 0 {
                return RunStatus::Error(format!("module has no verb {index}"));
            }
            let blob = match pack_arguments(arguments) {
                Ok(blob) => blob,
                Err(cause) => {
                    return RunStatus::Error(format!("the arguments do not parse: {cause}"))
                }
            };
            let host = Host::default();
            HOST.with(|cell| cell.set(&host as *const Host));
            unsafe { (self.entry)(blob.as_ptr(), blob.len() as u32) };
            HOST.with(|cell| cell.set(std::ptr::null()));
            let text = String::from_utf8_lossy(&host.out.into_inner()).into_owned();
            if host.err.get() {
                RunStatus::Failed(text)
            } else {
                RunStatus::Succeeded(text, None)
            }
        }
    }

    impl Drop for CoffLibrary {
        fn drop(&mut self) {
            // The leak is the posture: a BOF holds no unload callback,
            // and the allocation stays until the process ends.
            let _ = self.base;
        }
    }
}

#[cfg(windows)]
pub(crate) use host::CoffLibrary;

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    // --- A synthetic COFF builder: header, sections, symbols, string table

    struct SectionSpec {
        name: &'static str,
        data: Vec<u8>,
        relocs: Vec<(u32, u32, u16)>,
        discard: bool,
    }

    struct SymbolSpec {
        name: String,
        section: i16,
        value: u32,
    }

    fn build_object(machine: u16, sections: &[SectionSpec], symbols: &[SymbolSpec]) -> Vec<u8> {
        let mut long_names = Vec::new();
        let place_long = |name: &str, long_names: &mut Vec<u8>| -> String {
            if name.len() <= 8 {
                String::new()
            } else {
                let offset = 4 + long_names.len();
                long_names.extend_from_slice(name.as_bytes());
                long_names.push(0);
                format!("/{offset}")
            }
        };
        let section_name_hints: Vec<String> = sections
            .iter()
            .map(|section| place_long(section.name, &mut long_names))
            .collect();
        let symbol_name_hints: Vec<String> = symbols
            .iter()
            .map(|symbol| place_long(&symbol.name, &mut long_names))
            .collect();

        let mut bytes = Vec::new();
        let mut cursor = HEADER_LEN + sections.len() * SECTION_HEADER_LEN;
        // Section data first, relocations behind it.
        let mut data_at = Vec::new();
        let mut reloc_at = Vec::new();
        let mut relocs = Vec::new();
        for section in sections {
            data_at.push(cursor);
            bytes.extend_from_slice(&section.data);
            cursor += section.data.len();
            reloc_at.push(if section.relocs.is_empty() { 0 } else { cursor });
            relocs.clear();
            for (offset, symbol, kind) in &section.relocs {
                relocs.extend_from_slice(&offset.to_le_bytes());
                relocs.extend_from_slice(&symbol.to_le_bytes());
                relocs.extend_from_slice(&kind.to_le_bytes());
            }
            bytes.extend_from_slice(&relocs);
            cursor += section.relocs.len() * RELOCATION_LEN;
        }
        let symbol_table_at = cursor;
        let mut symbol_bytes = Vec::new();
        for (symbol, hint) in symbols.iter().zip(&symbol_name_hints) {
            let mut entry = Vec::with_capacity(SYMBOL_LEN);
            if hint.is_empty() {
                let mut inline = [0u8; 8];
                inline[..symbol.name.len()].copy_from_slice(symbol.name.as_bytes());
                entry.extend_from_slice(&inline);
            } else {
                let offset: u32 = hint[1..].parse().unwrap();
                entry.extend_from_slice(&[0, 0, 0, 0]);
                entry.extend_from_slice(&offset.to_le_bytes());
            }
            entry.extend_from_slice(&symbol.value.to_le_bytes());
            entry.extend_from_slice(&symbol.section.to_le_bytes());
            entry.extend_from_slice(&[0, 0]); // Type
            entry.extend_from_slice(&[2]); // StorageClass: external
            entry.extend_from_slice(&[0]); // NumberOfAuxSymbols
            symbol_bytes.extend_from_slice(&entry);
        }
        let mut string_table = (4 + long_names.len() as u32).to_le_bytes().to_vec();
        string_table.extend_from_slice(&long_names);

        let mut header = Vec::new();
        header.extend_from_slice(&machine.to_le_bytes());
        header.extend_from_slice(&(sections.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        header.extend_from_slice(&(symbol_table_at as u32).to_le_bytes());
        header.extend_from_slice(&(symbols.len() as u32).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes()); // SizeOfOptionalHeader
        header.extend_from_slice(&0u16.to_le_bytes()); // Characteristics
        bytes.splice(0..0, header);

        for (index, section) in sections.iter().enumerate() {
            let mut header = Vec::with_capacity(SECTION_HEADER_LEN);
            let mut name_field = [0u8; 8];
            let hint = &section_name_hints[index];
            if hint.is_empty() {
                name_field[..section.name.len()].copy_from_slice(section.name.as_bytes());
            } else {
                name_field[..hint.len()].copy_from_slice(hint.as_bytes());
            }
            header.extend_from_slice(&name_field);
            header.extend_from_slice(&0u32.to_le_bytes()); // VirtualSize
            header.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
            header.extend_from_slice(&(section.data.len() as u32).to_le_bytes());
            header.extend_from_slice(&(data_at[index] as u32).to_le_bytes());
            header.extend_from_slice(&(reloc_at[index] as u32).to_le_bytes());
            header.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
            header.extend_from_slice(&(section.relocs.len() as u16).to_le_bytes());
            header.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
            let flags: u32 = if section.discard {
                IMAGE_SCN_LNK_REMOVE
            } else {
                0x6000_0020 // code | execute | read
            };
            header.extend_from_slice(&flags.to_le_bytes());
            bytes.splice(
                HEADER_LEN + index * SECTION_HEADER_LEN..HEADER_LEN + index * SECTION_HEADER_LEN,
                header,
            );
        }

        bytes.extend_from_slice(&symbol_bytes);
        bytes.extend_from_slice(&string_table);
        bytes
    }

    fn sample() -> Vec<u8> {
        build_object(
            MACHINE_AMD64,
            &[
                SectionSpec {
                    name: ".text",
                    data: vec![0xcc; 64],
                    relocs: vec![],
                    discard: false,
                },
                SectionSpec {
                    name: ".rdata",
                    data: b"hello\0".to_vec(),
                    relocs: vec![],
                    discard: false,
                },
                SectionSpec {
                    name: ".debug$T",
                    data: vec![1, 2, 3],
                    relocs: vec![],
                    discard: true,
                },
            ],
            &[
                SymbolSpec {
                    name: "go".into(),
                    section: 1,
                    value: 0,
                },
                SymbolSpec {
                    name: "BeaconPrintf".into(),
                    section: 0,
                    value: 0,
                },
                SymbolSpec {
                    name: "message".into(),
                    section: 2,
                    value: 0,
                },
            ],
        )
    }

    #[test]
    fn parse_reads_the_object() {
        let coff = parse(&sample()).expect("the sample parses");
        assert_eq!(coff.machine, MACHINE_AMD64);
        assert_eq!(coff.sections.len(), 3);
        assert_eq!(coff.sections[0].name, ".text");
        assert_eq!(coff.sections[0].mapped, 64);
        assert_eq!(
            coff.sections[2].mapped, 0,
            "the discarded section maps nothing"
        );
        let symbols: Vec<&CoffSymbol> = coff.symbols.iter().flatten().collect();
        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[1].name, "BeaconPrintf");
        assert_eq!(symbols[1].section, 0);
    }

    #[test]
    fn long_names_ride_the_string_table() {
        let bytes = build_object(
            MACHINE_AMD64,
            &[SectionSpec {
                name: ".verylongtext",
                data: vec![0; 4],
                relocs: vec![],
                discard: false,
            }],
            &[SymbolSpec {
                name: "BeaconDataExtract".into(),
                section: 0,
                value: 0,
            }],
        );
        let coff = parse(&bytes).expect("the long names parse");
        assert_eq!(coff.sections[0].name, ".verylongtext");
        let symbols: Vec<&CoffSymbol> = coff.symbols.iter().flatten().collect();
        assert_eq!(symbols[0].name, "BeaconDataExtract");
    }

    #[test]
    fn malformed_objects_refuse_by_name() {
        let Err(short) = parse(&sample()[..10]) else {
            panic!("a truncated header refuses")
        };
        assert!(short.contains("shorter than a COFF header"));
        let Err(archive) = parse(b"!<arch>\nrest") else {
            panic!("an archive refuses")
        };
        assert!(archive.contains("archive"));
        let mut big = sample();
        big[0] = 0xff;
        big[1] = 0xff;
        let Err(big) = parse(&big) else {
            panic!("a big object refuses")
        };
        assert!(big.contains("big-object"));
        let mut arm = sample();
        arm[0] = 0x64;
        arm[1] = 0xaa;
        let Err(arm) = parse(&arm) else {
            panic!("a foreign machine refuses")
        };
        assert!(arm.contains("machine 0xaa64"));
        let mut image = sample();
        image[16] = 0xf0;
        image[17] = 0x00;
        let Err(image) = parse(&image) else {
            panic!("an optional header refuses")
        };
        assert!(image.contains("optional header"));
        let mut past = sample();
        // Point the symbol table past the end.
        let at = past.len();
        past[8..12].copy_from_slice(&((at + 4096) as u32).to_le_bytes());
        let Err(past) = parse(&past) else {
            panic!("a symbol table past the end refuses")
        };
        assert!(past.contains("symbol table runs past"));
    }

    #[test]
    fn discarded_sections_drop_out_of_the_image() {
        let coff = parse(&sample()).expect("the sample parses");
        let (size, offsets) = placements(&coff);
        assert_eq!(offsets[0], Some(0));
        assert_eq!(offsets[2], None);
        assert_eq!(size, 80, ".text (64) then .rdata (6) on 16-byte steps");
    }

    #[test]
    fn relocations_apply_the_x64_families() {
        // .text (slot 0) relocates against a symbol in .data (slot 80),
        // an external, and an absolute -- every family the x64 corpus
        // emits, each into its own 8-byte slot.
        let sections = vec![
            SectionSpec {
                name: ".text",
                data: vec![0; 80],
                relocs: vec![
                    (0, 1, 1),   // ADDR64 against 'answer'
                    (8, 1, 2),   // ADDR32
                    (16, 1, 3),  // ADDR32NB
                    (24, 1, 4),  // REL32
                    (32, 1, 6),  // REL32_2
                    (40, 4, 10), // SECTION against .data's own symbol
                    (48, 1, 11), // SECREL
                    (56, 2, 1),  // ADDR64 against the external
                    (64, 3, 1),  // ADDR64 against the absolute
                    (72, 2, 4),  // REL32 against the external
                ],
                discard: false,
            },
            SectionSpec {
                name: ".data",
                data: vec![0; 16],
                relocs: vec![],
                discard: false,
            },
        ];
        let symbols = vec![
            SymbolSpec {
                name: "go".into(),
                section: 1,
                value: 0,
            },
            SymbolSpec {
                name: "answer".into(),
                section: 2,
                value: 8,
            },
            SymbolSpec {
                name: "KERNEL32$Sleep".into(),
                section: 0,
                value: 0,
            },
            SymbolSpec {
                name: "the_answer".into(),
                section: -1,
                value: 0x1122,
            },
            SymbolSpec {
                name: ".data".into(),
                section: 2,
                value: 0,
            },
        ];
        let bytes = build_object(MACHINE_AMD64, &sections, &symbols);
        let coff = parse(&bytes).expect("the object parses");
        let (size, offsets) = placements(&coff);
        assert_eq!(size, 96);
        let mut image = vec![0u8; size];
        copy_sections(&mut image, &bytes, &coff, &offsets);
        let image_base = 0x1000_0000usize;
        let external = 0x7fff_0000_1000usize;
        apply_relocations(&mut image, image_base, &coff, &offsets, &mut |symbol| {
            assert_eq!(symbol.name, "KERNEL32$Sleep");
            Ok(external)
        })
        .expect("the families apply");

        let answer = (image_base + 80 + 8) as u64;
        let peek_u64 = |at: usize| u64::from_le_bytes(image[at..at + 8].try_into().unwrap());
        let peek_u32 = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        let peek_u16 = |at: usize| u16::from_le_bytes(image[at..at + 2].try_into().unwrap());
        assert_eq!(peek_u64(0), answer);
        assert_eq!(peek_u32(8), answer as u32);
        assert_eq!(peek_u32(16), (answer as usize - image_base) as u32);
        assert_eq!(
            peek_u32(24),
            (answer as i64 - (image_base + 24 + 4) as i64) as u32
        );
        assert_eq!(
            peek_u32(32),
            (answer as i64 - (image_base + 32 + 4 + 2) as i64) as u32
        );
        assert_eq!(peek_u16(40), 2);
        assert_eq!(peek_u32(48), 8);
        assert_eq!(peek_u64(56), external as u64);
        assert_eq!(peek_u64(64), 0x1122u64);
        assert_eq!(
            peek_u32(72),
            (external as i64 - (image_base + 72 + 4) as i64) as u32
        );
    }

    #[test]
    fn relocations_apply_the_x86_families() {
        let sections = vec![SectionSpec {
            name: ".text",
            data: vec![0; 16],
            relocs: vec![(0, 0, 6), (4, 1, 20), (8, 1, 7)],
            discard: false,
        }];
        let symbols = vec![
            SymbolSpec {
                name: "_go".into(),
                section: 1,
                value: 0,
            },
            SymbolSpec {
                name: "KERNEL32$Sleep".into(),
                section: 0,
                value: 0,
            },
        ];
        let bytes = build_object(MACHINE_I386, &sections, &symbols);
        let coff = parse(&bytes).expect("the object parses");
        let (size, offsets) = placements(&coff);
        let mut image = vec![0u8; size];
        copy_sections(&mut image, &bytes, &coff, &offsets);
        let image_base = 0x0040_0000usize;
        let external = 0x77dd_0000usize;
        apply_relocations(&mut image, image_base, &coff, &offsets, &mut |_| {
            Ok(external)
        })
        .expect("the x86 families apply");
        assert_eq!(
            u32::from_le_bytes(image[0..4].try_into().unwrap()),
            (image_base) as u32
        );
        assert_eq!(
            u32::from_le_bytes(image[4..8].try_into().unwrap()),
            (external as i64 - (image_base + 4 + 4) as i64) as u32
        );
        assert_eq!(
            u32::from_le_bytes(image[8..12].try_into().unwrap()),
            (external - image_base) as u32
        );
    }

    #[test]
    fn unknown_relocation_kinds_refuse_by_name() {
        let sections = vec![SectionSpec {
            name: ".text",
            data: vec![0; 8],
            relocs: vec![(0, 0, 31)],
            discard: false,
        }];
        let symbols = vec![SymbolSpec {
            name: "go".into(),
            section: 1,
            value: 0,
        }];
        let bytes = build_object(MACHINE_AMD64, &sections, &symbols);
        let coff = parse(&bytes).expect("the object parses");
        let (size, offsets) = placements(&coff);
        let mut image = vec![0u8; size];
        let cause = apply_relocations(&mut image, 0x1000, &coff, &offsets, &mut |_| Ok(0x2000))
            .expect_err("an unknown kind refuses");
        assert!(cause.contains("unsupported relocation type 31"), "{cause}");
    }

    #[test]
    fn the_entry_lookup_names_the_corpus_convention() {
        let coff = parse(&sample()).expect("the sample parses");
        let (section, value) = entry(&coff).expect("the x64 entry reads");
        assert_eq!((section, value), (0, 0));

        let bytes = build_object(
            MACHINE_I386,
            &[SectionSpec {
                name: ".text",
                data: vec![0x90; 4],
                relocs: vec![],
                discard: false,
            }],
            &[SymbolSpec {
                name: "_go".into(),
                section: 1,
                value: 0,
            }],
        );
        let coff = parse(&bytes).expect("the x86 object parses");
        assert!(entry(&coff).is_ok(), "the underscored entry reads");

        let bare = build_object(
            MACHINE_AMD64,
            &[SectionSpec {
                name: ".text",
                data: vec![0x90; 4],
                relocs: vec![],
                discard: false,
            }],
            &[SymbolSpec {
                name: "work".into(),
                section: 1,
                value: 0,
            }],
        );
        let coff = parse(&bare).expect("the entryless object parses");
        let cause = entry(&coff).expect_err("a missing entry refuses");
        assert!(cause.contains("no 'go' entry"), "{cause}");
    }

    #[test]
    fn external_classification_covers_the_corpus_shapes() {
        let host = classify_external("BeaconPrintf", MACHINE_AMD64).unwrap();
        assert!(matches!(host, External::Host("BeaconPrintf")));
        let imp = classify_external("__imp_BeaconDataInt", MACHINE_AMD64).unwrap();
        assert!(matches!(imp, External::Host("BeaconDataInt")));
        let dynamic = classify_external("__imp_KERNEL32$VirtualAlloc", MACHINE_AMD64).unwrap();
        assert!(matches!(
            dynamic,
            External::System {
                ref module,
                ref function,
            } if module == "KERNEL32" && function == "VirtualAlloc"
        ));
        let stdcall = classify_external("_KERNEL32$Sleep@4", MACHINE_I386).unwrap();
        assert!(matches!(
            stdcall,
            External::System {
                ref module,
                ref function,
            } if module == "KERNEL32" && function == "Sleep"
        ));
        let bare = classify_external("_GetProcAddress", MACHINE_I386).unwrap();
        assert!(matches!(bare, External::Kernel32("GetProcAddress")));

        let Err(refused) = classify_external("BeaconUseToken", MACHINE_AMD64) else {
            panic!("the token family refuses by name")
        };
        assert!(refused.contains("coff-v1 hosts"), "{refused}");
        let Err(seh) = classify_external("__C_specific_handler", MACHINE_AMD64) else {
            panic!("the SEH handler refuses by name")
        };
        assert!(seh.contains("coff-v1 hosts"), "{seh}");
        let unknown = classify_external("cosmic$ray", MACHINE_AMD64);
        assert!(unknown.is_ok(), "any MODULE$Function pair is dynamic");
        let Err(bare_unknown) = classify_external("SomeOddName", MACHINE_AMD64) else {
            panic!("a bare unknown name refuses")
        };
        assert!(
            bare_unknown.contains("not a host API name"),
            "{bare_unknown}"
        );
    }

    #[test]
    fn the_argument_grammar_packs_the_blob() {
        let empty = pack_arguments("   ").expect("empty packs");
        assert_eq!(empty, vec![0, 0, 0, 0]);

        let blob = pack_arguments("i:5 w:7 s:\"hi there\" b:0a0b").expect("the tokens pack");
        let mut expected = Vec::new();
        expected.extend_from_slice(&25u32.to_le_bytes());
        expected.extend_from_slice(&5i32.to_le_bytes());
        expected.extend_from_slice(&7i16.to_le_bytes());
        expected.extend_from_slice(&9u32.to_le_bytes());
        expected.extend_from_slice(b"hi there\0");
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[0x0a, 0x0b]);
        assert_eq!(blob, expected);

        let escaped = pack_arguments("s:\"quote \\\" and backslash \\\\ \"").expect("escapes pack");
        let body = &escaped[4..];
        let length = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
        assert_eq!(&body[4..4 + length], b"quote \" and backslash \\ \0");

        assert!(pack_arguments("x:5").is_err());
        assert!(pack_arguments("i:five").is_err());
        assert!(pack_arguments("b:0a1").is_err());
        assert!(pack_arguments("s:no-quote").is_err());
        assert!(pack_arguments("s:\"never closes").is_err());
    }

    #[test]
    fn beacon_data_walks_the_packed_blob() {
        let blob = pack_arguments("i:-1 w:7 s:\"hi\" b:0102").expect("the blob packs");
        let mut parser = Datap {
            original: std::ptr::null_mut(),
            buffer: std::ptr::null_mut(),
            length: 0,
            size: 0,
        };
        unsafe {
            beacon_data_parse(&mut parser, blob.as_ptr() as *mut u8, blob.len() as i32);
            assert_eq!(beacon_data_int(&mut parser), -1);
            assert_eq!(beacon_data_short(&mut parser), 7);
            let text = beacon_data_string(&mut parser);
            let text = std::ffi::CStr::from_ptr(text.cast()).to_bytes();
            assert_eq!(text, b"hi");
            let mut size = 0i32;
            let bytes = beacon_data_extract(&mut parser, &mut size);
            assert_eq!(size, 2);
            assert_eq!(std::slice::from_raw_parts(bytes, 2), [1, 2]);
            assert_eq!(beacon_data_length(&mut parser), 0);
            assert_eq!(
                beacon_data_int(&mut parser),
                0,
                "an exhausted parser yields zero"
            );
        }
    }

    #[test]
    fn beacon_output_accumulates_and_flags_errors() {
        let host = Host::default();
        HOST.with(|cell| cell.set(&host as *const Host));
        unsafe {
            beacon_output(0x0, b"ok line\n".as_ptr(), 8);
            beacon_output(0xd, b"bad line\n".as_ptr(), 9);
        }
        HOST.with(|cell| cell.set(std::ptr::null()));
        assert_eq!(host.out.into_inner(), b"ok line\nbad line\n".to_vec());
        assert!(host.err.get(), "a CALLBACK_ERROR line flags the run");
    }

    #[test]
    fn beacon_printf_formats_through_the_shim() {
        let name = b"bof\0";
        let format = b"count %d name %s hex %#06x pct %%\0";
        let host = Host::default();
        HOST.with(|cell| cell.set(&host as *const Host));
        unsafe {
            beacon_printf(
                0,
                format.as_ptr(),
                42usize,
                name.as_ptr() as usize,
                0xabusize,
                0,
                0,
                0,
            );
        }
        HOST.with(|cell| cell.set(std::ptr::null()));
        let out = String::from_utf8(host.out.into_inner()).expect("text");
        assert_eq!(out, "count 42 name bof hex 0x00ab pct %");
        assert!(!host.err.get());
    }

    #[test]
    fn the_format_engine_covers_the_corpus_directives() {
        assert_eq!(
            format_vargs(b"plain text", &mut || None).unwrap(),
            "plain text"
        );
        fn take(values: &[usize]) -> impl FnMut() -> Option<usize> + '_ {
            let mut next = 0usize;
            move || {
                let held = values.get(next).copied();
                next += 1;
                held
            }
        }
        let ints = [(-5i32) as usize, 7, 0xffff_ffff];
        assert_eq!(
            format_vargs(b"%d %i %u", &mut take(&ints)).unwrap(),
            "-5 7 4294967295"
        );
        let hexes = [0xabcd, 0xabcd, 8];
        assert_eq!(
            format_vargs(b"%x %X %o", &mut take(&hexes)).unwrap(),
            "abcd ABCD 10"
        );
        let pads = [42, 42];
        assert_eq!(
            format_vargs(b"%05d %-6d|", &mut take(&pads)).unwrap(),
            "00042 42    |"
        );
        assert_eq!(
            format_vargs(b"%+d % d", &mut take(&pads)).unwrap(),
            "+42  42"
        );
        let star = [5, 7];
        assert_eq!(format_vargs(b"%.*d", &mut take(&star)).unwrap(), "00007");
        let long = [(-1i64) as usize];
        assert_eq!(format_vargs(b"%lld", &mut take(&long)).unwrap(), "-1");
        let sized = [0xffff_ffffusize];
        assert_eq!(
            format_vargs(b"%zu", &mut take(&sized)).unwrap(),
            "4294967295"
        );
        let half = [0xffffusize];
        assert_eq!(format_vargs(b"%hd", &mut take(&half)).unwrap(), "-1");
        let text = b"hello\0";
        let strings = [
            text.as_ptr() as usize,
            text.as_ptr() as usize,
            text.as_ptr() as usize,
        ];
        assert_eq!(
            format_vargs(b"%.2s|%6s|%-6s|", &mut take(&strings)).unwrap(),
            "he| hello|hello |"
        );
        let chars = [b'a' as usize, b'Z' as usize];
        assert_eq!(format_vargs(b"%c%c", &mut take(&chars)).unwrap(), "aZ");
        let pointer = [0x7fff_0000_1000usize];
        assert_eq!(
            format_vargs(b"%p", &mut take(&pointer)).unwrap(),
            "0x7fff00001000"
        );
        let none = [0usize];
        assert!(
            format_vargs(b"%f", &mut take(&none)).is_err(),
            "floats refuse"
        );
        assert!(
            format_vargs(b"%n", &mut take(&none)).is_err(),
            "the write primitive refuses"
        );
        assert!(
            format_vargs(b"%d %d", &mut take(&[1usize])).is_err(),
            "a missing argument refuses"
        );
    }

    #[test]
    fn to_wide_char_encodes_utf16() {
        let source = b"rod\0";
        let mut wide = [0xffffu16; 8];
        unsafe { to_wide_char(source.as_ptr(), wide.as_mut_ptr(), 8) };
        assert_eq!(&wide[..4], &[0x72, 0x6f, 0x64, 0]);
        assert_eq!(wide[4], 0xffff, "the tail past the terminator is untouched");
    }

    // A real mingw-built object exercises the genuine relocation mix
    // (REL32 against imports, section symbols, the aux walk) end to end
    // through the host-blind core. The cross compiler is the one the CI
    // toolchain lane installs; without it the test steps aside.
    #[test]
    fn a_real_mingw_object_parses_and_relocates() {
        if !on_path("x86_64-w64-mingw32-gcc") {
            eprintln!("skipping: x86_64-w64-mingw32-gcc is not on PATH");
            return;
        }
        let dir = std::env::temp_dir().join("rod-coff-fixture");
        std::fs::create_dir_all(&dir).expect("the fixture dir creates");
        let source = dir.join("fixture.c");
        std::fs::write(
            &source,
            "extern void BeaconPrintf(int type, const char *format, ...);\n\
             extern void KERNEL32$Sleep(unsigned long ms);\n\
             void go(char *args, unsigned long length) {\n\
                 KERNEL32$Sleep(1);\n\
                 BeaconPrintf(0, \"fixture ran: %d\\\\n\", 123);\n\
                 (void)args; (void)length;\n\
             }\n",
        )
        .expect("the fixture source writes");
        let object = dir.join("fixture.o");
        let built = Command::new("x86_64-w64-mingw32-gcc")
            .arg("-c")
            .arg("-o")
            .arg(&object)
            .arg(&source)
            .output()
            .expect("the cross compiler starts");
        assert!(
            built.status.success(),
            "the fixture build failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let bytes = std::fs::read(&object).expect("the object reads");
        let coff = parse(&bytes).expect("the real object parses");
        assert_eq!(coff.machine, MACHINE_AMD64);
        let (size, offsets) = placements(&coff);
        assert!(size > 0);
        let mut image = vec![0u8; size];
        copy_sections(&mut image, &bytes, &coff, &offsets);
        let mut bound = 0usize;
        apply_relocations(&mut image, 0x1000_0000, &coff, &offsets, &mut |symbol| {
            bound += 1;
            match classify_external(&symbol.name, coff.machine)? {
                External::Host(_) => Ok(0x2000_0000),
                External::Kernel32(_) => Ok(0x2100_0000),
                External::System { .. } => Ok(0x2200_0000),
            }
        })
        .expect("the real relocations apply");
        assert!(bound >= 2, "the fixture's externals all resolved");
        assert!(entry(&coff).is_ok(), "the fixture's go entry reads");
    }

    fn on_path(program: &str) -> bool {
        std::env::var_os("PATH")
            .map(|paths| {
                std::env::split_paths(&paths).any(|dir| {
                    dir.join(program).is_file() || dir.join(format!("{program}.exe")).is_file()
                })
            })
            .unwrap_or(false)
    }
}
