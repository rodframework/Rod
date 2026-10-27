//! The SQLite file reader (the module's whole store-parse surface):
//! the rows a Chromium Login Data database carries, read out of the
//! file's own bytes with no store library on the target -- the file
//! arrives as a slice, so this half runs and its tests pin it on any
//! host. Only the reading of the file sits behind `cfg(windows)`, and
//! the Windows crosses the CI lane builds prove that half compiles.
//!
//! The reader walks the documented layout exactly -- file header to
//! the sqlite_master b-tree on page 1 to the named table's root, then
//! interior and leaf pages, records, and the overflow chains that
//! carry payloads wider than a page -- and refuses at every boundary:
//! a truncated or malformed database is an error naming the offender,
//! never a guessed row set. The write-ahead log a live browser keeps
//! beside the store is a later widening; this read answers for the
//! main file as it sits, and the rows it carries are committed rows.

/// One column value as the record laid it down.
#[derive(Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Blob(Vec<u8>),
    Text(String),
}

/// A table the reader read out of the database: the CREATE statement
/// its sqlite_master row carries (the caller binds columns by name
/// from it) and the table's rows, in the b-tree's own rowid order.
#[derive(Debug)]
pub(crate) struct TableRead {
    pub create_sql: String,
    pub rows: Vec<Vec<Value>>,
}

/// Reads every row of the named table.
pub(crate) fn read_table(database: &[u8], table: &str) -> Result<TableRead, String> {
    let reader = Reader::open(database)?;
    let master = reader.walk(1)?;
    for row in &master {
        if as_text(row.first()) != Some("table") {
            continue;
        }
        if as_text(row.get(1)).is_none_or(|name| !name.eq_ignore_ascii_case(table)) {
            continue;
        }
        let root = as_integer(row.get(3)).ok_or_else(|| {
            format!("malformed database: the '{table}' schema row carries no root page")
        })?;
        if root <= 0 {
            return Err(format!(
                "the '{table}' table has no b-tree to walk (a virtual table)"
            ));
        }
        let create_sql = as_text(row.get(4)).unwrap_or_default().to_string();
        let rows = reader.walk(root as u32)?;
        return Ok(TableRead { create_sql, rows });
    }
    Err(format!("the database carries no '{table}' table"))
}

fn as_text(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::Text(text)) => Some(text),
        _ => None,
    }
}

fn as_integer(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Integer(number)) => Some(*number),
        _ => None,
    }
}

/// The database's own geometry: everything the walk derives from the
/// 100-byte file header, held once so every page read checks against
/// the same numbers.
struct Reader<'a> {
    bytes: &'a [u8],
    page_size: usize,
    usable: usize,
    pages: u32,
}

impl<'a> Reader<'a> {
    fn open(bytes: &'a [u8]) -> Result<Reader<'a>, String> {
        let header = slice(bytes, 0, 100, "the file header")?;
        if &header[0..16] != b"SQLite format 3\0" {
            return Err("not a SQLite database: the header magic is absent".to_string());
        }
        let raw = u16::from_be_bytes([header[16], header[17]]);
        let page_size = if raw == 1 { 65536 } else { raw as usize };
        if !page_size.is_power_of_two() || !(512..=65536).contains(&page_size) {
            return Err(format!(
                "malformed database: the page size {page_size} is not one the format defines"
            ));
        }
        let usable = page_size - header[20] as usize;
        if usable < 480 {
            return Err(
                "malformed database: the reserved region leaves less than the 480 usable \
                 bytes the format requires"
                    .to_string(),
            );
        }
        let encoding = u32_at(header, 56);
        if encoding != 1 {
            return Err(format!(
                "the database's text encoding ({encoding}) is not the UTF-8 store files carry"
            ));
        }
        let mut pages = u32_at(header, 28);
        if pages == 0 {
            // A legacy header leaves the count to the file itself.
            pages = (bytes.len() / page_size) as u32;
        }
        Ok(Reader {
            bytes,
            page_size,
            usable,
            pages,
        })
    }

    /// One page's bytes, bounds-checked against both the header's page
    /// count and the file's real length -- a page outside either is
    /// malformed, not a zero page.
    fn page(&self, number: u32) -> Result<&[u8], String> {
        if number == 0 || number > self.pages {
            return Err(format!(
                "malformed database: page {number} is outside the database's {} pages",
                self.pages
            ));
        }
        let start = (number as usize - 1) * self.page_size;
        slice(self.bytes, start, self.page_size, &format!("page {number}"))
    }

    /// Every row under the b-tree rooted at the page: children left to
    /// right, the rightmost pointer last -- the tree's own rowid order.
    /// A page the walk revisits refuses: in a well-formed b-tree each
    /// page appears exactly once, so a repeat is corruption, and
    /// refusing it is what keeps a malformed tree from looping.
    fn walk(&self, root: u32) -> Result<Vec<Vec<Value>>, String> {
        let mut rows = Vec::new();
        let mut visited: Vec<u32> = Vec::new();
        self.walk_page(root, &mut visited, &mut rows)?;
        Ok(rows)
    }

    fn walk_page(
        &self,
        number: u32,
        visited: &mut Vec<u32>,
        rows: &mut Vec<Vec<Value>>,
    ) -> Result<(), String> {
        if visited.contains(&number) {
            return Err(format!(
                "malformed database: the b-tree revisits page {number}"
            ));
        }
        visited.push(number);
        let page = self.page(number)?;
        // Page 1 carries the 100-byte file header before its b-tree
        // header; every other page starts at its own first byte.
        let header = if number == 1 { 100 } else { 0 };
        let page_type = *page
            .get(header)
            .ok_or("truncated database: a page ends before its header")?;
        let cells = u16_at(page, header + 3) as usize;
        let pointers = header + if page_type == 5 { 12 } else { 8 };

        match page_type {
            13 => {
                for index in 0..cells {
                    let at = self.cell_offset(page, pointers, index)?;
                    let payload = self.cell_payload(page, at)?;
                    rows.push(record(&payload)?);
                }
            }
            5 => {
                for index in 0..cells {
                    let at = self.cell_offset(page, pointers, index)?;
                    let child = u32_at(page, at);
                    self.walk_page(child, visited, rows)?;
                }
                let rightmost = u32_at(page, header + 8);
                self.walk_page(rightmost, visited, rows)?;
            }
            2 | 10 => {
                return Err(format!(
                    "malformed database: page {number} is an index page where a table page \
                     belongs"
                ));
            }
            other => {
                return Err(format!(
                    "malformed database: page {number} carries unknown b-tree page type {other}"
                ));
            }
        }
        Ok(())
    }

    fn cell_offset(&self, page: &[u8], pointers: usize, index: usize) -> Result<usize, String> {
        let at = u16_at(page, pointers + index * 2) as usize;
        if at >= page.len() {
            return Err(
                "malformed database: a cell pointer runs past its own page's end".to_string(),
            );
        }
        Ok(at)
    }

    /// A table-leaf cell's payload, with the wide-payload case
    /// reassembled: the format keeps the first bytes local and chains
    /// the rest through overflow pages, and the split arithmetic is
    /// the format's own (X, M, K over the usable page size).
    fn cell_payload(&self, page: &[u8], at: usize) -> Result<Vec<u8>, String> {
        let (payload_len, header) = varint(page, at)?;
        let (_rowid, more) = varint(page, at + header)?;
        let data = at + header + more;
        let payload_len = payload_len as usize;
        let threshold = self.usable - 35;
        if payload_len <= threshold {
            return slice(page, data, payload_len, "a cell's payload").map(|bytes| bytes.to_vec());
        }

        let usable = self.usable;
        let m = ((usable - 12) * 32 / 255) - 23;
        let k = m + ((payload_len - m) % (usable - 4));
        let local = if k <= threshold { k } else { m };
        let mut payload = slice(page, data, local, "a cell's local payload")?.to_vec();
        let chain = slice(page, data + local, 4, "an overflow pointer")?;
        let first = u32::from_be_bytes([chain[0], chain[1], chain[2], chain[3]]);
        payload.extend(self.overflow(first, payload_len - local)?);
        Ok(payload)
    }

    /// The overflow chain behind a wide payload: each page names the
    /// next and carries usable-minus-four content bytes. No honest
    /// chain outwalks the database, so the page count is the chain's
    /// budget, and a chain that ends early refuses rather than
    /// padding the payload with zeros.
    fn overflow(&self, first: u32, mut remaining: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let mut number = first;
        let mut budget = self.pages as usize;
        while remaining > 0 {
            if budget == 0 {
                return Err("malformed database: the overflow chain does not terminate".to_string());
            }
            budget -= 1;
            let page = self.page(number)?;
            let next = u32_at(page, 0);
            let take = remaining.min(self.usable - 4);
            out.extend(slice(page, 4, take, "an overflow page's content")?);
            remaining -= take;
            if next == 0 && remaining > 0 {
                return Err(
                    "malformed database: the overflow chain ends before the payload does"
                        .to_string(),
                );
            }
            number = next;
        }
        Ok(out)
    }
}

/// A record: the header's own length, then the serial types, then the
/// values in order. The reserved serial types (10, 11) refuse, and a
/// value that runs past the payload refuses with it.
fn record(payload: &[u8]) -> Result<Vec<Value>, String> {
    let (header_len, read) = varint(payload, 0)?;
    let header_len = header_len as usize;
    if header_len < read || header_len > payload.len() {
        return Err("malformed database: a record's header length is impossible".to_string());
    }

    let mut kinds = Vec::new();
    let mut at = read;
    while at < header_len {
        let (kind, consumed) = varint(payload, at)?;
        at += consumed;
        kinds.push(kind);
    }
    if at != header_len {
        return Err("malformed database: a serial type runs past the record's header".to_string());
    }

    let mut values = Vec::with_capacity(kinds.len());
    let mut body = header_len;
    for kind in kinds {
        let (value, size) = match kind {
            0 => (Value::Null, 0),
            width @ 1..=6 => {
                let width = width as usize;
                let bytes = slice(payload, body, width, "an integer value")?;
                let mut raw = [0u8; 8];
                raw[8 - width..].copy_from_slice(bytes);
                // Left then arithmetic right: the two shifts together
                // sign-extend a narrow value into the 64 bits every
                // integer value reads as.
                let number = (i64::from_be_bytes(raw) << (64 - width * 8)) >> (64 - width * 8);
                (Value::Integer(number), width)
            }
            7 => {
                let bytes = slice(payload, body, 8, "a real value")?;
                let number = f64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                (Value::Real(number), 8)
            }
            8 => (Value::Integer(0), 0),
            9 => (Value::Integer(1), 0),
            10 | 11 => {
                return Err(
                    "malformed database: a record carries a reserved serial type".to_string(),
                )
            }
            even if even % 2 == 0 => {
                let width = ((even - 12) / 2) as usize;
                let bytes = slice(payload, body, width, "a blob value")?;
                (Value::Blob(bytes.to_vec()), width)
            }
            odd => {
                let width = ((odd - 13) / 2) as usize;
                let bytes = slice(payload, body, width, "a text value")?;
                // The encoding gate at open guarantees UTF-8; lossy
                // renders a straggler byte rather than refusing the
                // whole store over one value.
                (
                    Value::Text(String::from_utf8_lossy(bytes).into_owned()),
                    width,
                )
            }
        };
        body += size;
        values.push(value);
    }
    Ok(values)
}

/// The format's own variable-length integer: up to nine bytes, the
/// first eight carrying seven bits each under a continuation bit and
/// the ninth carrying eight.
fn varint(bytes: &[u8], at: usize) -> Result<(u64, usize), String> {
    let mut value: u64 = 0;
    for index in 0..9 {
        let byte = *bytes
            .get(at + index)
            .ok_or("truncated database: a varint runs past its bytes")?;
        if index == 8 {
            return Ok(((value << 8) | byte as u64, 9));
        }
        value = (value << 7) | (byte & 0x7F) as u64;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    unreachable!("the loop returns on the ninth byte at the latest")
}

fn slice<'a>(bytes: &'a [u8], at: usize, length: usize, what: &str) -> Result<&'a [u8], String> {
    let end = at.checked_add(length).ok_or("malformed database")?;
    bytes
        .get(at..end)
        .ok_or_else(|| format!("truncated database: {what} runs past its bytes"))
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the fixture: databases shaped at will ----

    /// One database under construction: pages reserved by number up
    /// front, so a cell can name its overflow chain and a schema row
    /// its root before the bytes exist.
    struct Fixture {
        page_size: usize,
        pages: Vec<Vec<u8>>,
    }

    impl Fixture {
        fn with(page_size: usize, count: usize) -> Fixture {
            Fixture {
                page_size,
                pages: vec![vec![0u8; page_size]; count],
            }
        }

        fn set(&mut self, number: u32, page: Vec<u8>) {
            self.pages[(number - 1) as usize] = page;
        }

        /// Page 1: the 100-byte file header carrying the fields the
        /// reader reads, then the sqlite_master leaf built from the
        /// schema cells.
        fn master(&mut self, cells: &[Vec<u8>]) {
            let mut page = std::mem::take(&mut self.pages[0]);
            page[0..16].copy_from_slice(b"SQLite format 3\0");
            let raw = if self.page_size == 65536 {
                1u16
            } else {
                self.page_size as u16
            };
            page[16..18].copy_from_slice(&raw.to_be_bytes());
            page[18] = 1; // write version
            page[19] = 1; // read version
            page[28..32].copy_from_slice(&(self.pages.len() as u32).to_be_bytes());
            page[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
            write_leaf(&mut page, 100, cells);
            self.pages[0] = page;
        }

        fn finish(self) -> Vec<u8> {
            self.pages.concat()
        }
    }

    /// A table-leaf page: type, cell count, content start, the pointer
    /// array, and the cells laid down from the page's end.
    fn leaf_page(page_size: usize, cells: &[Vec<u8>]) -> Vec<u8> {
        let mut page = vec![0u8; page_size];
        write_leaf(&mut page, 0, cells);
        page
    }

    /// The leaf layout with its b-tree header at `header` -- 0 for
    /// every page but page 1, whose header sits behind the 100-byte
    /// file header. Cell pointers and offsets are page-relative
    /// either way, the format's own rule.
    fn write_leaf(page: &mut [u8], header: usize, cells: &[Vec<u8>]) {
        page[header] = 13;
        page[header + 3..header + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        let mut at = page.len();
        let mut offsets = Vec::new();
        for cell in cells {
            at -= cell.len();
            page[at..at + cell.len()].copy_from_slice(cell);
            offsets.push(at as u16);
        }
        let start = if cells.is_empty() { page.len() } else { at };
        let start = if start == 65536 { 0u16 } else { start as u16 };
        page[header + 5..header + 7].copy_from_slice(&start.to_be_bytes());
        let mut pointer = header + 8;
        for offset in offsets {
            page[pointer..pointer + 2].copy_from_slice(&offset.to_be_bytes());
            pointer += 2;
        }
    }

    /// A table-interior page: one four-byte child pointer per cell,
    /// then the rightmost child in the header.
    fn interior_page(children: &[u32], rightmost: u32) -> Vec<u8> {
        let mut page = vec![0u8; 512];
        page[0] = 5;
        page[3..5].copy_from_slice(&(children.len() as u16).to_be_bytes());
        page[8..12].copy_from_slice(&rightmost.to_be_bytes());

        let cells: Vec<Vec<u8>> = children
            .iter()
            .enumerate()
            .map(|(index, child)| {
                let mut cell = child.to_be_bytes().to_vec();
                cell.extend(varint_bytes(50 + index as u64));
                cell
            })
            .collect();
        let mut at = page.len();
        let mut offsets = Vec::new();
        for cell in &cells {
            at -= cell.len();
            page[at..at + cell.len()].copy_from_slice(cell);
            offsets.push(at as u16);
        }
        page[5..7].copy_from_slice(&(at as u16).to_be_bytes());
        for (index, offset) in offsets.iter().enumerate() {
            page[12 + index * 2..14 + index * 2].copy_from_slice(&offset.to_be_bytes());
        }
        page
    }

    /// A table-leaf cell for a payload the page carries whole.
    fn leaf_cell(rowid: u64, payload: &[u8]) -> Vec<u8> {
        let mut cell = varint_bytes(payload.len() as u64);
        cell.extend(varint_bytes(rowid));
        cell.extend_from_slice(payload);
        cell
    }

    fn varint_bytes(mut value: u64) -> Vec<u8> {
        let mut groups = Vec::new();
        loop {
            groups.push((value & 0x7F) as u8);
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        groups.reverse();
        let last = groups.len() - 1;
        groups
            .into_iter()
            .enumerate()
            .map(|(index, group)| if index < last { group | 0x80 } else { group })
            .collect()
    }

    /// A record the way SQLite lays one down: the header's own length,
    /// the serial types, then the values. Integers stay inside one
    /// byte -- the widths the fixture writes are the widths it tests.
    fn record_bytes(values: &[Value]) -> Vec<u8> {
        let mut kinds = Vec::new();
        let mut body = Vec::new();
        for value in values {
            match value {
                Value::Null => kinds.extend(varint_bytes(0)),
                Value::Integer(0) => kinds.extend(varint_bytes(8)),
                Value::Integer(1) => kinds.extend(varint_bytes(9)),
                Value::Integer(small) if (-128..=127).contains(small) => {
                    kinds.extend(varint_bytes(1));
                    body.push(*small as i8 as u8);
                }
                Value::Integer(other) => panic!("the fixture writes one-byte integers: {other}"),
                Value::Real(number) => {
                    kinds.extend(varint_bytes(7));
                    body.extend_from_slice(&number.to_be_bytes());
                }
                Value::Blob(bytes) => {
                    kinds.extend(varint_bytes(12 + 2 * bytes.len() as u64));
                    body.extend_from_slice(bytes);
                }
                Value::Text(text) => {
                    kinds.extend(varint_bytes(13 + 2 * text.len() as u64));
                    body.extend_from_slice(text.as_bytes());
                }
            }
        }
        let mut length_bytes = 1;
        let header_len = loop {
            let candidate = length_bytes + kinds.len();
            if varint_bytes(candidate as u64).len() == length_bytes {
                break candidate;
            }
            length_bytes += 1;
        };
        let mut payload = varint_bytes(header_len as u64);
        payload.extend(kinds);
        payload.extend(body);
        payload
    }

    /// The sqlite_master row naming one table: (table, name, name,
    /// rootpage, sql).
    fn schema_cell(root: u32, name: &str, sql: &str) -> Vec<u8> {
        leaf_cell(
            1,
            &record_bytes(&[
                Value::Text("table".into()),
                Value::Text(name.into()),
                Value::Text(name.into()),
                Value::Integer(root as i64),
                Value::Text(sql.into()),
            ]),
        )
    }

    const CREATE: &str =
        "CREATE TABLE logins (origin_url VARCHAR, username_value VARCHAR, password_value BLOB)";

    // ---- the reader against the fixture ----

    #[test]
    fn the_logins_read_as_the_store_wrote_them() {
        let body = |rowid, origin: &str, username: &str, password: &[u8]| {
            leaf_cell(
                rowid,
                &record_bytes(&[
                    Value::Text(origin.into()),
                    Value::Text(username.into()),
                    Value::Blob(password.to_vec()),
                ]),
            )
        };
        let cells = vec![
            body(1, "https://example.com/", "alice", b"\x33 sealed"),
            body(2, "https://bank.example/", "bob", b"v10"),
        ];

        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &cells));

        let read = read_table(&fixture.finish(), "logins").unwrap();
        assert_eq!(read.create_sql, CREATE);
        assert_eq!(read.rows.len(), 2);
        assert_eq!(
            read.rows[0],
            vec![
                Value::Text("https://example.com/".into()),
                Value::Text("alice".into()),
                Value::Blob(b"\x33 sealed".to_vec()),
            ]
        );
        // The second row's password_value is the raw sealed bytes as
        // they sit in the file -- the sealed split is the caller's.
        assert_eq!(read.rows[1][2], Value::Blob(b"v10".to_vec()));
    }

    #[test]
    fn rows_read_through_interior_pages_in_rowid_order() {
        let leaf = |rowids: &[u64]| {
            let cells: Vec<Vec<u8>> = rowids
                .iter()
                .map(|rowid| {
                    leaf_cell(
                        *rowid,
                        &record_bytes(&[
                            Value::Text("https://example.com/".into()),
                            Value::Integer(*rowid as i64),
                            Value::Null,
                        ]),
                    )
                })
                .collect();
            leaf_page(512, &cells)
        };

        let mut fixture = Fixture::with(512, 5);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, interior_page(&[3, 4], 5));
        fixture.set(3, leaf(&[1, 2]));
        fixture.set(4, leaf(&[51]));
        fixture.set(5, leaf(&[101, 102]));

        let read = read_table(&fixture.finish(), "logins").unwrap();
        let order: Vec<i64> = read
            .rows
            .iter()
            .map(|row| match &row[1] {
                Value::Integer(number) => *number,
                other => panic!("the fixture wrote integers: {other:?}"),
            })
            .collect();
        assert_eq!(order, vec![1, 2, 51, 101, 102]);
    }

    #[test]
    fn a_wide_row_reassembles_through_overflow_pages() {
        // 512-byte pages leave 477 local bytes; a record this wide
        // keeps 39 local and chains the rest through 508-byte overflow
        // pages -- the format's own M/K arithmetic, computed here the
        // same way the reader computes it.
        let payload: Vec<u8> = (0..2000u16).map(|byte| byte as u8).collect();
        let record = record_bytes(&[
            Value::Text("https://example.com/".into()),
            Value::Blob(payload.clone()),
        ]);
        let usable = 512usize;
        let threshold = usable - 35;
        let m = ((usable - 12) * 32 / 255) - 23;
        let k = m + ((record.len() - m) % (usable - 4));
        let local = if k <= threshold { k } else { m };
        let count = (record.len() - local).div_ceil(usable - 4);

        let mut fixture = Fixture::with(512, 2 + count);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);

        // Pages 3.. carry the chain; page 2 is the leaf naming it.
        let mut tail = &record[local..];
        for index in 0..count {
            let number = 3 + index as u32;
            let next = if index + 1 < count { number + 1 } else { 0 };
            let page = &mut fixture.pages[(number - 1) as usize];
            page[0..4].copy_from_slice(&next.to_be_bytes());
            let take = tail.len().min(usable - 4);
            page[4..4 + take].copy_from_slice(&tail[..take]);
            tail = &tail[take..];
        }
        assert!(tail.is_empty(), "the chain must carry the whole payload");

        let mut cell = varint_bytes(record.len() as u64);
        cell.extend(varint_bytes(1));
        cell.extend_from_slice(&record[..local]);
        cell.extend_from_slice(&3u32.to_be_bytes());
        fixture.set(2, leaf_page(512, &[cell]));

        let read = read_table(&fixture.finish(), "logins").unwrap();
        assert_eq!(read.rows.len(), 1);
        assert_eq!(read.rows[0][1], Value::Blob(payload));
    }

    #[test]
    fn an_empty_table_reads_no_rows() {
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &[]));
        let read = read_table(&fixture.finish(), "logins").unwrap();
        assert!(read.rows.is_empty());
    }

    #[test]
    fn the_varint_reads_every_form_the_format_defines() {
        // Eight continuation bytes then a full eighth-bit ninth byte.
        let (value, read) =
            varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02], 0).unwrap();
        assert_eq!(read, 9);
        // The nine-byte form packs the first eight bytes' seven-bit
        // groups contiguously, then the ninth byte's full eight bits.
        assert_eq!(value, 0xFFFF_FFFF_FFFF_FF02);
        // A short varint reads its seven-bit groups.
        let (value, read) = varint(&[0x81, 0x01], 0).unwrap();
        assert_eq!((value, read), (129, 2));
        // Truncated mid-varint refuses.
        assert!(varint(&[0x81], 0).is_err());
    }

    #[test]
    fn real_and_wide_integer_values_read_as_their_serial_types_lay_them() {
        let cells = vec![leaf_cell(
            1,
            &record_bytes(&[Value::Real(1.5), Value::Text("https://example.com/".into())]),
        )];
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &cells));

        let read = read_table(&fixture.finish(), "logins").unwrap();
        assert_eq!(read.rows[0][0], Value::Real(1.5));

        // A two-byte integer, sign-extended: -300 does not fit one
        // byte, and the record's 0xFED4 must read back negative.
        let mut payload = varint_bytes(2);
        payload.extend(varint_bytes(2));
        payload.extend_from_slice(&0xFED4u16.to_be_bytes());
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &[leaf_cell(1, &payload)]));
        let read = read_table(&fixture.finish(), "logins").unwrap();
        assert_eq!(read.rows[0][0], Value::Integer(-300));
    }

    #[test]
    fn malformed_databases_refuse_naming_the_offender() {
        let cells = vec![leaf_cell(
            1,
            &record_bytes(&[
                Value::Text("https://example.com/".into()),
                Value::Text("alice".into()),
                Value::Blob(b"v10".to_vec()),
            ]),
        )];
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &cells));
        let good = fixture.finish();

        // Not SQLite.
        let mut broken = good.clone();
        broken[0] = b'X';
        assert!(read_table(&broken, "logins")
            .unwrap_err()
            .contains("header magic"));

        // Truncated mid-page.
        assert!(read_table(&good[..700], "logins")
            .unwrap_err()
            .contains("truncated"));

        // A root outside the database's pages.
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(9, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &cells));
        assert!(read_table(&fixture.finish(), "logins")
            .unwrap_err()
            .contains("outside the database's"));

        // The table is absent.
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "other", "CREATE TABLE other (a)")]);
        fixture.set(2, leaf_page(512, &cells));
        assert!(read_table(&fixture.finish(), "logins")
            .unwrap_err()
            .contains("carries no 'logins' table"));

        // An index page where the table's root belongs.
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        let mut index_page = vec![0u8; 512];
        index_page[0] = 10;
        fixture.set(2, index_page);
        assert!(read_table(&fixture.finish(), "logins")
            .unwrap_err()
            .contains("index page"));

        // The tree revisits a page: the root's own child is the root.
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, interior_page(&[2], 2));
        assert!(read_table(&fixture.finish(), "logins")
            .unwrap_err()
            .contains("revisits"));

        // The text encoding is not UTF-8.
        let mut broken = good.clone();
        broken[56..60].copy_from_slice(&2u32.to_be_bytes());
        assert!(read_table(&broken, "logins")
            .unwrap_err()
            .contains("encoding"));

        // The page size is not one the format defines.
        let mut broken = good.clone();
        broken[16..18].copy_from_slice(&3u16.to_be_bytes());
        assert!(read_table(&broken, "logins")
            .unwrap_err()
            .contains("page size 3"));

        // A cell pointer past its own page's end.
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        let mut runaway = leaf_page(512, &cells);
        runaway[8..10].copy_from_slice(&0x7FFFu16.to_be_bytes());
        fixture.set(2, runaway);
        assert!(read_table(&fixture.finish(), "logins")
            .unwrap_err()
            .contains("cell pointer"));
    }

    #[test]
    fn a_reserved_serial_type_and_a_short_chain_refuse() {
        // Serial type 10 is reserved by the format.
        let reserved = {
            let mut payload = varint_bytes(2);
            payload.extend(varint_bytes(10));
            leaf_cell(1, &payload)
        };
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &[reserved]));
        assert!(read_table(&fixture.finish(), "logins")
            .unwrap_err()
            .contains("reserved serial type"));

        // A payload that claims 2000 bytes with an overflow pointer to
        // a page that does not carry them.
        let record = record_bytes(&[Value::Blob(vec![7u8; 2000])]);
        let mut cell = varint_bytes(record.len() as u64);
        cell.extend(varint_bytes(1));
        cell.extend_from_slice(&record[..39]);
        cell.extend_from_slice(&3u32.to_be_bytes());
        let mut fixture = Fixture::with(512, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(512, &[cell]));

        let error = read_table(&fixture.finish(), "logins").unwrap_err();
        assert!(
            error.contains("overflow chain") || error.contains("outside the database's"),
            "{error}"
        );
    }

    #[test]
    fn the_65536_page_size_reads_through_its_one_marker() {
        let cells = vec![leaf_cell(
            1,
            &record_bytes(&[Value::Text("https://example.com/".into())]),
        )];
        let mut fixture = Fixture::with(65536, 2);
        fixture.master(&[schema_cell(2, "logins", CREATE)]);
        fixture.set(2, leaf_page(65536, &cells));

        let read = read_table(&fixture.finish(), "logins").unwrap();
        assert_eq!(read.rows.len(), 1);
    }
}
