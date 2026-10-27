/// PALA signature corpus — binary format.
///
/// Layout:
///   [0..4]   magic    "PALA"
///   [4]      version  0x01
///   [5..9]   count    u32 LE — number of signature records
///   [9..]    records  (see SignatureRecord below)
///
/// Each record:
///   u8          name_len
///   [name_len]  name (UTF-8)
///   u8          ext_len
///   [ext_len]   extension (UTF-8, no dot)
///   u8          magic_len
///   [magic_len] magic bytes (header pattern)
///   u8          flags
///                 0x01  has_end_magic
///                 0x02  end_magic_last   (rfind — for types with nested instances)
///                 0x04  has_end_magic_trail (include trailing \r\n after end marker)
///                 0x08  special_riff
///                 0x10  special_zip
///                 0x20  special_mp4
///   if has_end_magic:
///     u8          end_magic_len
///     [end_magic_len] end_magic bytes
///   if has_end_magic_trail:
///     u8          trail_max  (max bytes of \r/\n to include)
///   u8          magic_offset  (bytes before magic in file; 4 for MP4 ftyp, else 0)
///   u64 LE      max_size
///   u32 LE      min_size
///   u8          desc_len
///   [desc_len]  description (UTF-8)
use anyhow::{anyhow, Result};

pub const MAGIC: &[u8; 4] = b"PALA";
pub const VERSION: u8 = 0x01;

pub const FLAG_HAS_END_MAGIC: u8 = 0x01;
pub const FLAG_END_MAGIC_LAST: u8 = 0x02;
pub const FLAG_END_MAGIC_TRAIL: u8 = 0x04;
pub const FLAG_SPECIAL_RIFF: u8 = 0x08;
pub const FLAG_SPECIAL_ZIP: u8 = 0x10;
pub const FLAG_SPECIAL_MP4: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct Signature {
    pub name: String,
    pub extension: String,
    pub magic: Vec<u8>,
    pub magic_offset: u8,
    pub end_magic: Option<Vec<u8>>,
    pub end_magic_last: bool,
    pub end_magic_trail: u8,
    pub special_riff: bool,
    pub special_zip: bool,
    pub special_mp4: bool,
    pub max_size: u64,
    pub min_size: u32,
    pub description: String,
}

fn validate_signature(sig: &Signature) -> Result<()> {
    if sig.name.is_empty() {
        return Err(anyhow!("signature name must not be empty"));
    }
    if sig.extension.is_empty()
        || sig.extension.len() > 16
        || !sig
            .extension
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(anyhow!(
            "invalid extension {:?}: use 1-16 ASCII letters, digits, '-' or '_'",
            sig.extension
        ));
    }
    if sig.magic.is_empty() {
        return Err(anyhow!("signature {} has empty magic", sig.name));
    }
    if sig.end_magic.as_ref().is_some_and(Vec::is_empty) {
        return Err(anyhow!("signature {} has empty end magic", sig.name));
    }
    if sig.end_magic.is_none() && (sig.end_magic_last || sig.end_magic_trail > 0) {
        return Err(anyhow!(
            "signature {} has end-marker options without end magic",
            sig.name
        ));
    }
    if [sig.special_riff, sig.special_zip, sig.special_mp4]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
        > 1
    {
        return Err(anyhow!(
            "signature {} has multiple special handlers",
            sig.name
        ));
    }
    if sig.max_size == 0 || sig.max_size > usize::MAX as u64 {
        return Err(anyhow!("signature {} has invalid max_size", sig.name));
    }
    if u64::from(sig.min_size) > sig.max_size {
        return Err(anyhow!(
            "signature {} has min_size greater than max_size",
            sig.name
        ));
    }
    Ok(())
}

pub fn load_corpus(bytes: &[u8]) -> Result<Vec<Signature>> {
    const HEADER_LEN: usize = 9;
    const MIN_RECORD_LEN: usize = 18;

    if bytes.len() < HEADER_LEN {
        return Err(anyhow!("corpus too short"));
    }
    if &bytes[0..4] != MAGIC {
        return Err(anyhow!("bad magic: expected PALA, got {:?}", &bytes[0..4]));
    }
    if bytes[4] != VERSION {
        return Err(anyhow!("unsupported version 0x{:02x}", bytes[4]));
    }
    let count = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    if count > (bytes.len() - HEADER_LEN) / MIN_RECORD_LEN {
        return Err(anyhow!("corpus record count exceeds input length"));
    }

    let mut sigs = Vec::with_capacity(count);
    let mut pos = HEADER_LEN;

    macro_rules! read_bytes {
        ($n:expr, $label:literal) => {{
            let end = pos
                .checked_add($n)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| anyhow!("truncated reading {}", $label))?;
            let slice = &bytes[pos..end];
            pos = end;
            slice
        }};
    }

    macro_rules! read_u8 {
        ($label:literal) => {{
            if pos >= bytes.len() {
                return Err(anyhow!("truncated reading {}", $label));
            }
            let v = bytes[pos];
            pos += 1;
            v
        }};
    }

    for record in 0..count {
        let name_len = read_u8!("name_len") as usize;
        let name = std::str::from_utf8(read_bytes!(name_len, "name"))?.to_string();

        let ext_len = read_u8!("ext_len") as usize;
        let extension = std::str::from_utf8(read_bytes!(ext_len, "extension"))?.to_string();

        let magic_len = read_u8!("magic_len") as usize;
        let magic = read_bytes!(magic_len, "magic").to_vec();

        let flags = read_u8!("flags");
        if flags & !0x3f != 0 {
            return Err(anyhow!("record {record} has unknown flags"));
        }
        let has_end_magic = flags & FLAG_HAS_END_MAGIC != 0;
        let end_magic_last = flags & FLAG_END_MAGIC_LAST != 0;
        let has_trail = flags & FLAG_END_MAGIC_TRAIL != 0;
        let special_riff = flags & FLAG_SPECIAL_RIFF != 0;
        let special_zip = flags & FLAG_SPECIAL_ZIP != 0;
        let special_mp4 = flags & FLAG_SPECIAL_MP4 != 0;

        let end_magic = if has_end_magic {
            let em_len = read_u8!("end_magic_len") as usize;
            Some(read_bytes!(em_len, "end_magic").to_vec())
        } else {
            None
        };

        let end_magic_trail = if has_trail { read_u8!("trail_max") } else { 0 };
        let magic_offset = read_u8!("magic_offset");
        let max_size = u64::from_le_bytes(read_bytes!(8, "max_size").try_into()?);
        let min_size = u32::from_le_bytes(read_bytes!(4, "min_size").try_into()?);
        let desc_len = read_u8!("desc_len") as usize;
        let description = std::str::from_utf8(read_bytes!(desc_len, "description"))?.to_string();

        let sig = Signature {
            name,
            extension,
            magic,
            magic_offset,
            end_magic,
            end_magic_last,
            end_magic_trail,
            special_riff,
            special_zip,
            special_mp4,
            max_size,
            min_size,
            description,
        };
        validate_signature(&sig).map_err(|e| anyhow!("record {record}: {e}"))?;
        sigs.push(sig);
    }

    if pos != bytes.len() {
        return Err(anyhow!("corpus has {} trailing bytes", bytes.len() - pos));
    }
    Ok(sigs)
}

/// Serialize signatures into the PALA corpus binary format.
pub fn serialize_corpus(sigs: &[Signature]) -> Result<Vec<u8>> {
    let count = u32::try_from(sigs.len()).map_err(|_| anyhow!("too many corpus records"))?;
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(&count.to_le_bytes());

    for (index, s) in sigs.iter().enumerate() {
        validate_signature(s).map_err(|e| anyhow!("record {index}: {e}"))?;
        let name_len = u8::try_from(s.name.len()).map_err(|_| anyhow!("name too long"))?;
        let ext_len = u8::try_from(s.extension.len()).map_err(|_| anyhow!("extension too long"))?;
        let magic_len = u8::try_from(s.magic.len()).map_err(|_| anyhow!("magic too long"))?;
        let desc_len =
            u8::try_from(s.description.len()).map_err(|_| anyhow!("description too long"))?;

        buf.push(name_len);
        buf.extend_from_slice(s.name.as_bytes());
        buf.push(ext_len);
        buf.extend_from_slice(s.extension.as_bytes());
        buf.push(magic_len);
        buf.extend_from_slice(&s.magic);

        let mut flags: u8 = 0;
        if s.end_magic.is_some() {
            flags |= FLAG_HAS_END_MAGIC;
        }
        if s.end_magic_last {
            flags |= FLAG_END_MAGIC_LAST;
        }
        if s.end_magic_trail > 0 {
            flags |= FLAG_END_MAGIC_TRAIL;
        }
        if s.special_riff {
            flags |= FLAG_SPECIAL_RIFF;
        }
        if s.special_zip {
            flags |= FLAG_SPECIAL_ZIP;
        }
        if s.special_mp4 {
            flags |= FLAG_SPECIAL_MP4;
        }
        buf.push(flags);

        if let Some(em) = &s.end_magic {
            let em_len = u8::try_from(em.len()).map_err(|_| anyhow!("end magic too long"))?;
            buf.push(em_len);
            buf.extend_from_slice(em);
        }
        if s.end_magic_trail > 0 {
            buf.push(s.end_magic_trail);
        }

        buf.push(s.magic_offset);
        buf.extend_from_slice(&s.max_size.to_le_bytes());
        buf.extend_from_slice(&s.min_size.to_le_bytes());
        buf.push(desc_len);
        buf.extend_from_slice(s.description.as_bytes());
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Signature {
        Signature {
            name: "save".to_string(),
            extension: "sav".to_string(),
            magic: b"SAVE\x01".to_vec(),
            magic_offset: 0,
            end_magic: Some(b"END".to_vec()),
            end_magic_last: false,
            end_magic_trail: 1,
            special_riff: false,
            special_zip: false,
            special_mp4: false,
            max_size: 1024,
            min_size: 16,
            description: "Game save".to_string(),
        }
    }

    #[test]
    fn roundtrip() {
        let encoded = serialize_corpus(&[sample()]).unwrap();
        let decoded = load_corpus(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, "save");
        assert_eq!(decoded[0].end_magic_trail, 1);
    }

    #[test]
    fn rejects_implausible_record_count() {
        let mut encoded = MAGIC.to_vec();
        encoded.push(VERSION);
        encoded.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(load_corpus(&encoded).is_err());
    }

    #[test]
    fn rejects_path_in_extension() {
        let mut sig = sample();
        sig.extension = "../escape".to_string();
        assert!(serialize_corpus(&[sig]).is_err());
    }

    #[test]
    fn serialization_rejects_truncated_lengths() {
        let mut sig = sample();
        sig.description = "x".repeat(256);
        assert!(serialize_corpus(&[sig]).is_err());
    }
}
