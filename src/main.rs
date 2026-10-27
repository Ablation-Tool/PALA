#![allow(dead_code)]

mod corpus;

use anyhow::{Context, Result};
use memchr::memmem;
use memmap2::MmapOptions;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const MB: usize = 1024 * 1024;
const GB: usize = 1024 * MB;
const DEFAULT_MIN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Special {
    None,
    Riff,
    Zip,
    Mp4,
    Tiff,
    Sqlite,
    Jpeg,
    Gz,
    Aac,
    Bmp,
    Regf,
    Dex,
    Pf,
    Thumbcache,
    NtfsMft,
    Fat32Fsinfo,
    Ext2Sb,
    UfsSb,
    LiME,
    Elf,
    Pe,
    PageDump,
    Png,
    Mkv,
    Sevenz,
    Ole2,
    Mp3,
    Flac,
    Rar,
    Pcap,
    Pcapng,
    Der,
    Apfs,
    Iso9660,
    Luks,
    SquashfsLe,
    SquashfsBe,
    Uboot,
    Fit,
    Cramfs,
    Tar,
    Ogg,
    Bz2,
    Zstd,
    Rar5,
    UsnRec,
    Ese,
}

// Static signature table — zero-cost, embedded in binary.
struct Sig {
    name: &'static str,
    ext: &'static str,
    magic: &'static [u8],
    moff: usize,
    em: Option<&'static [u8]>,
    em_last: bool,
    em_trail: usize,
    special: Special,
    max: usize,
    min: usize,
    desc: &'static str,
}

static SIGS: &[Sig] = &[
    // ── Images ───────────────────────────────────────────────────────────────
    Sig {
        name: "jpeg",
        ext: "jpg",
        magic: b"\xFF\xD8\xFF",
        moff: 0,
        em: Some(b"\xFF\xD9"),
        em_last: true,
        em_trail: 0,
        special: Special::Jpeg,
        max: 50 * MB,
        min: 512,
        desc: "JPEG Image",
    },
    Sig {
        name: "png",
        ext: "png",
        magic: b"\x89PNG\r\n\x1a\n",
        moff: 0,
        em: Some(b"IEND\xaeB`\x82"),
        em_last: false,
        em_trail: 0,
        special: Special::Png,
        max: 100 * MB,
        min: 29,
        desc: "PNG Image",
    },
    Sig {
        name: "gif87a",
        ext: "gif",
        magic: b"GIF87a",
        moff: 0,
        em: Some(b"\x00;"),
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 20 * MB,
        min: 0,
        desc: "GIF Image (87a)",
    },
    Sig {
        name: "gif89a",
        ext: "gif",
        magic: b"GIF89a",
        moff: 0,
        em: Some(b"\x00;"),
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 20 * MB,
        min: 0,
        desc: "GIF Image (89a)",
    },
    Sig {
        name: "bmp",
        ext: "bmp",
        magic: b"BM",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Bmp,
        max: 100 * MB,
        min: 54,
        desc: "BMP Image",
    },
    Sig {
        name: "tiff_le",
        ext: "tif",
        magic: b"II*\x00",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Tiff,
        max: 500 * MB,
        min: 0,
        desc: "TIFF Image (LE)",
    },
    Sig {
        name: "tiff_be",
        ext: "tif",
        magic: b"MM\x00*",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Tiff,
        max: 500 * MB,
        min: 0,
        desc: "TIFF Image (BE)",
    },
    Sig {
        name: "psd",
        ext: "psd",
        magic: b"8BPS",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 2 * GB,
        min: 0,
        desc: "Photoshop Document",
    },
    // ── Audio / Video ─────────────────────────────────────────────────────────
    Sig {
        name: "riff",
        ext: "riff",
        magic: b"RIFF",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Riff,
        max: 4 * GB,
        min: 0,
        desc: "RIFF Container (WAV/AVI/WEBP)",
    },
    Sig {
        name: "mkv",
        ext: "mkv",
        magic: b"\x1a\x45\xdf\xa3",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Mkv,
        max: 8 * GB,
        min: 0,
        desc: "MKV/WebM Video",
    },
    Sig {
        name: "mp4",
        ext: "mp4",
        magic: b"ftyp",
        moff: 4,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Mp4,
        max: 8 * GB,
        min: 0,
        desc: "MP4/MOV Video",
    },
    Sig {
        name: "mp3_id3",
        ext: "mp3",
        magic: b"ID3",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Mp3,
        max: 300 * MB,
        min: 0,
        desc: "MP3 Audio (ID3)",
    },
    Sig {
        name: "flac",
        ext: "flac",
        magic: b"fLaC",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Flac,
        max: 500 * MB,
        min: 0,
        desc: "FLAC Audio",
    },
    Sig {
        name: "aac",
        ext: "aac",
        magic: b"\xFF\xF1",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Aac,
        max: 200 * MB,
        min: 0,
        desc: "AAC Audio (ADTS)",
    },
    // ── Documents ─────────────────────────────────────────────────────────────
    Sig {
        name: "pdf",
        ext: "pdf",
        magic: b"%PDF-",
        moff: 0,
        em: Some(b"%%EOF"),
        em_last: true,
        em_trail: 2,
        special: Special::None,
        max: 500 * MB,
        min: 0,
        desc: "PDF Document",
    },
    Sig {
        name: "rtf",
        ext: "rtf",
        magic: b"{\\rtf",
        moff: 0,
        em: Some(b"}"),
        em_last: true,
        em_trail: 0,
        special: Special::None,
        max: 100 * MB,
        min: 0,
        desc: "RTF Document",
    },
    // ── Archives / containers ─────────────────────────────────────────────────
    Sig {
        name: "zip",
        ext: "zip",
        magic: b"PK\x03\x04",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Zip,
        max: 500 * MB,
        min: 0,
        desc: "ZIP / Office Open XML",
    },
    Sig {
        name: "ole2",
        ext: "doc",
        magic: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Ole2,
        max: 500 * MB,
        min: 0,
        desc: "OLE2 Document",
    },
    Sig {
        name: "gz",
        ext: "gz",
        magic: b"\x1f\x8b",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Gz,
        max: 2 * GB,
        min: 0,
        desc: "Gzip Archive",
    },
    Sig {
        name: "7z",
        ext: "7z",
        magic: b"7z\xBC\xAF'\x1C",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Sevenz,
        max: 4 * GB,
        min: 0,
        desc: "7-Zip Archive",
    },
    Sig {
        name: "rar",
        ext: "rar",
        magic: b"Rar!\x1a\x07",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Rar,
        max: 4 * GB,
        min: 0,
        desc: "RAR Archive",
    },
    // ── Databases ─────────────────────────────────────────────────────────────
    Sig {
        name: "sqlite",
        ext: "db",
        magic: b"SQLite format 3\x00",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Sqlite,
        max: 2 * GB,
        min: 0,
        desc: "SQLite Database",
    },
    Sig {
        name: "sqlite_wal",
        ext: "db-wal",
        magic: b"\x37\x7F\x06\x82",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 2 * GB,
        min: 32,
        desc: "SQLite Write-Ahead Log",
    },
    // ── Email ─────────────────────────────────────────────────────────────────
    Sig {
        name: "eml",
        ext: "eml",
        magic: b"From:",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 50 * MB,
        min: 64,
        desc: "Email (EML)",
    },
    // ── Windows artifacts (from forensics book synthesis) ────────────────────
    Sig {
        name: "evtx",
        ext: "evtx",
        magic: b"ElfFile\x00",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 200 * MB,
        min: 128,
        desc: "Windows Event Log",
    },
    Sig {
        name: "regf",
        ext: "dat",
        magic: b"regf",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Regf,
        max: 512 * MB,
        min: 4096,
        desc: "Windows Registry Hive",
    },
    Sig {
        name: "lnk",
        ext: "lnk",
        magic: b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 50 * MB,
        min: 76,
        desc: "Windows Shell Link",
    },
    Sig {
        name: "pf",
        ext: "pf",
        magic: b"SCCA",
        moff: 4,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Pf,
        max: 10 * MB,
        min: 76,
        desc: "Windows Prefetch",
    },
    Sig {
        name: "thumbcache",
        ext: "db",
        magic: b"CMMM",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Thumbcache,
        max: 100 * MB,
        min: 24,
        desc: "Windows Thumbcache",
    },
    Sig {
        name: "hibr",
        ext: "bin",
        magic: b"hibr",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 8 * GB,
        min: 4096,
        desc: "Windows Hibernate File",
    },
    Sig {
        name: "pagedump",
        ext: "dmp",
        magic: b"PAGEDUMP",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::PageDump,
        max: 64 * GB,
        min: 4096,
        desc: "Windows Memory Dump 32-bit (BSOD)",
    },
    // ── Mobile / cross-platform ───────────────────────────────────────────────
    Sig {
        name: "bplist",
        ext: "plist",
        magic: b"bplist00",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 64 * MB,
        min: 8,
        desc: "Apple Binary Property List",
    },
    Sig {
        name: "dex",
        ext: "dex",
        magic: b"dex\n",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Dex,
        max: 100 * MB,
        min: 112,
        desc: "Android Dalvik Executable",
    },
    // ── Filesystem structures (from FSFA book synthesis) ─────────────────────
    Sig {
        name: "ntfs_mft",
        ext: "mft",
        magic: b"FILE",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::NtfsMft,
        max: 1024,
        min: 1024,
        desc: "NTFS MFT Entry",
    },
    Sig {
        name: "fat32_fsinfo",
        ext: "fsinfo",
        magic: b"RRaA",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Fat32Fsinfo,
        max: 512,
        min: 512,
        desc: "FAT32 FSINFO Sector",
    },
    Sig {
        name: "ext2_sb",
        ext: "sb",
        magic: b"\x53\xEF",
        moff: 56,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Ext2Sb,
        max: 1024,
        min: 84,
        desc: "Ext2/3/4 Superblock",
    },
    Sig {
        name: "ufs1_sb",
        ext: "ufs",
        magic: b"\x54\x19\x01\x00",
        moff: 1372,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::UfsSb,
        max: 2048,
        min: 1400,
        desc: "UFS1 Superblock",
    },
    Sig {
        name: "ufs2_sb",
        ext: "ufs",
        magic: b"\x19\x01\x54\x19",
        moff: 1372,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::UfsSb,
        max: 2048,
        min: 1400,
        desc: "UFS2 Superblock",
    },
    // ── Encrypted volumes ────────────────────────────────────────────────────
    Sig {
        name: "luks",
        ext: "luks",
        magic: b"LUKS\xBA\xBE",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Luks,
        max: 4096,
        min: 592,
        desc: "LUKS Encrypted Volume Header",
    },
    Sig {
        name: "bitlocker",
        ext: "bde",
        magic: b"-FVE-FS-",
        moff: 3,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 512,
        min: 512,
        desc: "BitLocker Encrypted Volume",
    },
    // ── Memory forensics (from AMF book synthesis) ───────────────────────────
    Sig {
        name: "hibr_upper",
        ext: "bin",
        magic: b"HIBR",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 8 * GB,
        min: 4096,
        desc: "Windows Hibernate File (HIBR variant)",
    },
    Sig {
        name: "wake_lower",
        ext: "bin",
        magic: b"wake",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 8 * GB,
        min: 4096,
        desc: "Windows Hibernate File (wake/resume)",
    },
    Sig {
        name: "wake_upper",
        ext: "bin",
        magic: b"WAKE",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 8 * GB,
        min: 4096,
        desc: "Windows Hibernate File (WAKE/resume)",
    },
    Sig {
        name: "pagedu64",
        ext: "dmp",
        magic: b"PAGEDU64",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::PageDump,
        max: 64 * GB,
        min: 4096,
        desc: "Windows Memory Dump 64-bit (BSOD)",
    },
    Sig {
        name: "lime",
        ext: "lime",
        magic: b"\x45\x4d\x69\x4c",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::LiME,
        max: 64 * GB,
        min: 32,
        desc: "Linux Memory Acquisition (LiME)",
    },
    Sig {
        name: "hpak",
        ext: "hpak",
        magic: b"HPAK",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 64 * GB,
        min: 32,
        desc: "HBGary Memory Acquisition (HPAK)",
    },
    // ── Executables ──────────────────────────────────────────────────────────
    Sig {
        name: "elf",
        ext: "elf",
        magic: b"\x7f\x45\x4c\x46",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Elf,
        max: 500 * MB,
        min: 52,
        desc: "ELF Binary",
    },
    Sig {
        name: "pe",
        ext: "exe",
        magic: b"\x4d\x5a",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Pe,
        max: 500 * MB,
        min: 64,
        desc: "PE/MZ Executable",
    },
    // ── Network graphics (from PNG book synthesis) ───────────────────────────
    Sig {
        name: "mng",
        ext: "mng",
        magic: b"\x8a\x4d\x4e\x47\x0d\x0a\x1a\x0a",
        moff: 0,
        em: Some(b"\x00\x00\x00\x00MEND"),
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 50 * MB,
        min: 0,
        desc: "MNG Animation",
    },
    Sig {
        name: "jng",
        ext: "jng",
        magic: b"\x8b\x4a\x4e\x47\x0d\x0a\x1a\x0a",
        moff: 0,
        em: Some(b"IEND\xaeB`\x82"),
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 50 * MB,
        min: 0,
        desc: "JNG Image",
    },
    // ── Network captures ─────────────────────────────────────────────────────
    Sig {
        name: "pcap",
        ext: "pcap",
        magic: b"\xd4\xc3\xb2\xa1",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Pcap,
        max: 4 * GB,
        min: 24,
        desc: "PCAP Capture (LE)",
    },
    Sig {
        name: "pcap_be",
        ext: "pcap",
        magic: b"\xa1\xb2\xc3\xd4",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Pcap,
        max: 4 * GB,
        min: 24,
        desc: "PCAP Capture (BE)",
    },
    Sig {
        name: "pcapng",
        ext: "pcapng",
        magic: b"\x0a\x0d\x0d\x0a",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Pcapng,
        max: 4 * GB,
        min: 28,
        desc: "PCAPng Capture",
    },
    // ── Virtual disk images ───────────────────────────────────────────────────
    Sig {
        name: "vmdk",
        ext: "vmdk",
        magic: b"KDMV",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 2 * GB,
        min: 512,
        desc: "VMware Virtual Disk (sparse)",
    },
    Sig {
        name: "vhdx",
        ext: "vhdx",
        magic: b"vhdxfile",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 2 * GB,
        min: 1024,
        desc: "Hyper-V Virtual Disk (VHDX)",
    },
    // ── Filesystem images ─────────────────────────────────────────────────────
    // APFS container superblock has NXSB magic at offset 32; moff=32 backs us up to byte 0
    Sig {
        name: "apfs",
        ext: "apfs",
        magic: b"NXSB",
        moff: 32,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Apfs,
        max: 2 * GB,
        min: 1024,
        desc: "APFS Container Superblock",
    },
    // ── Optical disc images ───────────────────────────────────────────────────
    // ISO 9660 Primary Volume Descriptor: type 0x01 + "CD001" at sector 16 (byte 32768).
    // moff=32768 backs candidate to byte 0; iso9660_size reads VolumeSpaceSize*LogicalBlockSize.
    Sig {
        name: "iso9660",
        ext: "iso",
        magic: b"\x01CD001",
        moff: 32768,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Iso9660,
        max: 10 * GB,
        min: 36870,
        desc: "ISO 9660 Optical Disc Image",
    },
    // ── Key / certificate material ────────────────────────────────────────────
    Sig {
        name: "openssh_key",
        ext: "key",
        magic: b"-----BEGIN OPENSSH PRIVATE KEY-----",
        moff: 0,
        em: Some(b"-----END OPENSSH PRIVATE KEY-----"),
        em_last: false,
        em_trail: 1,
        special: Special::None,
        max: 8 * MB,
        min: 64,
        desc: "OpenSSH Private Key",
    },
    Sig {
        name: "pem_cert",
        ext: "pem",
        magic: b"-----BEGIN CERTIFICATE-----",
        moff: 0,
        em: Some(b"-----END CERTIFICATE-----"),
        em_last: true,
        em_trail: 1,
        special: Special::None,
        max: 64 * MB,
        min: 64,
        desc: "PEM Certificate (chain)",
    },
    Sig {
        name: "der_cert",
        ext: "der",
        magic: b"\x30\x82",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Der,
        max: 128 * MB,
        min: 4,
        desc: "X.509 DER Certificate",
    },
    // ── Mobile / ART ──────────────────────────────────────────────────────────
    Sig {
        name: "art",
        ext: "art",
        magic: b"art\n",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: GB,
        min: 128,
        desc: "Android ART Image",
    },
    // ── Linux system artifacts ────────────────────────────────────────────────
    // Systemd binary journal: magic "lpkshhrh" (8 bytes, lowercase) at offset 0.
    // No size field carvable without parsing object headers; use max cap.
    Sig {
        name: "systemd_journal",
        ext: "journal",
        magic: b"lpkshhrh",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 256 * MB,
        min: 272,
        desc: "Systemd Binary Journal",
    },
    // ── Firmware images ───────────────────────────────────────────────────────
    // SquashFS: bytes_used at offset 40 (uint64 LE for sqsh, BE for hsqs).
    Sig {
        name: "squashfs_le",
        ext: "sqsh",
        magic: b"sqsh",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::SquashfsLe,
        max: 4 * GB,
        min: 96,
        desc: "SquashFS Filesystem (LE)",
    },
    Sig {
        name: "squashfs_be",
        ext: "sqsh",
        magic: b"hsqs",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::SquashfsBe,
        max: 4 * GB,
        min: 96,
        desc: "SquashFS Filesystem (BE)",
    },
    // SquashFS older big-endian variants (pre-4.0; same layout, LE/BE per magic)
    Sig {
        name: "squashfs_le3",
        ext: "sqsh",
        magic: b"qshs",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::SquashfsLe,
        max: 4 * GB,
        min: 96,
        desc: "SquashFS Filesystem (LE v3)",
    },
    Sig {
        name: "squashfs_be3",
        ext: "sqsh",
        magic: b"shsq",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::SquashfsBe,
        max: 4 * GB,
        min: 96,
        desc: "SquashFS Filesystem (BE v3)",
    },
    // JFFS2: node magic 0x1985 (LE) or 0x8519 (BE) — header is 12 bytes per node.
    Sig {
        name: "jffs2_le",
        ext: "jffs2",
        magic: b"\x85\x19",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 64 * MB,
        min: 12,
        desc: "JFFS2 Filesystem Image (LE)",
    },
    Sig {
        name: "jffs2_be",
        ext: "jffs2",
        magic: b"\x19\x85",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 64 * MB,
        min: 12,
        desc: "JFFS2 Filesystem Image (BE)",
    },
    // UBIFS: superblock node magic 0x06101831 LE.
    Sig {
        name: "ubifs",
        ext: "ubifs",
        magic: b"\x31\x18\x10\x06",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 512 * MB,
        min: 4096,
        desc: "UBIFS Filesystem Image",
    },
    // U-Boot legacy image: data_size at bytes 12-15 (uint32 BE); total = 64 + data_size.
    Sig {
        name: "uboot",
        ext: "uboot",
        magic: b"\x27\x05\x19\x56",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Uboot,
        max: 64 * MB,
        min: 64,
        desc: "U-Boot Legacy Image",
    },
    // U-Boot FIT / Device Tree Blob: totalsize at bytes 4-7 (uint32 BE).
    Sig {
        name: "fit",
        ext: "itb",
        magic: b"\xD0\x0D\xFE\xED",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Fit,
        max: 128 * MB,
        min: 4096,
        desc: "U-Boot FIT / Device Tree Blob",
    },
    // cramfs: filesystem size at bytes 4-7 (uint32 LE/BE).
    Sig {
        name: "cramfs_le",
        ext: "cramfs",
        magic: b"\x45\x3d\xcd\x28",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Cramfs,
        max: 256 * MB,
        min: 76,
        desc: "cramfs Filesystem (LE)",
    },
    Sig {
        name: "cramfs_be",
        ext: "cramfs",
        magic: b"\x28\xcd\x3d\x45",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Cramfs,
        max: 256 * MB,
        min: 76,
        desc: "cramfs Filesystem (BE)",
    },
    // ── Compressed archives (common on Linux, containers, firmware) ───────────
    // GNU tar / POSIX ustar: "ustar" magic at byte 257 inside the first 512-byte header block.
    // moff=257 backs the candidate to byte 0 (the true archive start).
    Sig {
        name: "tar",
        ext: "tar",
        magic: b"ustar",
        moff: 257,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Tar,
        max: 4 * GB,
        min: 512,
        desc: "TAR Archive",
    },
    // XZ stream: 6-byte header magic + "YZ" end-of-stream footer (rfind = last stream in multi-stream file).
    Sig {
        name: "xz",
        ext: "xz",
        magic: b"\xfd7zXZ\x00",
        moff: 0,
        em: Some(b"\x59\x5a"),
        em_last: true,
        em_trail: 0,
        special: Special::None,
        max: 4 * GB,
        min: 12,
        desc: "XZ Compressed Archive",
    },
    // Bzip2: "BZh[1-9]" header; bz2 blocks are bit-packed so no reliable byte-aligned end marker.
    Sig {
        name: "bz2",
        ext: "bz2",
        magic: b"BZh",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Bz2,
        max: 2 * GB,
        min: 10,
        desc: "Bzip2 Compressed Archive",
    },
    // Zstandard: 4-byte magic; FHD reserved bit must be 0 (validated in zstd_ok).
    Sig {
        name: "zstd",
        ext: "zst",
        magic: b"\x28\xb5\x2f\xfd",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Zstd,
        max: 4 * GB,
        min: 8,
        desc: "Zstandard Compressed Data",
    },
    // ── Modern image formats ──────────────────────────────────────────────────
    // HEIC/HEIF: ISOBMFF container (same as MP4) with brand bytes distinguishing it.
    // moff=4 aligns the search to find "ftyp<brand>" starting at box byte 4.
    // mp4_size() works correctly since HEIC is a valid ftyp-rooted ISOBMFF container.
    Sig {
        name: "heic",
        ext: "heic",
        magic: b"ftypheic",
        moff: 4,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Mp4,
        max: 500 * MB,
        min: 0,
        desc: "HEIC Image (High Efficiency)",
    },
    Sig {
        name: "heif",
        ext: "heif",
        magic: b"ftypmif1",
        moff: 4,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Mp4,
        max: 500 * MB,
        min: 0,
        desc: "HEIF Image Container",
    },
    Sig {
        name: "avif",
        ext: "avif",
        magic: b"ftypavif",
        moff: 4,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Mp4,
        max: 500 * MB,
        min: 0,
        desc: "AVIF Image (AV1)",
    },
    // ── OGG container ────────────────────────────────────────────────────────
    // OggS magic; ogg_ok validates beginning-of-stream page flag; ogg_size walks page headers.
    Sig {
        name: "ogg",
        ext: "ogg",
        magic: b"OggS",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Ogg,
        max: 500 * MB,
        min: 27,
        desc: "OGG Media Container",
    },
    // ── RAR 5.x ──────────────────────────────────────────────────────────────
    // RAR5 has a different 8-byte magic from RAR4; rar5_size() walks blocks via VINT headers.
    Sig {
        name: "rar5",
        ext: "rar",
        magic: b"Rar!\x1a\x07\x01\x00",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Rar5,
        max: 4 * GB,
        min: 8,
        desc: "RAR 5.x Archive",
    },
    // ── Windows Mini Dump ─────────────────────────────────────────────────────
    // MDMP: Windows Minidump (from crash reporting, WER, user-mode dumps). Separate from BSOD PAGEDUMP.
    Sig {
        name: "mdmp",
        ext: "dmp",
        magic: b"MDMP",
        moff: 0,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::None,
        max: 512 * MB,
        min: 32,
        desc: "Windows Minidump (WER/User-mode)",
    },
    // ── NTFS USN Change Journal ───────────────────────────────────────────────────
    // $USNJRNL:$J v2 records: RecordLength(u32) + MajorVersion=2(u16) + MinorVersion=0(u16) at moff=4.
    Sig {
        name: "usn_rec",
        ext: "usn",
        magic: b"\x02\x00\x00\x00",
        moff: 4,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::UsnRec,
        max: 64 * MB,
        min: 64,
        desc: "NTFS USN Change Journal Records",
    },
    // ── ESE / JET Blue Database ───────────────────────────────────────────────────
    // ESE magic 0xEFCDAB89 at offset 4; covers ntds.dit, SRUDB.dat, DataStore.edb, Windows.edb.
    Sig {
        name: "ese",
        ext: "edb",
        magic: b"\xef\xcd\xab\x89",
        moff: 4,
        em: None,
        em_last: false,
        em_trail: 0,
        special: Special::Ese,
        max: 2 * GB,
        min: 4096,
        desc: "ESE/JET Blue Database (ntds.dit/SRUDB.dat)",
    },
];

// ─── Runtime signature (static or corpus-loaded) ──────────────────────────────

pub struct DynSig {
    pub name: String,
    pub ext: String,
    pub magic: Vec<u8>,
    pub moff: usize,
    pub em: Option<Vec<u8>>,
    pub em_last: bool,
    pub em_trail: usize,
    pub special: Special,
    pub max: usize,
    pub min: usize,
    pub desc: String,
}

fn make_dyn(s: &Sig) -> DynSig {
    DynSig {
        name: s.name.to_string(),
        ext: s.ext.to_string(),
        magic: s.magic.to_vec(),
        moff: s.moff,
        em: s.em.map(|b| b.to_vec()),
        em_last: s.em_last,
        em_trail: s.em_trail,
        special: s.special,
        max: s.max,
        min: s.min,
        desc: s.desc.to_string(),
    }
}

fn corpus_dyn(s: &corpus::Signature) -> DynSig {
    let special = if s.special_riff {
        Special::Riff
    } else if s.special_zip {
        Special::Zip
    } else if s.special_mp4 {
        Special::Mp4
    } else {
        Special::None
    };
    DynSig {
        name: s.name.clone(),
        ext: s.extension.clone(),
        magic: s.magic.clone(),
        moff: s.magic_offset as usize,
        em: s.end_magic.clone(),
        em_last: s.end_magic_last,
        em_trail: s.end_magic_trail as usize,
        special,
        max: s.max_size as usize,
        min: s.min_size as usize,
        desc: s.description.clone(),
    }
}

// ─── Size/end algorithms ──────────────────────────────────────────────────────

fn jpeg_length(data: &[u8]) -> Option<usize> {
    let mut i = 2usize;
    loop {
        if i + 1 >= data.len() {
            return None;
        }
        if data[i] != 0xFF {
            return None;
        }
        while i < data.len() && data[i] == 0xFF {
            i += 1;
        }
        if i >= data.len() {
            return None;
        }
        let marker = data[i];
        i += 1;
        if marker == 0xD9 {
            return Some(i);
        }
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if i + 2 > data.len() {
            return None;
        }
        let seg_len = ((data[i] as usize) << 8) | data[i + 1] as usize;
        if seg_len < 2 {
            return None;
        }
        if marker == 0xDA {
            i += seg_len;
            loop {
                if i + 1 >= data.len() {
                    return None;
                }
                if data[i] == 0xFF {
                    match data[i + 1] {
                        0x00 => i += 2,
                        0xD0..=0xD7 => i += 2,
                        0xD9 => return Some(i + 2),
                        _ => break,
                    }
                } else {
                    i += 1;
                }
            }
        } else {
            i += seg_len;
        }
    }
}

fn riff_size(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let inner = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    inner.checked_add(8)
}

fn bmp_size(data: &[u8]) -> Option<usize> {
    if data.len() < 6 {
        return None;
    }
    let sz = u32::from_le_bytes(data[2..6].try_into().ok()?) as usize;
    if sz > 0 {
        Some(sz)
    } else {
        None
    }
}

fn sqlite_size(data: &[u8]) -> Option<usize> {
    if data.len() < 100 {
        return None;
    }
    let raw = u16::from_be_bytes([data[16], data[17]]) as usize;
    let ps = if raw == 1 { 65536 } else { raw };
    if !(512..=65536).contains(&ps) || !ps.is_power_of_two() {
        return None;
    }
    let pc = u32::from_be_bytes(data[28..32].try_into().ok()?) as usize;
    ps.checked_mul(pc)
}

fn tiff_size(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let le = data[0..2] == *b"II";
    macro_rules! u16at {
        ($o:expr) => {{
            let o = $o;
            if o + 2 > data.len() {
                return None;
            }
            if le {
                u16::from_le_bytes([data[o], data[o + 1]])
            } else {
                u16::from_be_bytes([data[o], data[o + 1]])
            }
        }};
    }
    macro_rules! u32at {
        ($o:expr) => {{
            let o = $o;
            if o + 4 > data.len() {
                return None;
            }
            if le {
                u32::from_le_bytes(data[o..o + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(data[o..o + 4].try_into().unwrap())
            }
        }};
    }
    macro_rules! u32raw {
        ($b:expr) => {{
            let b: [u8; 4] = $b;
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        }};
    }
    if u16at!(2) != 42 {
        return None;
    }

    const OTAGS: &[u16] = &[273, 324, 519, 520, 521];
    const CTAGS: &[u16] = &[279, 325, 522, 523, 524];
    let tsz = |t: u16| -> usize {
        match t {
            1 | 2 | 6 | 7 => 1,
            3 | 8 => 2,
            4 | 9 | 11 => 4,
            5 | 10 | 12 => 8,
            _ => 1,
        }
    };

    let mut mx: usize = 8;
    let mut vis: HashSet<usize> = HashSet::new();
    let mut ifd = u32at!(4) as usize;

    loop {
        if ifd == 0 || !vis.insert(ifd) || ifd + 2 > data.len() {
            break;
        }
        let n = u16at!(ifd) as usize;
        let mut offs: Vec<usize> = Vec::new();
        let mut cnts: Vec<usize> = Vec::new();

        for i in 0..n {
            let ep = ifd + 2 + i * 12;
            if ep + 12 > data.len() {
                break;
            }
            let tag = u16at!(ep);
            let dtype = u16at!(ep + 2);
            let count = u32at!(ep + 4) as usize;
            let raw: [u8; 4] = data[ep + 8..ep + 12].try_into().unwrap();
            let ts = tsz(dtype);
            let dsz = ts.saturating_mul(count);

            if dsz <= 4 {
                mx = mx.max(ep + 12);
                let v = u32raw!(raw) as usize;
                if OTAGS.contains(&tag) {
                    offs.push(v);
                } else if CTAGS.contains(&tag) {
                    cnts.push(v);
                }
            } else {
                let doff = u32raw!(raw) as usize;
                mx = mx.max(doff.saturating_add(dsz));
                if OTAGS.contains(&tag) || CTAGS.contains(&tag) {
                    let is_off = OTAGS.contains(&tag);
                    let isz = if ts >= 4 { 4usize } else { 2usize };
                    for j in 0..count {
                        let ip = doff + j * ts;
                        if ip + isz > data.len() {
                            break;
                        }
                        let v: usize = if isz == 4 {
                            if le {
                                u32::from_le_bytes(data[ip..ip + 4].try_into().unwrap()) as usize
                            } else {
                                u32::from_be_bytes(data[ip..ip + 4].try_into().unwrap()) as usize
                            }
                        } else {
                            if le {
                                u16::from_le_bytes(data[ip..ip + 2].try_into().unwrap()) as usize
                            } else {
                                u16::from_be_bytes(data[ip..ip + 2].try_into().unwrap()) as usize
                            }
                        };
                        if is_off {
                            offs.push(v);
                        } else {
                            cnts.push(v);
                        }
                    }
                }
            }
        }

        for (o, c) in offs.iter().zip(cnts.iter()) {
            mx = mx.max(o.saturating_add(*c));
        }
        for o in offs.get(cnts.len()..).unwrap_or(&[]) {
            mx = mx.max(*o);
        }

        let np = ifd + 2 + n * 12;
        if np + 4 > data.len() {
            break;
        }
        mx = mx.max(np + 4);
        ifd = u32at!(np) as usize;
    }
    if mx > 8 {
        Some(mx)
    } else {
        None
    }
}

fn zip_eocd_end(data: &[u8]) -> Option<usize> {
    let p = memmem::find(data, b"PK\x05\x06")?;
    if p + 22 > data.len() {
        return Some(p + 4);
    }
    let clen = u16::from_le_bytes([data[p + 20], data[p + 21]]) as usize;
    Some(p + 22 + clen)
}

// hive_bins_size (LE u32 at offset 40) + 4096 base header = total hive size
fn regf_size(data: &[u8]) -> Option<usize> {
    if data.len() < 44 {
        return None;
    }
    let hbs = u32::from_le_bytes(data[40..44].try_into().ok()?) as usize;
    hbs.checked_add(4096)
}

// file_size at offset 12 (LE u32) gives exact prefetch file length
fn pf_size(data: &[u8]) -> Option<usize> {
    if data.len() < 16 {
        return None;
    }
    let sz = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
    if sz >= 76 {
        Some(sz)
    } else {
        None
    }
}

// file_size at offset 32 (LE u32) gives exact DEX file length
fn dex_size(data: &[u8]) -> Option<usize> {
    if data.len() < 36 {
        return None;
    }
    let sz = u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;
    if sz >= 112 {
        Some(sz)
    } else {
        None
    }
}

// e_shoff + e_shnum * e_shentsize = end of section header table = end of ELF file
fn elf_size(data: &[u8]) -> Option<usize> {
    if data.len() < 6 {
        return None;
    }
    let le = data[5] == 1;
    let class = data[4];
    macro_rules! u16r {
        ($o:expr) => {{
            let o = $o;
            if o + 2 > data.len() {
                return None;
            }
            (if le {
                u16::from_le_bytes([data[o], data[o + 1]])
            } else {
                u16::from_be_bytes([data[o], data[o + 1]])
            }) as usize
        }};
    }
    macro_rules! u32r {
        ($o:expr) => {{
            let o = $o;
            if o + 4 > data.len() {
                return None;
            }
            (if le {
                u32::from_le_bytes(data[o..o + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(data[o..o + 4].try_into().unwrap())
            }) as usize
        }};
    }
    macro_rules! u64r {
        ($o:expr) => {{
            let o = $o;
            if o + 8 > data.len() {
                return None;
            }
            (if le {
                u64::from_le_bytes(data[o..o + 8].try_into().unwrap())
            } else {
                u64::from_be_bytes(data[o..o + 8].try_into().unwrap())
            }) as usize
        }};
    }
    let (shoff, shentsize, shnum) = if class == 2 {
        // 64-bit: e_shoff@40(u64), e_shentsize@58(u16), e_shnum@60(u16)
        if data.len() < 64 {
            return None;
        }
        (u64r!(40), u16r!(58), u16r!(60))
    } else {
        // 32-bit: e_shoff@32(u32), e_shentsize@46(u16), e_shnum@48(u16)
        if data.len() < 52 {
            return None;
        }
        (u32r!(32), u16r!(46), u16r!(48))
    };
    if shoff == 0 || shnum == 0 {
        return None;
    }
    shoff.checked_add(shnum.checked_mul(shentsize)?)
}

// PE file size = highest raw extent across all sections + optional security overlay.
// SizeOfImage is the virtual (page-aligned) layout — always larger; don't use it.
fn pe_size(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off + 24 > data.len() {
        return None;
    }
    if &data[pe_off..pe_off + 4] != b"PE\x00\x00" {
        return None;
    }
    // COFF header: pe_off+4; number of sections at pe_off+6 (u16); opt hdr size at pe_off+20 (u16)
    let nsections = u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().ok()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().ok()?) as usize;
    // section table starts after the 24-byte COFF header + optional header
    let sec_table = pe_off + 24 + opt_hdr_size;
    let mut end = 0usize;
    for i in 0..nsections {
        let s = sec_table + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let raw_sz = u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?) as usize;
        let raw_off = u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?) as usize;
        if raw_sz > 0 && raw_off > 0 {
            end = end.max(raw_off + raw_sz);
        }
    }
    // security directory (authenticode overlay) may extend past the last section
    // offset into optional header depends on PE32 (magic=0x10b) vs PE32+ (magic=0x20b)
    if opt_hdr_size >= 4 && pe_off + 24 + 4 <= data.len() {
        let magic = u16::from_le_bytes(data[pe_off + 24..pe_off + 26].try_into().ok()?);
        let cert_dir_off: usize = pe_off
            + 24
            + match magic {
                0x10b => 128, // PE32:  data directories at opt_hdr+96, security dir is [4] = +128
                0x20b => 144, // PE32+: data directories at opt_hdr+112, security dir is [4] = +144
                _ => 0,
            };
        if cert_dir_off > 0 && cert_dir_off + 8 <= data.len() {
            let cert_off =
                u32::from_le_bytes(data[cert_dir_off..cert_dir_off + 4].try_into().ok()?) as usize;
            let cert_sz =
                u32::from_le_bytes(data[cert_dir_off + 4..cert_dir_off + 8].try_into().ok()?)
                    as usize;
            if cert_off > 0 && cert_sz > 0 {
                end = end.max(cert_off + cert_sz);
            }
        }
    }
    if end > 0 {
        Some(end)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MP4/MOV: walk ISOBMFF top-level boxes; accumulate extent.
// Returns Some(file_size) when the last box lands exactly at or inside the window.
// Returns None when any box extends past the window (file larger than chunk).
fn mp4_size(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    loop {
        if pos + 8 > data.len() {
            return Some(pos.min(data.len()));
        }
        let raw = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
        let (box_size, _hdr): (usize, usize) = match raw {
            0 => {
                // size=0 means box extends to file EOF — valid only when the type field
                // contains 4 ASCII alpha bytes.  Null bytes here = trailing disk garbage.
                let typ = &data[pos + 4..pos + 8];
                if typ.iter().all(|&b| b.is_ascii_alphabetic()) {
                    return Some(data.len());
                } else {
                    return Some(pos); // trailing zeros — file ends here
                }
            }
            1 => {
                // extended-size: 8-byte size field follows the 8-byte box header
                if pos + 16 > data.len() {
                    return Some(pos);
                }
                (
                    u64::from_be_bytes(data[pos + 8..pos + 16].try_into().ok()?) as usize,
                    16,
                )
            }
            n => (n as usize, 8),
        };
        if box_size < 8 {
            return None;
        } // malformed
        let next = pos.saturating_add(box_size);
        if next > data.len() {
            return None;
        } // box extends past window
        pos = next;
    }
}

// MKV/WebM: read EBML header size, then Segment element size.
// Many streaming MKV files use unknown segment size (all-ones vint) — return None in that case.
fn mkv_size(data: &[u8]) -> Option<usize> {
    // Parse an EBML variable-length integer starting at `pos`; return (value, byte_count).
    fn ebml_vint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
        if pos >= data.len() {
            return None;
        }
        let first = data[pos];
        let (extra, mask): (usize, u8) = if first & 0x80 != 0 {
            (0, 0x7f)
        } else if first & 0x40 != 0 {
            (1, 0x3f)
        } else if first & 0x20 != 0 {
            (2, 0x1f)
        } else if first & 0x10 != 0 {
            (3, 0x0f)
        } else if first & 0x08 != 0 {
            (4, 0x07)
        } else if first & 0x04 != 0 {
            (5, 0x03)
        } else if first & 0x02 != 0 {
            (6, 0x01)
        } else {
            (7, 0x00)
        };
        let total = 1 + extra;
        if pos + total > data.len() {
            return None;
        }
        let mut val = (first & mask) as u64;
        for i in 1..total {
            val = (val << 8) | data[pos + i] as u64;
        }
        Some((val, total))
    }
    // magic is 4 bytes at offset 0: 1a 45 df a3 (EBML element ID)
    // Read EBML header element size (at offset 4)
    let (hdr_size, hdr_bytes) = ebml_vint(data, 4)?;
    let seg_start = 4usize
        .checked_add(hdr_bytes)?
        .checked_add(hdr_size as usize)?;
    // Segment element ID: 18 53 80 67 (4 bytes)
    if seg_start + 4 > data.len() {
        return None;
    }
    if data[seg_start..seg_start + 4] != [0x18, 0x53, 0x80, 0x67] {
        return None;
    }
    let (seg_size, sz_bytes) = ebml_vint(data, seg_start + 4)?;
    // All-ones in the vint value field means "unknown size" (common in streaming/live-capture MKV)
    let all_ones = (1u64 << (7 * (sz_bytes as u64))) - 1;
    if seg_size == all_ones {
        return None;
    }
    let file_end = seg_start
        .checked_add(4)?
        .checked_add(sz_bytes)?
        .checked_add(seg_size as usize)?;
    if file_end <= data.len() {
        Some(file_end)
    } else {
        None
    }
}

// RAR 4.x: walk block chain from offset 7 (after the 7-byte marker block).
// Stop when block type 0x7B (end-of-archive) is found.
// RAR 5.x uses a different structure and is handled by a separate signature.
fn rar_size(data: &[u8]) -> Option<usize> {
    let mut pos = 7usize; // skip the fixed marker block
    for _ in 0..20_000usize {
        if pos + 7 > data.len() {
            break;
        }
        let head_type = data[pos + 2];
        let head_flags = u16::from_le_bytes([data[pos + 3], data[pos + 4]]);
        let head_size = u16::from_le_bytes([data[pos + 5], data[pos + 6]]) as usize;
        if head_size < 7 {
            break;
        } // malformed — don't advance forever
        let add_size: usize = if head_flags & 0x8000 != 0 {
            if pos + 11 > data.len() {
                break;
            }
            u32::from_le_bytes(data[pos + 7..pos + 11].try_into().ok()?) as usize
        } else {
            0
        };
        if head_type == 0x7B {
            // End-of-archive block — file ends after this block header
            return Some(pos + head_size);
        }
        let block_total = head_size.checked_add(add_size)?;
        pos = pos.checked_add(block_total)?;
        if pos >= data.len() {
            break;
        }
    }
    None
}

// 7-Zip: StartHeader at bytes 12-27 gives exact archive size.
// file_size = 32 + NextHeaderOffset + NextHeaderSize
fn sevenz_size(data: &[u8]) -> Option<usize> {
    if data.len() < 32 {
        return None;
    }
    let next_hdr_off = u64::from_le_bytes(data[12..20].try_into().ok()?) as usize;
    let next_hdr_size = u64::from_le_bytes(data[20..28].try_into().ok()?) as usize;
    32usize
        .checked_add(next_hdr_off)?
        .checked_add(next_hdr_size)
}

// OLE2 Compound Document: estimate file size from FAT sector count.
// Each FAT sector has sector_size/4 entries (each entry = one 4-byte sector number),
// giving an upper bound on total data sectors.  This over-estimates for small files,
// but Office parsers follow the FAT chain and ignore trailing unallocated sectors.
fn ole2_size(data: &[u8]) -> Option<usize> {
    if data.len() < 52 {
        return None;
    }
    let sector_pow2 = u16::from_le_bytes(data[30..32].try_into().ok()?) as u32;
    if !(7..=16).contains(&sector_pow2) {
        return None;
    } // 128B – 64KB sector
    let ss = 1usize << sector_pow2;
    let nfat = u32::from_le_bytes(data[44..48].try_into().ok()?) as usize;
    if nfat == 0 || nfat > 10_000 {
        return None;
    }
    // header (512 bytes) + nfat × (ss/4) sectors × ss bytes per sector
    let total = 512usize.checked_add(nfat.checked_mul(ss / 4)?.checked_mul(ss)?)?;
    Some(total.min(data.len()))
}

// MP3 with ID3v2 tag: read syncsafe tag size, then look for a Xing/Info VBR header
// in the first MPEG frame to get the total audio byte count.
// Falls back to None (full window) when Xing/Info is absent (CBR without Info tag, older encoders).
fn mp3_id3_size(data: &[u8]) -> Option<usize> {
    if data.len() < 10 || &data[0..3] != b"ID3" {
        return None;
    }
    // ID3v2 syncsafe integer: each byte uses only 7 bits
    let b = [data[6], data[7], data[8], data[9]];
    if b.iter().any(|&x| x & 0x80 != 0) {
        return None;
    }
    let id3_size = 10
        + ((b[0] as usize) << 21 | (b[1] as usize) << 14 | (b[2] as usize) << 7 | (b[3] as usize));
    let pos = id3_size;
    if pos + 4 > data.len() {
        return None;
    }
    // MPEG frame sync: first 11 bits set
    if data[pos] != 0xFF || data[pos + 1] & 0xE0 != 0xE0 {
        return None;
    }
    let version = (data[pos + 1] >> 3) & 0x3; // 3=MPEG1, 2=MPEG2, 0=MPEG2.5
    let layer = (data[pos + 1] >> 1) & 0x3; // 3=LayerI, 2=LayerII, 1=LayerIII(mp3)
    if version != 3 || layer != 1 {
        return None;
    } // only handle MPEG1 Layer III
    let ch_mode = (data[pos + 3] >> 6) & 0x3;
    // Xing/Info tag sits at frame_header (4) + side_info (32 stereo / 17 mono)
    let xing_off = pos + 4 + if ch_mode == 3 { 17 } else { 32 };
    if xing_off + 8 > data.len() {
        return None;
    }
    let tag = &data[xing_off..xing_off + 4];
    if tag != b"Xing" && tag != b"Info" {
        return None;
    }
    let flags = u32::from_be_bytes(data[xing_off + 4..xing_off + 8].try_into().ok()?);
    if flags & 0x2 == 0 {
        return None;
    } // total-bytes field not present
      // optional: if flags & 0x1, a 4-byte total-frames count precedes total-bytes
    let tb_off = xing_off + 8 + if flags & 0x1 != 0 { 4 } else { 0 };
    if tb_off + 4 > data.len() {
        return None;
    }
    let total_bytes = u32::from_be_bytes(data[tb_off..tb_off + 4].try_into().ok()?) as usize;
    if total_bytes > id3_size {
        Some(total_bytes)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP: walk packet records (each 16-byte header + incl_len bytes payload).
// Global header at 0 (24 bytes); LE vs BE determined from the byte-order magic.
fn pcap_size(data: &[u8]) -> Option<usize> {
    if data.len() < 24 {
        return None;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let le = matches!(magic, 0xa1b2c3d4 | 0xa1b23c4d); // normal + nanosecond LE
    let be = matches!(magic, 0xd4c3b2a1 | 0x4d3cb2a1); // normal + nanosecond BE
    if !le && !be {
        return None;
    }
    let snaplen = if le {
        u32::from_le_bytes(data[16..20].try_into().ok()?)
    } else {
        u32::from_be_bytes(data[16..20].try_into().ok()?)
    } as usize;
    let mut pos = 24usize;
    for _ in 0..10_000_000usize {
        if pos + 16 > data.len() {
            return Some(pos.min(data.len()));
        }
        let incl = if le {
            u32::from_le_bytes(data[pos + 8..pos + 12].try_into().ok()?)
        } else {
            u32::from_be_bytes(data[pos + 8..pos + 12].try_into().ok()?)
        } as usize;
        // All-zero 16-byte record header = trailing disk zeros, not a real packet
        let orig_len = if le {
            u32::from_le_bytes(data[pos + 12..pos + 16].try_into().ok()?)
        } else {
            u32::from_be_bytes(data[pos + 12..pos + 16].try_into().ok()?)
        } as usize;
        let ts_sec = if le {
            u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?)
        } else {
            u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?)
        };
        let ts_usec = if le {
            u32::from_le_bytes(data[pos + 4..pos + 8].try_into().ok()?)
        } else {
            u32::from_be_bytes(data[pos + 4..pos + 8].try_into().ok()?)
        };
        if ts_sec == 0 && ts_usec == 0 && incl == 0 && orig_len == 0 {
            return Some(pos);
        }
        // incl_len > snaplen (or > 65536 if snaplen==0) = malformed record = end of capture
        let limit = if snaplen > 0 { snaplen } else { 65536 };
        if incl > limit {
            return Some(pos);
        }
        let next = pos.checked_add(16)?.checked_add(incl)?;
        if next > data.len() {
            return Some(pos);
        }
        pos = next;
    }
    None
}

// PCAPng: walk Section Header Blocks and Interface/Packet blocks.
// Each block: block_type(4) + block_total_length(4) + body + block_total_length(4).
fn pcapng_size(data: &[u8]) -> Option<usize> {
    if data.len() < 28 {
        return None;
    }
    if u32::from_le_bytes(data[0..4].try_into().ok()?) != 0x0A0D0D0A {
        return None;
    }
    let first_len = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    if first_len < 28 || first_len > data.len() {
        return None;
    }
    let bom = u32::from_le_bytes(data[8..12].try_into().ok()?);
    let le = bom == 0x1A2B3C4D;
    if bom != 0x1A2B3C4D && bom != 0x4D3C2B1A {
        return None;
    }
    let mut pos = first_len;
    for _ in 0..10_000_000usize {
        if pos + 8 > data.len() {
            return Some(pos.min(data.len()));
        }
        let blen = if le {
            u32::from_le_bytes(data[pos + 4..pos + 8].try_into().ok()?) as usize
        } else {
            u32::from_be_bytes(data[pos + 4..pos + 8].try_into().ok()?) as usize
        };
        if blen < 12 || blen % 4 != 0 {
            return Some(pos);
        }
        let next = pos.checked_add(blen)?;
        if next > data.len() {
            return Some(pos);
        }
        pos = next;
    }
    None
}

// X.509 DER: bytes 0-1 must be 0x30 0x82 (SEQUENCE, 2-byte length).
// Total size = 4 (header) + content length encoded in bytes 2-3.
fn der_size(data: &[u8]) -> Option<usize> {
    if data.len() < 4 || data[0] != 0x30 || data[1] != 0x82 {
        return None;
    }
    let content_len = ((data[2] as usize) << 8) | (data[3] as usize);
    4usize.checked_add(content_len)
}

// APFS container superblock: NXSB at offset 32 of the on-disk block (moff=32).
// data[0] = block start; nx_superblock layout:
//   [0..32]  object header (cksum, oid, xid, type, subtype)
//   [32..36] nx_magic = "NXSB"
//   [36..40] nx_block_size (u32 LE)
//   [40..48] nx_block_count (u64 LE)
fn apfs_size(data: &[u8]) -> Option<usize> {
    if data.len() < 48 {
        return None;
    }
    let bs = u32::from_le_bytes(data[36..40].try_into().ok()?) as usize;
    let bc = u64::from_le_bytes(data[40..48].try_into().ok()?) as usize;
    if !(512..=65536).contains(&bs) {
        return None;
    }
    bs.checked_mul(bc)
}

// ISO 9660: data[0] = byte 0 of ISO; PVD at data[32768..].
// VolumeSpaceSize (LE u32, logical blocks) at PVD+80; LogicalBlockSize (LE u16) at PVD+128.
fn iso9660_size(data: &[u8]) -> Option<usize> {
    const PVD: usize = 32768;
    if data.len() < PVD + 166 {
        return None;
    }
    let space = u32::from_le_bytes(data[PVD + 80..PVD + 84].try_into().ok()?) as usize;
    let blksz = u16::from_le_bytes(data[PVD + 128..PVD + 130].try_into().ok()?) as usize;
    if space == 0 || blksz == 0 || !blksz.is_power_of_two() || blksz > 32768 {
        return None;
    }
    space.checked_mul(blksz)
}

// Walk FLAC METADATA_BLOCK chain; use STREAMINFO total_samples to bound audio size.
// FLAC compressed audio is always <= uncompressed PCM — use that as the upper bound.
fn flac_size(data: &[u8]) -> Option<usize> {
    if data.len() < 8 || &data[..4] != b"fLaC" {
        return None;
    }
    let mut off = 4usize;
    let mut total_samples = 0u64;
    let mut channels: u8 = 0;
    let mut bits_per_sample = 0u8;

    loop {
        if off + 4 > data.len() {
            return None;
        }
        let hdr = data[off];
        let last = hdr & 0x80 != 0;
        let block_type = hdr & 0x7F;
        let block_len = ((data[off + 1] as usize) << 16)
            | ((data[off + 2] as usize) << 8)
            | (data[off + 3] as usize);
        if block_len > 16 * MB {
            return None;
        }

        if block_type == 0 && off + 4 + 18 <= data.len() {
            // STREAMINFO bit-field layout (big-endian bitstream):
            //   [0:15]   min blocksize
            //   [16:31]  max blocksize
            //   [32:55]  min framesize (24 bits)
            //   [56:79]  max framesize (24 bits)
            //   [80:99]  sample_rate (20 bits)
            //   [100:102] channels - 1 (3 bits)
            //   [103:107] bits_per_sample - 1 (5 bits)
            //   [108:143] total_samples (36 bits)
            let si = &data[off + 4..];
            channels = ((si[12] & 0x0E) >> 1) + 1;
            bits_per_sample = (((si[12] & 0x01) << 4) | ((si[13] >> 4) & 0x0F)) + 1;
            total_samples = ((si[13] & 0x0F) as u64) << 32
                | ((si[14] as u64) << 24)
                | ((si[15] as u64) << 16)
                | ((si[16] as u64) << 8)
                | (si[17] as u64);
        }

        off = match off.checked_add(4 + block_len) {
            Some(n) if n <= data.len() => n,
            _ => return None,
        };
        if last {
            break;
        }
    }

    // off = first audio frame byte; estimate total file size
    if total_samples == 0 || channels == 0 || bits_per_sample == 0 {
        return None;
    }
    let bytes_per_sample = (bits_per_sample as u64).div_ceil(8);
    let uncompressed = total_samples
        .saturating_mul(channels as u64)
        .saturating_mul(bytes_per_sample);
    let total = (off as u64).saturating_add(uncompressed);
    if total < data.len() as u64 {
        Some(total as usize)
    } else {
        None // estimate >= window size; let max cap stand
    }
}

// SquashFS v4 header: bytes_used at offset 40 (uint64).
fn squashfs_size_le(data: &[u8]) -> Option<usize> {
    if data.len() < 48 {
        return None;
    }
    let sz = u64::from_le_bytes(data[40..48].try_into().ok()?) as usize;
    if !(96..=4 * GB).contains(&sz) {
        return None;
    }
    Some(sz)
}
fn squashfs_size_be(data: &[u8]) -> Option<usize> {
    if data.len() < 48 {
        return None;
    }
    let sz = u64::from_be_bytes(data[40..48].try_into().ok()?) as usize;
    if !(96..=4 * GB).contains(&sz) {
        return None;
    }
    Some(sz)
}

// U-Boot legacy image: 64-byte header; data_size at bytes 12-15 (uint32 BE).
fn uboot_size(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }
    let data_sz = u32::from_be_bytes(data[12..16].try_into().ok()?) as usize;
    if data_sz == 0 {
        return None;
    }
    64usize.checked_add(data_sz)
}

// FDT/FIT blob: totalsize at bytes 4-7 (uint32 BE).
fn fit_size(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let sz = u32::from_be_bytes(data[4..8].try_into().ok()?) as usize;
    if sz < 8 {
        return None;
    }
    Some(sz)
}

// LiME memory dump: scan segment headers (32 bytes each: magic+version+start+end+reserved).
// Segments are written sequentially: header then data. Sum to find total extent.
fn lime_size(data: &[u8]) -> Option<usize> {
    const HDR: usize = 32;
    const MAGIC: &[u8] = b"\x45\x4d\x69\x4c";
    if data.len() < HDR || &data[..4] != MAGIC {
        return None;
    }
    let mut off = 0usize;
    loop {
        if off + HDR > data.len() {
            break;
        }
        if &data[off..off + 4] != MAGIC {
            break;
        }
        let start = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?) as usize;
        let end = u64::from_le_bytes(data[off + 16..off + 24].try_into().ok()?) as usize;
        if end < start {
            break;
        }
        off += HDR + (end - start + 1);
    }
    if off == 0 {
        return None;
    }
    Some(off.min(data.len()))
}

// cramfs: size at bytes 4-7 (same field for both LE and BE variants of cramfs).
fn cramfs_size(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let sz_le = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    if (76..=256 * MB).contains(&sz_le) {
        return Some(sz_le);
    }
    let sz_be = u32::from_be_bytes(data[4..8].try_into().ok()?) as usize;
    if (76..=256 * MB).contains(&sz_be) {
        return Some(sz_be);
    }
    None
}

// ─── New size parsers ─────────────────────────────────────────────────────────

// TAR: walk 512-byte blocks. Each entry = 512-byte header + ceil(size/512)*512 data blocks.
// EOF = two consecutive all-zero 512-byte blocks.
// Handles POSIX ustar, GNU tar, and base-256 encoded sizes (files > 8GB in GNU extensions).
fn tar_size(data: &[u8]) -> Option<usize> {
    const BLOCK: usize = 512;
    let mut pos = 0usize;
    let mut zero_blocks = 0usize;
    for _ in 0..1_000_000usize {
        if pos + BLOCK > data.len() {
            return Some(pos.min(data.len()));
        }
        let header = &data[pos..pos + BLOCK];
        if header.iter().all(|&b| b == 0) {
            zero_blocks += 1;
            pos += BLOCK;
            if zero_blocks >= 2 {
                return Some(pos);
            }
            continue;
        }
        zero_blocks = 0;
        let size_bytes = &header[124..136];
        let file_size: usize = if size_bytes[0] & 0x80 != 0 {
            // Base-256 (GNU extension for files > 8GB)
            let mut v = 0u64;
            for byte in size_bytes.iter().take(12).skip(1) {
                v = (v << 8) | (*byte as u64);
            }
            v as usize
        } else {
            // Octal ASCII (null or space terminated)
            let end = size_bytes
                .iter()
                .position(|&b| b == 0 || b == b' ')
                .unwrap_or(12);
            usize::from_str_radix(std::str::from_utf8(&size_bytes[..end]).unwrap_or("0"), 8)
                .unwrap_or(0)
        };
        let data_blocks = file_size.div_ceil(BLOCK);
        pos = pos
            .checked_add(BLOCK)?
            .checked_add(data_blocks.checked_mul(BLOCK)?)?;
        if pos > data.len() {
            return None;
        }
    }
    None
}

// OGG: walk page headers. Page = 27-byte header + n_segs-byte segment table + data.
// EOS page (header_type & 0x04) marks the physical end of the stream.
fn ogg_size(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    for _ in 0..10_000_000usize {
        if pos + 27 > data.len() {
            return Some(pos.min(data.len()));
        }
        if &data[pos..pos + 4] != b"OggS" {
            return Some(pos);
        }
        if data[pos + 4] != 0 {
            return Some(pos);
        }
        let header_type = data[pos + 5];
        let n_segs = data[pos + 26] as usize;
        if pos + 27 + n_segs > data.len() {
            return Some(pos);
        }
        let data_len: usize = data[pos + 27..pos + 27 + n_segs]
            .iter()
            .map(|&b| b as usize)
            .sum();
        let page_size = 27 + n_segs + data_len;
        let next = pos.checked_add(page_size)?;
        if next > data.len() {
            return Some(pos);
        }
        pos = next;
        if header_type & 0x04 != 0 {
            return Some(pos);
        } // EOS
    }
    None
}

// Bz2: blocks are bit-packed so there's no reliable byte-aligned end marker.
// We validate the header and use the static cap; bz2_ok weeds out false hits on "BZh".
fn bz2_ok(d: &[u8]) -> bool {
    d.len() >= 4 && d[0] == b'B' && d[1] == b'Z' && d[2] == b'h' && d[3] >= b'1' && d[3] <= b'9'
}

// Zstandard: magic is specific; validate reserved bit (bit 4 of FHD byte) is 0.
fn zstd_ok(d: &[u8]) -> bool {
    if d.len() < 6 {
        return false;
    }
    let fhd = d[4];
    fhd & 0x08 == 0 // reserved bit must be 0
}

// Walk a zstd frame to its exact byte length.
// Frame: 4-byte magic + FHD(1) + optional Window_Descriptor(1) + optional Dict_ID(0/1/2/4)
// + optional Content_Size(0/1/2/8) + blocks(3+N each) + optional Checksum(4).
fn zstd_size(d: &[u8]) -> Option<usize> {
    if d.len() < 6 {
        return None;
    }
    let fhd = d[4];
    let fcs_flag = (fhd >> 6) & 0x03;
    let ssf = (fhd >> 5) & 0x01;
    let chk_flag = (fhd >> 3) & 0x01;
    let did_flag = (fhd >> 1) & 0x03;
    if fhd & 0x08 != 0 {
        return None;
    } // reserved bit set

    let mut pos = 5usize;
    if ssf == 0 {
        pos += 1;
    } // Window_Descriptor
    pos += match did_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => return None,
    };
    // Content_Size size: FCS_Flag=0+SSF=1 -> 1 byte; FCS_Flag=1 -> 2 bytes; 2 -> 4 bytes; 3 -> 8 bytes.
    pos += if ssf == 1 && fcs_flag == 0 {
        1
    } else {
        match fcs_flag {
            0 => 0,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return None,
        }
    };
    if pos > d.len() {
        return None;
    }

    loop {
        if pos + 3 > d.len() {
            return None;
        }
        let hdr = (d[pos] as u32) | ((d[pos + 1] as u32) << 8) | ((d[pos + 2] as u32) << 16);
        let last = (hdr & 0x01) != 0;
        let btype = (hdr >> 1) & 0x03;
        let bsize = (hdr >> 3) as usize;
        // RLE_Block (type 1): Block_Size is the decoded repeat count; stored content is 1 byte.
        // Raw_Block (type 0) and Compressed_Block (type 2): Block_Size is stored bytes.
        let stored = match btype {
            0 | 2 => bsize,
            1 => 1,
            _ => return None, // reserved
        };
        pos += 3 + stored;
        if pos > d.len() {
            return None;
        }
        if last {
            break;
        }
    }

    if chk_flag != 0 {
        pos += 4;
    }
    if pos > d.len() {
        return None;
    }
    Some(pos)
}

// TAR: magic at moff=257 means d[0] is the start of the 512-byte header block.
// "ustar" at d[257..262]; check checksum field as further validation.
fn tar_ok(d: &[u8]) -> bool {
    if d.len() < 262 {
        return false;
    }
    if &d[257..262] != b"ustar" {
        return false;
    }
    // Checksum validation: sum all header bytes treating [148..156] as 0x20 (space).
    if d.len() < 512 {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &b) in d[..512].iter().enumerate() {
        sum += if (148..156).contains(&i) {
            0x20u32
        } else {
            b as u32
        };
    }
    // Stored checksum: octal ASCII in d[148..156]
    let ck_bytes = &d[148..156];
    let end = ck_bytes
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(8);
    let stored =
        usize::from_str_radix(std::str::from_utf8(&ck_bytes[..end]).unwrap_or("0"), 8).unwrap_or(0);
    // Both unsigned and signed interpretations are used by different implementations
    stored == sum as usize || stored == (sum as i32) as usize
}

// OGG: first page must be BOS (beginning-of-stream, header_type bit 1 set = 0x02).
fn ogg_ok(d: &[u8]) -> bool {
    d.len() >= 28 && &d[0..4] == b"OggS" && d[4] == 0 && d[5] & 0x02 != 0
}

// ── RAR5 VINT / block walker ──────────────────────────────────────────────────

fn rar5_vint(d: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= d.len() {
            return None;
        }
        let b = d[*pos];
        *pos += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 63 {
            return None;
        }
    }
    Some(val)
}

fn rar5_size(d: &[u8]) -> Option<usize> {
    if d.len() < 8 {
        return None;
    }
    let mut pos = 8usize; // skip 8-byte RAR5 signature
    loop {
        if pos + 4 > d.len() {
            return None;
        }
        pos += 4; // skip CRC32
        let hdr_size = rar5_vint(d, &mut pos)? as usize;
        if hdr_size == 0 {
            return None;
        }
        let hdr_body_start = pos;
        let hdr_body_end = pos + hdr_size;
        if hdr_body_end > d.len() {
            return None;
        }

        let mut hpos = hdr_body_start;
        let block_type = rar5_vint(d, &mut hpos)?;
        let flags = rar5_vint(d, &mut hpos)?;

        // RHFL_DATA (bit 2): data area follows header; its size is the LAST VINT in header body.
        let data_area_size: usize = if flags & 0x0004 != 0 && hdr_body_end > hdr_body_start {
            let last = d[hdr_body_end - 1];
            if last & 0x80 != 0 {
                return None;
            } // not a valid VINT terminator
            let mut start = hdr_body_end - 1;
            while start > hdr_body_start && d[start - 1] & 0x80 != 0 {
                start -= 1;
            }
            let mut v = 0u64;
            let mut sh = 0u32;
            for &b in &d[start..hdr_body_end] {
                v |= ((b & 0x7F) as u64) << sh;
                sh += 7;
            }
            v as usize
        } else {
            0
        };

        pos = hdr_body_end + data_area_size;
        if pos > d.len() {
            return None;
        }
        if block_type == 5 {
            return Some(pos);
        } // End of Archive
    }
}

// ── NTFS USN v2 Change Journal ────────────────────────────────────────────────

fn usn_ok(d: &[u8]) -> bool {
    if d.len() < 64 {
        return false;
    }
    let rec_len = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize;
    let major = u16::from_le_bytes([d[4], d[5]]);
    let minor = u16::from_le_bytes([d[6], d[7]]);
    if major != 2 || minor != 0 {
        return false;
    }
    if !(64..=65536).contains(&rec_len) || !rec_len.is_multiple_of(8) {
        return false;
    }
    let fname_len = u16::from_le_bytes([d[56], d[57]]) as usize;
    let fname_off = u16::from_le_bytes([d[58], d[59]]) as usize;
    fname_off >= 60
        && fname_len > 0
        && fname_len.is_multiple_of(2)
        && fname_off + fname_len <= rec_len
}

fn usn_size(d: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    while pos + 64 <= d.len() {
        let rec_len = u32::from_le_bytes([d[pos], d[pos + 1], d[pos + 2], d[pos + 3]]) as usize;
        if !(64..=65536).contains(&rec_len) || !rec_len.is_multiple_of(8) {
            break;
        }
        let major = u16::from_le_bytes([d[pos + 4], d[pos + 5]]);
        let minor = u16::from_le_bytes([d[pos + 6], d[pos + 7]]);
        if major != 2 || minor != 0 {
            break;
        }
        pos += rec_len;
    }
    if pos > 0 {
        Some(pos)
    } else {
        None
    }
}

// ── ESE / JET Blue ────────────────────────────────────────────────────────────

fn ese_ok(d: &[u8]) -> bool {
    d.len() >= 8 && d[4..8] == [0xEF, 0xCD, 0xAB, 0x89]
}

// ─── Subtype detection ────────────────────────────────────────────────────────

fn riff_sub(data: &[u8]) -> (&'static str, &'static str) {
    if data.len() >= 12 {
        match &data[8..12] {
            b"WAVE" => return ("wav", "WAV Audio"),
            b"AVI " => return ("avi", "AVI Video"),
            b"WEBP" => return ("webp", "WebP Image"),
            _ => {}
        }
    }
    ("riff", "RIFF Container")
}

fn zip_sub(data: &[u8]) -> (&'static str, &'static str) {
    let eocd = match memmem::find(data, b"PK\x05\x06") {
        Some(p) => p,
        None => return ("zip", "ZIP Archive"),
    };
    if eocd + 22 > data.len() {
        return ("zip", "ZIP Archive");
    }
    let cdsz = u32::from_le_bytes(data[eocd + 12..eocd + 16].try_into().unwrap_or([0; 4])) as usize;
    let cdoff =
        u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap_or([0; 4])) as usize;
    if cdoff >= data.len() {
        return ("zip", "ZIP Archive");
    }
    let cd = &data[cdoff..(cdoff + cdsz).min(data.len())];

    const PFX: &[(&[u8], &str, &str)] = &[
        (b"word/", "docx", "Word Document"),
        (b"xl/", "xlsx", "Excel Spreadsheet"),
        (b"ppt/", "pptx", "PowerPoint Presentation"),
        (b"META-INF/", "odt", "OpenDocument"),
    ];

    let mut pos = 0;
    while pos + 46 <= cd.len() {
        if &cd[pos..pos + 4] != b"PK\x01\x02" {
            break;
        }
        let fnl = u16::from_le_bytes([cd[pos + 28], cd[pos + 29]]) as usize;
        let exl = u16::from_le_bytes([cd[pos + 30], cd[pos + 31]]) as usize;
        let cml = u16::from_le_bytes([cd[pos + 32], cd[pos + 33]]) as usize;
        let fns = pos + 46;
        let fne = (fns + fnl).min(cd.len());
        let fname = &cd[fns..fne];
        for (p, ext, desc) in PFX {
            if fname.starts_with(p) {
                return (ext, desc);
            }
        }
        pos += 46 + fnl + exl + cml;
    }
    ("zip", "ZIP Archive")
}

// ─── Validators ───────────────────────────────────────────────────────────────

fn jpeg_ok(d: &[u8]) -> bool {
    if d.len() < 4 {
        return false;
    }
    let m = d[3];
    if m == 0x00 || m == 0x01 || m == 0xFF || (0xF8..=0xFD).contains(&m) {
        return false;
    }
    if d.len() >= 8 {
        let sl = ((d[4] as usize) << 8) | d[5] as usize;
        let np = 4 + sl;
        if sl < 2 || np >= d.len() || d[np] != 0xFF {
            return false;
        }
    }
    true
}

fn gz_ok(d: &[u8]) -> bool {
    d.len() >= 3 && d[2] == 0x08
}

fn aac_ok(d: &[u8]) -> bool {
    if d.len() < 7 || (d[1] & 0x06) != 0x00 {
        return false;
    }
    let fl = (((d[3] & 0x03) as usize) << 11) | ((d[4] as usize) << 3) | ((d[5] >> 5) as usize);
    (8..=8192).contains(&fl)
}

fn bmp_ok(d: &[u8]) -> bool {
    if d.len() < 18 {
        return true;
    }
    const VALID: &[u32] = &[12, 40, 52, 56, 64, 108, 124];
    VALID.contains(&u32::from_le_bytes(d[14..18].try_into().unwrap()))
}

// version byte at offset 0 must be a known Prefetch format version
fn pf_ok(d: &[u8]) -> bool {
    d.len() >= 13 && matches!(d[0], 0x11 | 0x17 | 0x1A | 0x1E)
}

// bytes 4-6 must be "03" + ASCII digit; byte 7 must be NUL
fn dex_ok(d: &[u8]) -> bool {
    d.len() >= 8 && d[4] == b'0' && d[5] == b'3' && d[6].is_ascii_digit() && d[7] == 0
}

// version LE u32 at offset 4 must be a known Thumbcache format version
fn thumbcache_ok(d: &[u8]) -> bool {
    if d.len() < 8 {
        return false;
    }
    let ver = u32::from_le_bytes(d[4..8].try_into().unwrap_or([0; 4]));
    ver > 0 && ver < 0x30
}

// PNG: IHDR chunk must be present and structurally valid
fn png_ok(d: &[u8]) -> bool {
    if d.len() < 29 {
        return true;
    }
    if d[8..12] != [0, 0, 0, 13] {
        return false;
    } // IHDR length == 13
    if &d[12..16] != b"IHDR" {
        return false;
    }
    let w = u32::from_be_bytes(d[16..20].try_into().unwrap_or([0; 4]));
    let h = u32::from_be_bytes(d[20..24].try_into().unwrap_or([0; 4]));
    if w == 0 || w >= 0x8000_0000 || h == 0 || h >= 0x8000_0000 {
        return false;
    }
    matches!(d[24], 1|2|4|8|16)       // bit_depth
        && matches!(d[25], 0|2|3|4|6) // color_type
        && d[26] == 0                  // compression_method (only 0 valid)
        && d[27] == 0                  // filter_method (only 0 valid)
        && d[28] <= 1 // interlace_method (0=none, 1=Adam7)
}

// NTFS MFT entry: fixup sentinel at 510-511 must equal sentinel at 1022-1023
fn ntfs_mft_ok(d: &[u8]) -> bool {
    if d.len() < 1024 {
        return false;
    }
    let fixup_off = u16::from_le_bytes([d[4], d[5]]) as usize;
    if !(28..=64).contains(&fixup_off) {
        return false;
    }
    if u16::from_le_bytes([d[6], d[7]]) != 3 {
        return false;
    } // (entry_size/512)+1 = 3 for 1024-byte
    let s0 = u16::from_le_bytes([d[510], d[511]]);
    let s1 = u16::from_le_bytes([d[1022], d[1023]]);
    s0 == s1 && u16::from_le_bytes([d[22], d[23]]) <= 3 // flags: 0=free,1=in-use,2=dir,3=dir in-use
}

// FAT32 FSINFO: secondary sig "rrAa" at byte 484; boot sig 0x55AA at 510-511
fn fat32_fsinfo_ok(d: &[u8]) -> bool {
    d.len() >= 512 && &d[484..488] == b"\x72\x72\x41\x61" && d[510] == 0x55 && d[511] == 0xAA
}

// ext2/3/4 superblock (d[0] = superblock base, moff=56): inode_count > 0, log_block_size <= 6
fn ext2_sb_ok(d: &[u8]) -> bool {
    if d.len() < 84 {
        return false;
    }
    let inodes = u32::from_le_bytes(d[0..4].try_into().unwrap_or([0; 4]));
    let log_bs = u32::from_le_bytes(d[24..28].try_into().unwrap_or([0xff; 4]));
    inodes > 0 && log_bs <= 6
}

// UFS1/2 superblock (d[0] = superblock base, moff=1372): fs_bsize/fs_fsize at 48/52 are powers of 2
fn ufs_sb_ok(d: &[u8]) -> bool {
    if d.len() < 56 {
        return false;
    }
    let bsize = u32::from_le_bytes(d[48..52].try_into().unwrap_or([0; 4]));
    let fsize = u32::from_le_bytes(d[52..56].try_into().unwrap_or([0; 4]));
    fsize > 0
        && bsize >= fsize
        && fsize.is_power_of_two()
        && bsize.is_power_of_two()
        && fsize <= 65536
        && bsize <= 65536
}

// Windows crash dump: ValidDump field at offset 4 must be "DUMP" (32-bit) or "DU64" (64-bit)
fn pagedump_ok(d: &[u8]) -> bool {
    d.len() >= 8 && (&d[4..8] == b"DUMP" || &d[4..8] == b"DU64")
}

// LiME: version field (u32 LE at offset 4) must be 1
fn lime_ok(d: &[u8]) -> bool {
    d.len() >= 8 && u32::from_le_bytes(d[4..8].try_into().unwrap_or([0; 4])) == 1
}

// LUKS: version field (u16 BE at offset 6) must be 1 or 2
fn luks_ok(d: &[u8]) -> bool {
    d.len() >= 8 && matches!(u16::from_be_bytes([d[6], d[7]]), 1 | 2)
}

// ELF: EI_CLASS (byte 4) in {1,2}; EI_DATA (byte 5) in {1,2}
fn elf_ok(d: &[u8]) -> bool {
    d.len() >= 6 && matches!(d[4], 1 | 2) && matches!(d[5], 1 | 2)
}

// PE/MZ: e_lfanew at 0x3c points to "PE\x00\x00"
fn mz_ok(d: &[u8]) -> bool {
    if d.len() < 0x40 {
        return false;
    }
    let pe_off = u32::from_le_bytes(d[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
    pe_off > 0 && pe_off + 4 <= d.len() && &d[pe_off..pe_off + 4] == b"PE\x00\x00"
}

// ─── Utilities ────────────────────────────────────────────────────────────────

fn human_size(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1}MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1}KB", n as f64 / 1024.0)
    } else {
        format!("{}B", n)
    }
}

fn create_output_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    Ok(())
}

#[cfg(unix)]
fn same_device(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev(),
        _ => false,
    }
}

// ─── Metadata extractors (--meta) ────────────────────────────────────────────
//
// Each extractor reads the carved bytes and returns key→value pairs useful for
// triage: timestamps, machine type, filenames, version info.  All functions are
// purely read-only and panic-free; any parse failure is silent.

type MetaMap = serde_json::Map<String, serde_json::Value>;

fn extract_meta(data: &[u8], special: Special) -> Option<MetaMap> {
    let mut m = MetaMap::new();
    match special {
        Special::Jpeg => jpeg_meta(data, &mut m),
        Special::Png => png_meta(data, &mut m),
        Special::Elf => elf_meta(data, &mut m),
        Special::Pe => pe_meta(data, &mut m),
        Special::NtfsMft => mft_meta(data, &mut m),
        Special::Sqlite => sqlite_meta(data, &mut m),
        _ => {}
    }
    if m.is_empty() {
        None
    } else {
        Some(m)
    }
}

// ── JPEG EXIF ──────────────────────────────────────────────────────────────────

fn jpeg_meta(data: &[u8], m: &mut MetaMap) {
    // Walk markers to find APP1 (FF E1) carrying Exif
    let mut i = 2usize;
    loop {
        if i + 3 > data.len() {
            return;
        }
        if data[i] != 0xFF {
            return;
        }
        while i < data.len() && data[i] == 0xFF {
            i += 1;
        }
        if i >= data.len() {
            return;
        }
        let marker = data[i];
        i += 1;
        if marker == 0xD9 || marker == 0xDA {
            return;
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if i + 2 > data.len() {
            return;
        }
        let seg_len = ((data[i] as usize) << 8) | data[i + 1] as usize;
        if seg_len < 2 || i + seg_len > data.len() {
            return;
        }
        let seg = &data[i + 2..i + seg_len];
        if marker == 0xE1 && seg.len() >= 6 && &seg[..6] == b"Exif\x00\x00" {
            exif_parse(&seg[6..], m);
            return;
        }
        i += seg_len;
        if i > data.len() {
            return;
        }
    }
}

fn exif_parse(data: &[u8], m: &mut MetaMap) {
    if data.len() < 8 {
        return;
    }
    let le = &data[0..2] == b"II";
    if !(data[2..4] == [0x2A, 0x00] || data[2..4] == [0x00, 0x2A]) {
        return;
    }

    macro_rules! u16at {
        ($o:expr) => {{
            let o = $o;
            if o + 2 > data.len() {
                return;
            }
            if le {
                u16::from_le_bytes([data[o], data[o + 1]])
            } else {
                u16::from_be_bytes([data[o], data[o + 1]])
            }
        }};
    }
    macro_rules! u32at {
        ($o:expr) => {{
            let o = $o;
            if o + 4 > data.len() {
                return;
            }
            if le {
                u32::from_le_bytes(data[o..o + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(data[o..o + 4].try_into().unwrap())
            }
        }};
    }

    let ifd0 = u32at!(4) as usize;
    if ifd0 + 2 > data.len() {
        return;
    }
    let n = u16at!(ifd0) as usize;
    let mut gps_off: Option<usize> = None;

    for k in 0..n.min(256) {
        let ep = ifd0 + 2 + k * 12;
        if ep + 12 > data.len() {
            break;
        }
        let tag = u16at!(ep);
        let dtype = u16at!(ep + 2);
        let count = u32at!(ep + 4) as usize;

        match tag {
            0x010F | 0x0110 => {
                // Make, Model
                if let Some(v) = exif_ascii_str(data, le, dtype, count, ep + 8) {
                    m.insert(
                        (if tag == 0x010F { "make" } else { "model" }).into(),
                        v.into(),
                    );
                }
            }
            0x0112 if dtype == 3 => {
                // Orientation (SHORT)
                let v = if le {
                    u16::from_le_bytes([data[ep + 8], data[ep + 9]])
                } else {
                    u16::from_be_bytes([data[ep + 8], data[ep + 9]])
                };
                m.insert("orientation".into(), (v as u64).into());
            }
            0x9003 | 0x9004 => {
                // DateTimeOriginal, DateTimeDigitized
                if let Some(v) = exif_ascii_str(data, le, dtype, count, ep + 8) {
                    m.insert(
                        (if tag == 0x9003 {
                            "datetime_original"
                        } else {
                            "datetime_digitized"
                        })
                        .into(),
                        v.into(),
                    );
                }
            }
            0x9011 => {
                // SubSecTimeOriginal
                if let Some(v) = exif_ascii_str(data, le, dtype, count, ep + 8) {
                    m.insert("subsec_time_original".into(), v.into());
                }
            }
            0x8825 => {
                gps_off = Some(u32at!(ep + 8) as usize);
            }
            _ => {}
        }
    }

    if let Some(go) = gps_off {
        if go + 2 > data.len() {
            return;
        }
        let ng = u16at!(go) as usize;
        let (mut lat, mut lon) = (None::<f64>, None::<f64>);
        let (mut lat_ref, mut lon_ref) = (' ', ' ');

        for k in 0..ng.min(64) {
            let ep = go + 2 + k * 12;
            if ep + 12 > data.len() {
                break;
            }
            let tag = u16at!(ep);
            let dtype = u16at!(ep + 2);
            let count = u32at!(ep + 4) as usize;

            match tag {
                0x0001 | 0x0003 => {
                    if ep + 8 < data.len() {
                        let c = data[ep + 8] as char;
                        if tag == 0x0001 {
                            lat_ref = c;
                        } else {
                            lon_ref = c;
                        }
                    }
                }
                0x0002 | 0x0004 if dtype == 5 && count >= 3 => {
                    // RATIONAL
                    let off = u32at!(ep + 8) as usize;
                    if off + 24 <= data.len() {
                        let dd = exif_rational(data, le, off)
                            + exif_rational(data, le, off + 8) / 60.0
                            + exif_rational(data, le, off + 16) / 3600.0;
                        if tag == 0x0002 {
                            lat = Some(dd);
                        } else {
                            lon = Some(dd);
                        }
                    }
                }
                0x001D => {
                    // GPSDateStamp
                    if let Some(v) = exif_ascii_str(data, le, dtype, count, ep + 8) {
                        m.insert("gps_date".into(), v.into());
                    }
                }
                _ => {}
            }
        }

        if let (Some(la), Some(lo)) = (lat, lon) {
            m.insert(
                "gps_lat".into(),
                (la * if lat_ref == 'S' { -1.0 } else { 1.0 }).into(),
            );
            m.insert(
                "gps_lon".into(),
                (lo * if lon_ref == 'W' { -1.0 } else { 1.0 }).into(),
            );
        }
    }
}

fn exif_ascii_str(data: &[u8], le: bool, dtype: u16, count: usize, voff: usize) -> Option<String> {
    if dtype != 2 {
        return None;
    }
    let (ptr, len) = if count <= 4 {
        (voff, count)
    } else {
        let off = if le {
            u32::from_le_bytes(data[voff..voff + 4].try_into().ok()?) as usize
        } else {
            u32::from_be_bytes(data[voff..voff + 4].try_into().ok()?) as usize
        };
        (off, count)
    };
    if ptr + len > data.len() {
        return None;
    }
    let s = std::str::from_utf8(&data[ptr..ptr + len])
        .ok()?
        .trim_end_matches('\x00')
        .trim()
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn exif_rational(data: &[u8], le: bool, off: usize) -> f64 {
    if off + 8 > data.len() {
        return 0.0;
    }
    let n = if le {
        u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
    } else {
        u32::from_be_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
    };
    let d = if le {
        u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4]))
    } else {
        u32::from_be_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4]))
    };
    if d == 0 {
        0.0
    } else {
        n as f64 / d as f64
    }
}

// ── PNG tEXt / iTXt ───────────────────────────────────────────────────────────

fn png_meta(data: &[u8], m: &mut MetaMap) {
    const KEEP: &[&str] = &[
        "Creation Time",
        "Software",
        "Author",
        "Comment",
        "Title",
        "Description",
        "Copyright",
        "Source",
    ];
    let mut pos = 8usize; // skip 8-byte PNG signature
    let mut n = 0usize;
    while pos + 12 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4])) as usize;
        if pos + 8 + len > data.len() {
            break;
        }
        let typ = &data[pos + 4..pos + 8];
        let body = &data[pos + 8..pos + 8 + len];

        if typ == b"tEXt" {
            if let Some(nul) = body.iter().position(|&b| b == 0) {
                let key = std::str::from_utf8(&body[..nul]).unwrap_or("").to_string();
                let val = std::str::from_utf8(&body[nul + 1..])
                    .unwrap_or("")
                    .to_string();
                if KEEP.contains(&key.as_str()) {
                    m.insert(key.to_lowercase().replace(' ', "_"), val.into());
                }
            }
        } else if typ == b"IEND" {
            break;
        }

        pos += 12 + len;
        n += 1;
        if n > 2000 {
            break;
        }
    }
}

// ── ELF ───────────────────────────────────────────────────────────────────────

fn elf_meta(data: &[u8], m: &mut MetaMap) {
    if data.len() < 24 {
        return;
    }
    let class = data[4]; // 1=32-bit, 2=64-bit
    let le = data[5] == 1;
    macro_rules! u16r {
        ($o:expr) => {{
            let o = $o;
            if o + 2 > data.len() {
                return;
            }
            if le {
                u16::from_le_bytes([data[o], data[o + 1]])
            } else {
                u16::from_be_bytes([data[o], data[o + 1]])
            }
        }};
    }
    macro_rules! u32r {
        ($o:expr) => {{
            let o = $o;
            if o + 4 > data.len() {
                return;
            }
            if le {
                u32::from_le_bytes(data[o..o + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(data[o..o + 4].try_into().unwrap())
            }
        }};
    }
    macro_rules! u64r {
        ($o:expr) => {{
            let o = $o;
            if o + 8 > data.len() {
                return;
            }
            if le {
                u64::from_le_bytes(data[o..o + 8].try_into().unwrap())
            } else {
                u64::from_be_bytes(data[o..o + 8].try_into().unwrap())
            }
        }};
    }

    let e_type = u16r!(16);
    let e_machine = u16r!(18);
    let e_entry = if class == 2 {
        u64r!(40)
    } else {
        u64::from(u32r!(24))
    };

    m.insert(
        "class".into(),
        (if class == 2 { "ELF64" } else { "ELF32" }).into(),
    );
    m.insert("endian".into(), (if le { "little" } else { "big" }).into());
    m.insert(
        "type".into(),
        match e_type {
            1 => "relocatable",
            2 => "executable",
            3 => "shared",
            4 => "core",
            _ => "unknown",
        }
        .into(),
    );
    m.insert("machine".into(), elf_machine_name(e_machine).into());
    if e_entry > 0 {
        m.insert("entry".into(), format!("0x{e_entry:x}").into());
    }
}

fn elf_machine_name(m: u16) -> &'static str {
    match m {
        0x00 => "none",
        0x02 => "SPARC",
        0x03 => "x86",
        0x08 => "MIPS",
        0x14 => "PPC",
        0x16 => "S390",
        0x28 => "ARM",
        0x2A => "SuperH",
        0x32 => "IA-64",
        0x3E => "x86-64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        0xF7 => "BPF",
        _ => "unknown",
    }
}

// ── PE/MZ ─────────────────────────────────────────────────────────────────────

fn pe_meta(data: &[u8], m: &mut MetaMap) {
    if data.len() < 0x40 {
        return;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
    if pe_off + 24 > data.len() {
        return;
    }
    if &data[pe_off..pe_off + 4] != b"PE\x00\x00" {
        return;
    }
    let machine = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
    let timestamp = u32::from_le_bytes(data[pe_off + 8..pe_off + 12].try_into().unwrap_or([0; 4]));
    let nsections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]);
    let opt_size = u16::from_le_bytes([data[pe_off + 20], data[pe_off + 21]]) as usize;
    m.insert("machine".into(), pe_machine_name(machine).into());
    m.insert("compile_timestamp".into(), (timestamp as i64).into());
    m.insert("sections".into(), (nsections as u64).into());
    if opt_size >= 2 && pe_off + 26 <= data.len() {
        let magic = u16::from_le_bytes([data[pe_off + 24], data[pe_off + 25]]);
        // Subsystem is at opt_header+68 for both PE32 (0x10b) and PE32+ (0x20b).
        // The only structural difference is ImageBase width (4 vs 8) at offset 24/28,
        // but all fields from SectionAlignment (offset 32) onward are at the same offsets.
        let sub_off = pe_off
            + 24
            + match magic {
                0x10b | 0x20b => 68,
                _ => 0,
            };
        if sub_off > pe_off + 24 && sub_off + 2 <= data.len() {
            let sub = u16::from_le_bytes([data[sub_off], data[sub_off + 1]]);
            m.insert("subsystem".into(), pe_subsystem_name(sub).into());
        }
    }
}

fn pe_machine_name(m: u16) -> &'static str {
    match m {
        0x014c => "x86",
        0x8664 => "x64",
        0x01c4 => "ARMv7",
        0xAA64 => "ARM64",
        0x0200 => "IA64",
        _ => "unknown",
    }
}

fn pe_subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "windows-gui",
        3 => "windows-cui",
        7 => "posix",
        9 => "windows-ce",
        10 => "efi-app",
        _ => "unknown",
    }
}

// ── NTFS MFT ─────────────────────────────────────────────────────────────────

fn mft_meta(data: &[u8], m: &mut MetaMap) {
    if data.len() < 48 {
        return;
    }
    // Offset to first attribute is at byte 20 (u16 LE)
    let attr_off = u16::from_le_bytes([data[20], data[21]]) as usize;
    if attr_off < 48 || attr_off >= data.len() {
        return;
    }
    let mut pos = attr_off;
    for _ in 0..64usize {
        if pos + 8 > data.len() {
            break;
        }
        let atype = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0xFF; 4]));
        if atype == 0xFFFFFFFF {
            break;
        }
        let alen = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        if alen < 8 || pos + alen > data.len() {
            break;
        }
        if atype == 0x30 {
            // $FILE_NAME
            let non_res = data[pos + 8];
            if non_res == 0 {
                let voff = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
                let vs = pos + voff;
                // $FILE_NAME layout: parent(8)+created(8)+modified(8)+mft_mod(8)+accessed(8)+
                //                    alloc(8)+real(8)+flags(4)+reparse(4)+name_len(1)+ns(1)+name(2*n)
                if vs + 66 <= data.len() {
                    let fn_data = &data[vs..];
                    let created = u64::from_le_bytes(fn_data[8..16].try_into().unwrap_or([0; 8]));
                    let modified = u64::from_le_bytes(fn_data[16..24].try_into().unwrap_or([0; 8]));
                    let accessed = u64::from_le_bytes(fn_data[32..40].try_into().unwrap_or([0; 8]));
                    let name_len = fn_data[64] as usize;
                    if vs + 66 + name_len * 2 <= data.len() {
                        let nb = &data[vs + 66..vs + 66 + name_len * 2];
                        let name: String =
                            (0..name_len)
                                .filter_map(|i| {
                                    char::from_u32(
                                        u16::from_le_bytes([nb[i * 2], nb[i * 2 + 1]]) as u32
                                    )
                                })
                                .collect();
                        if !name.is_empty() {
                            m.insert("filename".into(), name.into());
                        }
                    }
                    if let Some(ts) = filetime_to_unix(created) {
                        m.insert("created".into(), ts.into());
                    }
                    if let Some(ts) = filetime_to_unix(modified) {
                        m.insert("modified".into(), ts.into());
                    }
                    if let Some(ts) = filetime_to_unix(accessed) {
                        m.insert("accessed".into(), ts.into());
                    }
                    break;
                }
            }
        }
        pos += alen;
    }

    // Cluster runs from non-resident $DATA: emit for forensic cross-referencing
    if let Some(info) = mft_run_info(data) {
        if !info.runs.is_empty() {
            let arr = serde_json::Value::Array(
                info.runs
                    .iter()
                    .map(|&(lcn, len)| {
                        serde_json::Value::Array(vec![
                            serde_json::Value::Number(lcn.into()),
                            serde_json::Value::Number(len.into()),
                        ])
                    })
                    .collect(),
            );
            m.insert("cluster_runs".into(), arr);
            m.insert("data_size_bytes".into(), info.data_size.into());
        }
        if let Some(ref n) = info.name_hint {
            if !m.contains_key("filename") {
                m.insert("ntfs_filename".into(), n.clone().into());
            }
        }
    }
}

fn filetime_to_unix(ft: u64) -> Option<i64> {
    // FILETIME: 100-ns intervals since 1601-01-01; Unix epoch offset in same units
    const OFFSET: u64 = 116_444_736_000_000_000;
    if ft < OFFSET || ft == 0 {
        return None;
    }
    Some(((ft - OFFSET) / 10_000_000) as i64)
}

// ── NTFS cluster run helpers ──────────────────────────────────────────────────

// Read NTFS cluster size from the BPB at offset 0 of a partition image.
// Negative spc_raw means cluster size = 2^(-spc_raw) bytes (Win8+, large clusters).
fn ntfs_cluster_size(src: &[u8]) -> u64 {
    if src.len() < 0x10 || &src[3..11] != b"NTFS    " {
        return 4096;
    }
    let bps = u16::from_le_bytes([src[0x0B], src[0x0C]]) as u64;
    if bps == 0 {
        return 4096;
    }
    let spc_raw = src[0x0D] as i8;
    if spc_raw <= 0 {
        return 1u64 << ((-spc_raw as u32).min(30));
    }
    (bps * spc_raw as u64).max(512)
}

// Decode an NTFS data run list starting at `data[start..]`.
// Returns (start_lcn, length_in_clusters) pairs; cluster offsets are cumulative
// (each run's LCN = sum of all previous delta offsets).
// Sparse runs (off_bytes == 0) are skipped — no physical sectors to read.
fn parse_data_runs(data: &[u8], start: usize) -> Vec<(u64, u64)> {
    let mut runs = Vec::new();
    let mut pos = start;
    let mut lcn: i64 = 0;

    while pos < data.len() {
        let hdr = data[pos];
        if hdr == 0 {
            break;
        } // run-list terminator
        pos += 1;

        let len_bytes = (hdr & 0x0F) as usize; // bytes encoding run length
        let off_bytes = (hdr >> 4) as usize; // bytes encoding cluster delta (signed)

        if !(1..=8).contains(&len_bytes)
            || off_bytes > 8
            || pos
                .checked_add(len_bytes)
                .and_then(|p| p.checked_add(off_bytes))
                .is_none_or(|end| end > data.len())
        {
            break;
        }

        // Run length: unsigned LE, 1-8 bytes
        let mut run_len = 0u64;
        for i in 0..len_bytes {
            run_len |= (data[pos + i] as u64) << (i * 8);
        }
        pos += len_bytes;

        if off_bytes == 0 {
            // Sparse run — no LCN data; the clusters are a hole (all zeros)
            continue;
        }

        // Cluster delta: signed LE, sign-extend to i64
        let mut delta = 0i64;
        for i in 0..off_bytes {
            delta |= (data[pos + i] as i64) << (i * 8);
        }
        if off_bytes < 8 && data[pos + off_bytes - 1] & 0x80 != 0 {
            delta |= -1i64 << (off_bytes * 8);
        }
        pos += off_bytes;

        lcn = lcn.saturating_add(delta);
        if lcn >= 0 && run_len > 0 {
            runs.push((lcn as u64, run_len));
        }
    }
    runs
}

struct MftRunInfo {
    runs: Vec<(u64, u64)>,     // (start_lcn, length_in_clusters)
    data_size: u64,            // actual file size in bytes (from non-resident $DATA header)
    name_hint: Option<String>, // filename from $FILE_NAME, for type detection fallback
}

// Walk a 1024-byte NTFS MFT entry's attribute list.
// Returns cluster run info if the entry has a non-resident $DATA attribute.
// Resident $DATA (small files with inline data) returns None — nothing to re-read.
fn mft_run_info(entry: &[u8]) -> Option<MftRunInfo> {
    if entry.len() < 48 {
        return None;
    }
    let attr_off = u16::from_le_bytes([entry[20], entry[21]]) as usize;
    if attr_off < 48 || attr_off >= entry.len() {
        return None;
    }

    let mut pos = attr_off;
    let mut found_runs: Option<Vec<(u64, u64)>> = None;
    let mut data_size = 0u64;
    let mut name_hint: Option<String> = None;

    for _ in 0..32usize {
        if pos + 8 > entry.len() {
            break;
        }
        let atype = u32::from_le_bytes(entry[pos..pos + 4].try_into().unwrap_or([0xFF; 4]));
        if atype == 0xFFFF_FFFF {
            break;
        }
        let alen =
            u32::from_le_bytes(entry[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        if alen < 8 || pos + alen > entry.len() {
            break;
        }

        match atype {
            0x30 => {
                // $FILE_NAME — extract filename as type-detection hint
                if entry[pos + 8] == 0 {
                    // resident
                    let voff = u16::from_le_bytes([entry[pos + 20], entry[pos + 21]]) as usize;
                    let vs = pos + voff;
                    if vs + 66 <= entry.len() {
                        let name_len = entry[vs + 64] as usize;
                        if vs + 66 + name_len * 2 <= entry.len() {
                            let nb = &entry[vs + 66..vs + 66 + name_len * 2];
                            let s: String = (0..name_len)
                                .filter_map(|i| {
                                    char::from_u32(
                                        u16::from_le_bytes([nb[i * 2], nb[i * 2 + 1]]) as u32
                                    )
                                })
                                .collect();
                            if !s.is_empty() {
                                name_hint = Some(s);
                            }
                        }
                    }
                }
            }
            0x80 if entry[pos + 8] == 1 && pos + 56 <= entry.len() => {
                // $DATA — extract non-resident run list
                // Non-resident attribute header (offset from attribute start):
                //   +8  non_resident flag (1 = non-resident)
                //   +32 run list offset (u16 LE, relative to attribute start)
                //   +48 data size (u64 LE, actual file bytes)
                let run_off = u16::from_le_bytes([entry[pos + 32], entry[pos + 33]]) as usize;
                let ds = u64::from_le_bytes(entry[pos + 48..pos + 56].try_into().unwrap_or([0; 8]));
                if ds > 0 && pos + run_off < entry.len() {
                    let r = parse_data_runs(entry, pos + run_off);
                    if !r.is_empty() {
                        found_runs = Some(r);
                        data_size = ds;
                    }
                }
            }
            _ => {}
        }
        pos += alen;
    }

    let runs = found_runs?;
    Some(MftRunInfo {
        runs,
        data_size,
        name_hint,
    })
}

// ── SQLite ────────────────────────────────────────────────────────────────────

fn sqlite_meta(data: &[u8], m: &mut MetaMap) {
    if data.len() < 100 {
        return;
    }
    let raw_ps = u16::from_be_bytes([data[16], data[17]]) as usize;
    let ps = if raw_ps == 1 { 65536 } else { raw_ps };
    let pc = u32::from_be_bytes(data[28..32].try_into().unwrap_or([0; 4])) as u64;
    let app_id = u32::from_be_bytes(data[60..64].try_into().unwrap_or([0; 4]));
    let usr_v = u32::from_be_bytes(data[68..72].try_into().unwrap_or([0; 4]));
    let write_v = data[18]; // 1=journal, 2=WAL
    m.insert("page_size".into(), (ps as u64).into());
    m.insert("page_count".into(), pc.into());
    if app_id != 0 {
        m.insert("application_id".into(), (app_id as u64).into());
    }
    if usr_v != 0 {
        m.insert("user_version".into(), (usr_v as u64).into());
    }
    m.insert(
        "journal_mode".into(),
        (if write_v == 2 { "WAL" } else { "journal" }).into(),
    );
}

// ─── Carving engine ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Quality {
    Complete,   // size algorithm found a natural end marker
    Partial,    // hit max-size window without natural end
    Fragmented, // assembled from 2+ pieces by frag_merge()
}

impl Quality {
    fn as_str(self) -> &'static str {
        match self {
            Quality::Complete => "complete",
            Quality::Partial => "partial",
            Quality::Fragmented => "fragmented",
        }
    }
}

#[derive(Clone)]
pub struct Finding {
    pub offset: usize,
    pub name: String,
    pub ext: String,
    pub desc: String,
    pub size: usize,
    pub path: PathBuf,
    pub trunc: bool,
    pub quality: Quality,
    pub sha256: String,
    pub has_bad_sectors: bool,
    pub meta: Option<serde_json::Map<String, serde_json::Value>>,
    pub source: Option<String>, // "inode:N" for filesystem-assisted recovery; None for sig-carved
}

// Pre-write candidate: all fields needed to emit a Finding, without touching the filesystem.
// Produced by scan_sig() during the parallel scan phase.
struct Candidate {
    global_start: usize,
    sig_idx: usize, // tiebreaker: lower index = higher priority on same offset
    name: String,
    ext: String,
    desc: String,
    special: Special,
    trunc: bool,
    merged: bool,      // true if frag_merge() assembled this from 2+ pieces
    low_entropy: bool, // true if Shannon entropy of first 512 bytes < 0.1 bits/byte
    data: Vec<u8>,
}

// Scan `src` for one signature; return all validated, trimmed candidates.
// Does NOT touch the filesystem or check the seen-set — both happen in the serial phase.
// align_bytes > 0: skip matches whose global byte offset is not a multiple of align_bytes.
fn scan_sig(
    src: &[u8],
    base_offset: usize,
    sig: &DynSig,
    sig_idx: usize,
    min_override: Option<usize>,
    max_override: Option<usize>,
    align_bytes: usize,
) -> Vec<Candidate> {
    let finder = memmem::Finder::new(&sig.magic);
    let min = sig.min.max(min_override.unwrap_or(0)).max(DEFAULT_MIN);
    let max = max_override.unwrap_or(sig.max);
    let mut out = Vec::new();
    let mut ss = 0usize;

    while let Some(rel) = finder.find(&src[ss..]) {
        let idx = ss + rel;
        ss = idx + 1;

        if idx < sig.moff {
            continue;
        }
        let start = idx - sig.moff;

        if align_bytes > 0
            && !base_offset
                .saturating_add(start)
                .is_multiple_of(align_bytes)
        {
            continue;
        }

        let wend = start.saturating_add(max).min(src.len());
        let data = &src[start..wend];
        if data.len() < min {
            continue;
        }

        // ── end-finding ──────────────────────────────────────────────────────
        let (carved, mut trunc): (&[u8], bool) = match sig.special {
            Special::Jpeg => match jpeg_length(data) {
                Some(n) => (&data[..n], false),
                None => match memmem::find(data, b"\xFF\xD9") {
                    Some(p) => (&data[..p + 2], false),
                    None => (data, true),
                },
            },
            Special::Zip => match zip_eocd_end(data) {
                Some(e) => (&data[..e.min(data.len())], false),
                None => (data, true),
            },
            _ => {
                if let Some(ref em) = sig.em {
                    let p = if sig.em_last {
                        memmem::rfind(data, em)
                    } else {
                        memmem::find(data, em)
                    };
                    match p {
                        Some(p) => {
                            let mut cut = p + em.len();
                            let mut tr = sig.em_trail;
                            while tr > 0 && cut < data.len() && matches!(data[cut], 0x0A | 0x0D) {
                                cut += 1;
                                tr -= 1;
                            }
                            (&data[..cut], false)
                        }
                        None => (data, true),
                    }
                } else {
                    (data, true)
                }
            }
        };

        if carved.len() < min {
            continue;
        }

        // ── validation ───────────────────────────────────────────────────────
        let valid = match sig.special {
            Special::Jpeg => jpeg_ok(carved),
            Special::Gz => gz_ok(carved),
            Special::Aac => aac_ok(carved),
            Special::Bmp => bmp_ok(carved),
            Special::Pf => pf_ok(carved),
            Special::Dex => dex_ok(carved),
            Special::Thumbcache => thumbcache_ok(carved),
            Special::Png => png_ok(carved),
            Special::NtfsMft => ntfs_mft_ok(carved),
            Special::Fat32Fsinfo => fat32_fsinfo_ok(carved),
            Special::Ext2Sb => ext2_sb_ok(carved),
            Special::UfsSb => ufs_sb_ok(carved),
            Special::PageDump => pagedump_ok(carved),
            Special::LiME => lime_ok(carved),
            Special::Luks => luks_ok(carved),
            Special::Elf => elf_ok(carved),
            Special::Pe => mz_ok(carved),
            Special::Tar => tar_ok(carved),
            Special::Ogg => ogg_ok(carved),
            Special::Bz2 => bz2_ok(carved),
            Special::Zstd => zstd_ok(carved),
            Special::UsnRec => usn_ok(carved),
            Special::Ese => ese_ok(carved),
            _ => true,
        };
        if !valid {
            continue;
        }

        // ── subtype + size-field trimming ─────────────────────────────────────
        let (fext, fdesc, fdata): (&str, &str, &[u8]) = match sig.special {
            Special::Riff => {
                let (e, d) = riff_sub(carved);
                let trim = match riff_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (e, d, trim)
            }
            Special::Zip => {
                let (e, d) = zip_sub(carved);
                (e, d, carved)
            }
            Special::Bmp => {
                let trim = match bmp_size(carved) {
                    Some(n) if n < carved.len() => &carved[..n],
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Tiff => {
                let trim = match tiff_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Sqlite => {
                let trim = match sqlite_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Regf => {
                let trim = match regf_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Pf => {
                let trim = match pf_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Dex => {
                let trim = match dex_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Elf => {
                let trim = match elf_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Pe => {
                let trim = match pe_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Mp4 => {
                let trim = match mp4_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Mkv => {
                let trim = match mkv_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Rar => {
                let trim = match rar_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Sevenz => {
                let trim = match sevenz_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Ole2 => {
                let trim = match ole2_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Mp3 => {
                let trim = match mp3_id3_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Flac => {
                let trim = match flac_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Pcap => {
                let trim = match pcap_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Pcapng => {
                let trim = match pcapng_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Der => {
                let trim = match der_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Apfs => {
                let trim = match apfs_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Iso9660 => {
                let trim = match iso9660_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::SquashfsLe => {
                let trim = match squashfs_size_le(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::SquashfsBe => {
                let trim = match squashfs_size_be(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Uboot => {
                let trim = match uboot_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Fit => {
                let trim = match fit_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Cramfs => {
                let trim = match cramfs_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::LiME => {
                let trim = match lime_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Tar => {
                let trim = match tar_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Ogg => {
                let trim = match ogg_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Zstd => {
                let trim = match zstd_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            // Bz2: bit-packed EOS marker; no byte-aligned trim possible.
            Special::Bz2 => (&sig.ext, &sig.desc, carved),
            Special::Rar5 => {
                let trim = match rar5_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::UsnRec => {
                let trim = match usn_size(carved) {
                    Some(n) if n <= carved.len() => {
                        trunc = false;
                        &carved[..n]
                    }
                    _ => carved,
                };
                (&sig.ext, &sig.desc, trim)
            }
            Special::Ese => (&sig.ext, &sig.desc, carved),
            _ => (&sig.ext, &sig.desc, carved),
        };

        let low_entropy = entropy_estimate(fdata, 512) < 0.1;
        out.push(Candidate {
            global_start: base_offset + start,
            sig_idx,
            name: sig.name.clone(),
            ext: fext.to_string(),
            desc: fdesc.to_string(),
            special: sig.special,
            trunc,
            merged: false,
            low_entropy,
            data: fdata.to_vec(),
        });
    }
    out
}

// ─── Fragment reassembly (stage 1) ───────────────────────────────────────────
//
// After dedup, scan consecutive same-type pairs where block A is truncated and
// B starts exactly where A ends.  Concatenate and re-validate; if the merged
// result passes, replace A with the merged bytes and drop B.  Repeats until
// no more merges are possible (handles 3+ fragment runs).
//
// Only types that have meaningful validators benefit from this.  Special::None
// types have no validator so they're accepted unconditionally — acceptable since
// the trigger condition (trunc=true AND exact-contiguous B) is already tight.

fn frag_valid(data: &[u8], special: Special) -> bool {
    match special {
        Special::Jpeg => jpeg_ok(data),
        Special::Png => png_ok(data),
        Special::Gz => gz_ok(data),
        Special::Bmp => bmp_ok(data),
        Special::Elf => elf_ok(data),
        Special::Pe => mz_ok(data),
        Special::NtfsMft => ntfs_mft_ok(data),
        Special::Fat32Fsinfo => fat32_fsinfo_ok(data),
        Special::Ext2Sb => ext2_sb_ok(data),
        Special::UfsSb => ufs_sb_ok(data),
        Special::PageDump => pagedump_ok(data),
        Special::LiME => lime_ok(data),
        Special::Luks => luks_ok(data),
        Special::Dex => dex_ok(data),
        Special::Pf => pf_ok(data),
        Special::Thumbcache => thumbcache_ok(data),
        Special::Tar => tar_ok(data),
        Special::Ogg => ogg_ok(data),
        Special::Bz2 => bz2_ok(data),
        Special::Zstd => zstd_ok(data),
        Special::UsnRec => usn_ok(data),
        Special::Ese => ese_ok(data),
        Special::Zip => zip_eocd_end(data).is_some(),
        _ => true, // Riff/Mp4/Mkv/etc — accept; size-trimmer corrects the bounds
    }
}

fn entropy_estimate(data: &[u8], limit: usize) -> f64 {
    let n = data.len().min(limit);
    if n == 0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in &data[..n] {
        freq[b as usize] += 1;
    }
    let nf = n as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / nf;
            -p * p.log2()
        })
        .sum()
}

// gap_limit > 0: also attempt merge when B starts within gap_limit bytes past A's end.
// The gap is zero-filled in the merged output (mirrors bad-sector zero-fill on block devices).
// Returns the number of merge operations performed.
fn frag_merge(candidates: &mut Vec<Candidate>, gap_limit: usize) -> usize {
    let mut total_merges = 0usize;
    let mut changed = true;
    while changed {
        changed = false;
        let mut i = 0;
        while i + 1 < candidates.len() {
            let a_end = candidates[i].global_start + candidates[i].data.len();
            let b_start = candidates[i + 1].global_start;
            let gap = b_start.saturating_sub(a_end);
            if candidates[i].trunc
                && !candidates[i].low_entropy
                && !candidates[i + 1].low_entropy
                && candidates[i].name == candidates[i + 1].name
                && b_start >= a_end
                && gap <= gap_limit
            {
                let mut merged: Vec<u8> = Vec::with_capacity(
                    candidates[i].data.len() + gap + candidates[i + 1].data.len(),
                );
                merged.extend_from_slice(&candidates[i].data);
                merged.resize(merged.len() + gap, 0);
                merged.extend_from_slice(&candidates[i + 1].data);
                if frag_valid(&merged, candidates[i].special) {
                    let b_trunc = candidates[i + 1].trunc;
                    candidates[i].data = merged;
                    candidates[i].trunc = b_trunc;
                    candidates[i].merged = true;
                    candidates.remove(i + 1);
                    total_merges += 1;
                    changed = true;
                    continue;
                }
            }
            i += 1;
        }
    }
    total_merges
}

// Shared state across carve() calls — enables chunked scanning without duplicate findings
// or colliding output filenames.
pub struct CarveState {
    pub seen: HashSet<usize>,
    pub ctr: HashMap<String, usize>,
    pub completed_chunks: usize,
    pub findings_so_far: usize,
    pub emitted_this_run: usize,
    pub finding_limit: Option<usize>,
    pub min_size_override: Option<usize>,
    pub merge_count: usize,
    pub bad_sector_offsets: Vec<u64>,
    pub seen_sha256: HashSet<String>,
    pub skip_high_entropy: bool,
    pub zero_sectors: u64,
    pub high_entropy_sectors_skipped: u64,
}

impl CarveState {
    pub fn new() -> Self {
        CarveState {
            seen: HashSet::new(),
            ctr: HashMap::new(),
            completed_chunks: 0,
            findings_so_far: 0,
            emitted_this_run: 0,
            finding_limit: None,
            min_size_override: None,
            merge_count: 0,
            bad_sector_offsets: Vec::new(),
            seen_sha256: HashSet::new(),
            skip_high_entropy: false,
            zero_sectors: 0,
            high_entropy_sectors_skipped: 0,
        }
    }

    fn limit_reached(&self) -> bool {
        self.finding_limit
            .is_some_and(|limit| self.emitted_this_run >= limit)
    }

    fn below_min_size(&self, size: usize) -> bool {
        self.min_size_override.is_some_and(|min| size < min)
    }

    fn record_finding(&mut self) {
        self.findings_so_far += 1;
        self.emitted_this_run += 1;
    }
}

impl Default for CarveState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Checkpoint / resume ─────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct PalaState {
    source: String,
    source_bytes: u64,
    completed_chunks: u64,
    ctr: HashMap<String, usize>,
    findings_so_far: usize,
    #[serde(default)]
    seen_offsets: Vec<u64>,
    #[serde(default)]
    seen_sha256: Vec<String>,
}

fn write_checkpoint(
    state_path: &Path,
    source: &str,
    source_bytes: u64,
    state: &CarveState,
) -> Result<()> {
    use std::io::Write as _;

    let mut seen_offsets: Vec<u64> = state.seen.iter().map(|&o| o as u64).collect();
    seen_offsets.sort_unstable();
    let mut seen_sha256: Vec<String> = state.seen_sha256.iter().cloned().collect();
    seen_sha256.sort_unstable();
    let ps = PalaState {
        source: source.to_string(),
        source_bytes,
        completed_chunks: state.completed_chunks as u64,
        ctr: state.ctr.clone(),
        findings_so_far: state.findings_so_far,
        seen_offsets,
        seen_sha256,
    };
    let json = serde_json::to_vec_pretty(&ps)?;
    let tmp = state_path.with_extension("json.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(&json)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    if state_path.exists() {
        fs::remove_file(state_path)?;
    }
    fs::rename(&tmp, state_path)?;
    Ok(())
}

fn read_checkpoint(state_path: &Path) -> Option<PalaState> {
    let bytes = fs::read(state_path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

// Scan `src` for all signatures, write recovered files to `outdir`.
// `base_offset`: byte offset of `src[0]` within the original source — used to compute
// globally-unique offsets when called repeatedly on overlapping chunks.
#[allow(clippy::too_many_arguments)]
pub fn carve(
    src: &[u8],
    base_offset: usize,
    outdir: &Path,
    sigs: &[DynSig],
    quiet: bool,
    emit_meta: bool,
    max_override: Option<usize>,
    frag_gap: usize,
    align_bytes: usize,
    emit_before: Option<usize>,
    state: &mut CarveState,
) -> Result<Vec<Finding>> {
    create_output_dir(outdir)?;

    let total = sigs.len();
    let completed = AtomicUsize::new(0);
    let min_override = state.min_size_override;

    // ── Phase 1: parallel scan ─────────────────────────────────────────────────
    // Each signature scans the full window independently on its own thread.
    // scan_sig() does not touch the filesystem or the seen-set.
    let mut candidates: Vec<Candidate> = sigs
        .par_iter()
        .enumerate()
        .flat_map(|(si, sig)| {
            let hits = scan_sig(
                src,
                base_offset,
                sig,
                si,
                min_override,
                max_override,
                align_bytes,
            );
            if !quiet {
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!(
                    "  [{:>2}/{}] {}... {} hit(s)",
                    done,
                    total,
                    sig.name,
                    hits.len()
                );
            }
            hits
        })
        .collect();

    // Sort by (offset, sig_idx) so that sig-list order breaks ties at the same offset.
    candidates.sort_unstable_by_key(|c| (c.global_start, c.sig_idx));

    // ── Phase 1b: fragment reassembly ─────────────────────────────────────────
    // Dedup first so merge only sees one candidate per starting offset, then merge.
    let mut deduped: Vec<Candidate> = Vec::new();
    let mut candidate_offsets = HashSet::new();
    for c in candidates {
        if emit_before.is_some_and(|end| c.global_start >= end)
            || state.seen.contains(&c.global_start)
            || !candidate_offsets.insert(c.global_start)
        {
            continue;
        }
        deduped.push(c);
    }
    state.merge_count += frag_merge(&mut deduped, frag_gap);

    // ── Phase 2: write (serial) ───────────────────────────────────────────────
    let mut out = Vec::new();
    for c in deduped {
        if state.limit_reached() {
            break;
        }

        // Entropy gate: if --skip-high-entropy, skip findings whose START SECTOR
        // has H > 7.5 (compressed/encrypted data that produces false magic-byte matches).
        if state.skip_high_entropy {
            const SECTOR: usize = 512;
            let global_sector = (c.global_start / SECTOR) * SECTOR;
            let local_sector = global_sector.saturating_sub(base_offset);
            let sec_end = (local_sector + SECTOR).min(src.len());
            if local_sector < sec_end && sector_entropy(&src[local_sector..sec_end]) > 7.5 {
                state.high_entropy_sectors_skipped += 1;
                continue;
            }
        }

        state.seen.insert(c.global_start);

        // SHA256 dedup must happen BEFORE counter increment and writing so that
        // files already recovered by another phase do not consume a sequence number.
        let mut h = Sha256::new();
        h.update(&c.data);
        let sha = format!("{:x}", h.finalize());
        if state.seen_sha256.contains(&sha) {
            continue;
        }
        state.seen_sha256.insert(sha.clone());

        let n = {
            let cnt = state
                .ctr
                .entry(c.ext.clone())
                .and_modify(|x| *x += 1)
                .or_insert(1);
            *cnt
        };
        let quality = if c.merged {
            Quality::Fragmented
        } else if c.trunc {
            Quality::Partial
        } else {
            Quality::Complete
        };
        // JPEG files that exhaust the max-size window without finding EOI get a _partial
        // suffix so the user knows the recovered file is incomplete.
        let partial = c.trunc && c.special == Special::Jpeg;
        let fname = if partial {
            format!("{ext}_{n:04}_partial.{ext}", ext = c.ext)
        } else {
            format!("{ext}_{n:04}.{ext}", ext = c.ext)
        };
        let out_path = outdir.join(&fname);
        write_new(&out_path, &c.data).with_context(|| format!("writing {}", out_path.display()))?;

        if !quiet {
            let quality_mark = match quality {
                Quality::Fragmented => " [fragmented]",
                Quality::Partial => " [partial]",
                Quality::Complete => "",
            };
            eprintln!(
                "         {:<5}  {:>8}  offset=0x{:08x}  {}{}",
                c.ext,
                human_size(c.data.len()),
                c.global_start,
                fname,
                quality_mark
            );
        }

        let meta = if emit_meta {
            extract_meta(&c.data, c.special)
        } else {
            None
        };

        let f_end = c.global_start + c.data.len();
        let has_bad_sectors = state.bad_sector_offsets.iter().any(|&off| {
            let o = off as usize;
            o >= c.global_start && o < f_end
        });

        out.push(Finding {
            offset: c.global_start,
            name: c.name,
            ext: c.ext,
            desc: c.desc,
            size: c.data.len(),
            path: out_path,
            trunc: c.trunc,
            quality,
            sha256: sha,
            has_bad_sectors,
            meta,
            source: None,
        });
        state.record_finding();
    }
    Ok(out)
}

// ─── Block device I/O ─────────────────────────────────────────────────────────

enum DataSource {
    Mmap(memmap2::Mmap),
    Buf(Vec<u8>),
}

impl DataSource {
    fn as_bytes(&self) -> &[u8] {
        match self {
            DataSource::Mmap(m) => m,
            DataSource::Buf(v) => v,
        }
    }
}

// Read `len` bytes from `file` at `offset` into `buf[..len]`, zero-filling any
// sectors that return EIO (bad sector). Returns the number of bad 512-byte sectors.
// `degraded_delay_us`: if > 0, sleep this many microseconds between sector reads when
//   any bad sector has been seen. Slows head movement on mechanically failing drives to
//   reduce the risk of accelerating head degradation.
// `bad_offsets`: if Some, appended with the absolute byte offset of each bad sector.
#[cfg(unix)]
fn read_chunk_resilient(
    file: &File,
    buf: &mut [u8],
    offset: u64,
    degraded_delay_us: u64,
    mut bad_offsets: Option<&mut Vec<u64>>,
) -> u64 {
    use std::os::unix::fs::FileExt;
    use std::time::Duration;
    const SECTOR: usize = 512;
    const BAD_TRIGGER: u64 = 3; // start delaying after this many bad sectors total
    const MAX_TRACK: usize = 1000; // cap offset list at 1000 entries
    let size = buf.len();
    let mut bad = 0u64;
    let mut off = 0usize;
    while off < size {
        let end = (off + SECTOR).min(size);
        let slice = &mut buf[off..end];
        match file.read_at(slice, offset + off as u64) {
            Ok(n) => {
                for b in &mut slice[n..] {
                    *b = 0;
                }
            }
            Err(_) => {
                bad += 1;
                slice.fill(0);
                if let Some(ref mut v) = bad_offsets {
                    if v.len() < MAX_TRACK {
                        v.push(offset + off as u64);
                    }
                }
            }
        }
        if degraded_delay_us > 0 && bad >= BAD_TRIGGER {
            std::thread::sleep(Duration::from_micros(degraded_delay_us));
        }
        off = end;
    }
    bad
}

// Scan a block device in overlapping chunks, carving each window and deduplicating
// findings globally via CarveState.  Avoids the O(device_size) RAM allocation of
// reading the whole device into a Vec<u8>.
//
// CHUNK: how many bytes to process per window.
// OVERLAP: how far back the next window starts — must be >= max realistic file size
//          we expect to find intact, so a file starting near a chunk boundary is
//          fully captured in the following chunk.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn carve_device(
    file: &File,
    size: usize,
    outdir: &Path,
    sigs: &[DynSig],
    quiet: bool,
    emit_meta: bool,
    max_override: Option<usize>,
    frag_gap: usize,
    state_path: Option<&Path>,
    src_path: &str,
    degraded_delay_us: u64,
    align_bytes: usize,
    state: &mut CarveState,
) -> Result<(Vec<Finding>, u64)> {
    const CHUNK: usize = 256 * MB;
    const OVERLAP: usize = 64 * MB;

    let mut all_findings = Vec::new();
    let mut total_bad = 0u64;
    let mut buf = vec![0u8; CHUNK.min(size)];
    // Resume: start from last completed chunk if state says so.
    let mut chunk_start = state.completed_chunks * (CHUNK - OVERLAP);

    while chunk_start < size && !state.limit_reached() {
        let chunk_end = (chunk_start + CHUNK).min(size);
        let window_size = chunk_end - chunk_start;

        if buf.len() != window_size {
            buf.resize(window_size, 0);
        }
        let prev_bad = total_bad;
        total_bad += read_chunk_resilient(
            file,
            &mut buf,
            chunk_start as u64,
            degraded_delay_us,
            Some(&mut state.bad_sector_offsets),
        );
        if !quiet && prev_bad == 0 && total_bad > 0 {
            eprintln!("pala: WARNING — first bad sector at chunk offset 0x{chunk_start:08x}");
            if degraded_delay_us == 0 {
                eprintln!("pala:          consider --degraded=1 to slow reads on a failing drive");
            }
        }

        // Only emit findings whose start falls in the non-overlap prefix of this chunk.
        // Findings starting in [chunk_start + CHUNK - OVERLAP, chunk_end) will be
        // re-found in the next chunk where they are fully within the window — unless
        // this is the last chunk, in which we emit everything.
        let emit_end = if chunk_end < size {
            chunk_start + CHUNK.saturating_sub(OVERLAP)
        } else {
            size
        };

        // carve() deduplicates via state.seen (global offsets), so any finding already
        // emitted from a previous chunk is silently skipped here.
        let findings = carve(
            &buf[..window_size],
            chunk_start,
            outdir,
            sigs,
            quiet,
            emit_meta,
            max_override,
            frag_gap,
            align_bytes,
            Some(emit_end),
            state,
        )?;
        all_findings.extend(findings);

        state.completed_chunks += 1;

        if !quiet {
            let pct = chunk_end * 100 / size;
            eprintln!(
                "pala: progress — {}%  {}  of  {}  ({} found)",
                pct,
                human_size(chunk_end),
                human_size(size),
                state.findings_so_far
            );
            eprintln!();
        }

        // Checkpoint: write state after each chunk so a crashed run can resume here.
        // state.completed_chunks was just incremented above to N+1; storing it directly
        // avoids the off-by-one from reconstructing it via last_chunk_start / stride.
        if let Some(sp) = state_path {
            write_checkpoint(sp, src_path, size as u64, state)?;
        }

        if chunk_end == size {
            break;
        }
        chunk_start += CHUNK - OVERLAP;
    }

    Ok((all_findings, total_bad))
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
fn carve_device(
    file: &File,
    size: usize,
    outdir: &Path,
    sigs: &[DynSig],
    quiet: bool,
    emit_meta: bool,
    max_override: Option<usize>,
    frag_gap: usize,
    state_path: Option<&Path>,
    src_path: &str,
    degraded_delay_us: u64,
    align_bytes: usize,
    state: &mut CarveState,
) -> Result<(Vec<Finding>, u64)> {
    let _ = (
        file,
        size,
        outdir,
        sigs,
        quiet,
        emit_meta,
        max_override,
        frag_gap,
        state_path,
        src_path,
        degraded_delay_us,
        align_bytes,
        state,
    );
    anyhow::bail!("raw block-device recovery is supported only on Unix")
}

// ─── NTFS cluster-run stage 2 ────────────────────────────────────────────────
//
// For each ntfs_mft finding produced by the sig scan, reads the carved 1024-byte
// MFT entry from disk, parses the non-resident $DATA attribute run list, and
// assembles the file content by reading those clusters directly from `src`.
// SHA256-deduplicates against state.seen_sha256 so files the sig scan already
// found by signature are not written a second time.
// Only runs on the mmap (file) path — block-device callers pass an empty
// findings slice.

#[allow(clippy::too_many_arguments)]
fn carve_mft_stage2(
    src: &[u8],
    findings: &[Finding],
    cluster_size: u64,
    outdir: &Path,
    sigs: &[DynSig],
    quiet: bool,
    emit_meta: bool,
    state: &mut CarveState,
) -> Result<Vec<Finding>> {
    const CAP: usize = 500 * 1024 * 1024; // 500 MB ceiling per assembled file

    let mft_iter: Vec<&Finding> = findings.iter().filter(|f| f.name == "ntfs_mft").collect();
    if mft_iter.is_empty() {
        return Ok(Vec::new());
    }

    if !quiet {
        eprintln!(
            "pala: NTFS stage-2 — {} MFT entry(ies), cluster_size={} bytes",
            mft_iter.len(),
            cluster_size
        );
        eprintln!();
    }

    let mut out = Vec::new();

    // MFT record size is 1024 bytes in standard NTFS.  The sig scan carves
    // contiguous blocks of records (because the MFT is a single flat file),
    // so each carved .mft file may contain many records.  We iterate them.
    const MFT_REC: usize = 1024;

    for mft_f in mft_iter {
        let chunk = match fs::read(&mft_f.path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let mut rec_off = 0usize;
        while rec_off + MFT_REC <= chunk.len() && !state.limit_reached() {
            let entry = &chunk[rec_off..rec_off + MFT_REC];
            let entry_base_off = mft_f.offset + rec_off;
            rec_off += MFT_REC;

            if &entry[0..4] != b"FILE" {
                continue;
            }

            let info = match mft_run_info(entry) {
                Some(i) => i,
                None => continue,
            };

            let limit = (info.data_size as usize).min(CAP);
            let mut assembled: Vec<u8> = Vec::with_capacity(limit);

            for (lcn, run_len) in &info.runs {
                if assembled.len() >= limit {
                    break;
                }
                let byte_start = (*lcn as usize).saturating_mul(cluster_size as usize);
                let byte_len = (*run_len as usize).saturating_mul(cluster_size as usize);
                if byte_start >= src.len() {
                    continue;
                }
                let take = (limit - assembled.len()).min(byte_len);
                let slice = &src[byte_start..(byte_start + take).min(src.len())];
                assembled.extend_from_slice(slice);
            }

            if assembled.len() > limit {
                assembled.truncate(limit);
            }
            if assembled.is_empty() || state.below_min_size(assembled.len()) {
                continue;
            }

            let mut h = Sha256::new();
            h.update(&assembled);
            let sha = format!("{:x}", h.finalize());
            if state.seen_sha256.contains(&sha) {
                continue;
            }
            state.seen_sha256.insert(sha.clone());

            // Type detection: magic match first; fall back to filename extension hint
            let (ext, name, desc, special) = if let Some(sig) = detect_sig(&assembled, sigs) {
                (
                    sig.ext.as_str(),
                    sig.name.as_str(),
                    sig.desc.as_str(),
                    sig.special,
                )
            } else {
                let e = info
                    .name_hint
                    .as_deref()
                    .and_then(|n| std::path::Path::new(n).extension())
                    .and_then(|x| x.to_str())
                    .unwrap_or("dat");
                (e, "unknown", "NTFS cluster-run extracted", Special::None)
            };

            let n = {
                let cnt = state
                    .ctr
                    .entry(ext.to_string())
                    .and_modify(|x| *x += 1)
                    .or_insert(1);
                *cnt
            };
            let fname = format!("{ext}_{n:04}.{ext}");
            let out_path = outdir.join(&fname);
            write_new(&out_path, &assembled)
                .with_context(|| format!("writing {}", out_path.display()))?;

            let meta = if emit_meta {
                extract_meta(&assembled, special)
            } else {
                None
            };

            if !quiet {
                let hint = info.name_hint.as_deref().unwrap_or("(no name)");
                eprintln!(
                    "         {ext:<5}  {:>8}  mft@{:08x}  {} run(s)  [{hint}]  {fname}",
                    human_size(assembled.len()),
                    entry_base_off,
                    info.runs.len()
                );
            }

            out.push(Finding {
                offset: entry_base_off,
                name: name.to_string(),
                ext: ext.to_string(),
                desc: desc.to_string(),
                size: assembled.len(),
                path: out_path,
                trunc: assembled.len() < info.data_size as usize,
                quality: Quality::Fragmented,
                sha256: sha,
                has_bad_sectors: false,
                meta,
                source: Some(format!("mft:{:08x}", entry_base_off)),
            });
            state.record_finding();
        } // while rec_off
    } // for mft_f

    if !quiet && !out.is_empty() {
        eprintln!(
            "pala: NTFS stage-2 — {} file(s) extracted from cluster runs",
            out.len()
        );
        eprintln!();
    }

    Ok(out)
}

// ─── Filesystem-assisted recovery ────────────────────────────────────────────
//
// Uses The Sleuth Kit (fls + icat) to enumerate deleted inodes and extract
// their content directly — bypassing the signature scan for files the inode
// table still describes.  Runs BEFORE the sig scan; the sig scan then
// deduplicates against SHA256s populated here so recovered files are not
// written twice.

fn fls_deleted(src: &str, fs_type: &str) -> Result<Vec<(u64, String)>> {
    let mut cmd = std::process::Command::new("fls");
    if fs_type != "auto" {
        cmd.args(["-f", fs_type]);
    }
    cmd.args(["-rd", src]);
    let output = cmd.output().context("fls (sleuthkit) not found")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();
    for line in text.lines() {
        if !line.starts_with("r/r * ") {
            continue;
        }
        if line.contains("(realloc)") {
            continue;
        } // inode reused — data gone
        let rest = &line["r/r * ".len()..];
        let colon = rest.find(':').unwrap_or(0);
        if colon == 0 {
            continue;
        }
        let inum: u64 = match rest[..colon].trim().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let name = rest.get(colon + 1..).unwrap_or("").trim().to_string();
        result.push((inum, name));
    }
    Ok(result)
}

fn icat_read(src: &str, fs_type: &str, inum: u64) -> Result<Vec<u8>> {
    let mut cmd = std::process::Command::new("icat");
    if fs_type != "auto" {
        cmd.args(["-f", fs_type]);
    }
    cmd.arg(src).arg(inum.to_string());
    let output = cmd.output().context("icat (sleuthkit) not found")?;
    if output.stdout.is_empty() {
        anyhow::bail!("icat: empty output for inode {inum}");
    }
    Ok(output.stdout)
}

// Match data against the sig table by checking magic bytes at the declared offset.
fn detect_sig<'a>(data: &[u8], sigs: &'a [DynSig]) -> Option<&'a DynSig> {
    for sig in sigs {
        let end = sig.moff.saturating_add(sig.magic.len());
        if data.len() >= end && &data[sig.moff..end] == sig.magic.as_slice() {
            return Some(sig);
        }
    }
    None
}

// ─── Entropy classification ──────────────────────────────────────────────────

// Shannon entropy of a byte slice: 0.0 = uniform single byte, 8.0 = all 256 equally likely.
fn sector_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

// Pre-scan entropy survey: returns (zero_sectors, high_entropy_sectors, total_sectors).
// zero = H < 0.1 (all-zero or nearly so); high = H > 7.5 (compressed/encrypted/random).
fn entropy_survey(src: &[u8]) -> (u64, u64, u64) {
    const SECTOR: usize = 512;
    let mut zero = 0u64;
    let mut high = 0u64;
    let mut total = 0u64;
    for chunk in src.chunks(SECTOR) {
        let h = sector_entropy(chunk);
        if h < 0.1 {
            zero += 1;
        } else if h > 7.5 {
            high += 1;
        }
        total += 1;
    }
    (zero, high, total)
}

// ─── FAT32 cluster-chain stage 2 ─────────────────────────────────────────────
//
// Derives FAT32 volume parameters from a carved FSINFO finding's source offset,
// scans the root directory for deleted entries (0xE5 first byte), and follows
// cluster chains to assemble file content.  For deleted files whose FAT chain
// was cleared, predicts contiguous cluster runs (cluster N+1 follows N) as a
// fallback — correct for unfragmented volumes, which are the common case.

struct Fat32Params {
    partition_start: usize,
    fat_offset: usize, // byte offset of FAT1 in src
    data_start: usize, // byte offset of first data cluster in src
    cluster_size: usize,
    root_cluster: u32,
    bps: usize,
}

fn fat32_params(src: &[u8], partition_start: usize) -> Option<Fat32Params> {
    if partition_start + 512 > src.len() {
        return None;
    }
    let bs = &src[partition_start..partition_start + 512];
    // Validate FAT32: "FAT32   " at offset 0x52, root_entry_count=0, fat_size_16=0
    if &bs[0x52..0x5A] != b"FAT32   " {
        return None;
    }
    let root_entry_count = u16::from_le_bytes([bs[0x11], bs[0x12]]);
    let fat_size_16 = u16::from_le_bytes([bs[0x16], bs[0x17]]);
    if root_entry_count != 0 || fat_size_16 != 0 {
        return None;
    }

    let bps = u16::from_le_bytes([bs[0x0B], bs[0x0C]]) as usize;
    let spc = bs[0x0D] as usize;
    let rsc = u16::from_le_bytes([bs[0x0E], bs[0x0F]]) as usize;
    let num_fats = bs[0x10] as usize;
    let fat32_sz = u32::from_le_bytes(bs[0x24..0x28].try_into().unwrap_or([0; 4])) as usize;
    let root_clus = u32::from_le_bytes(bs[0x2C..0x30].try_into().unwrap_or([0; 4]));

    if bps == 0 || spc == 0 || rsc == 0 || fat32_sz == 0 || root_clus < 2 {
        return None;
    }

    let fat_offset = partition_start + rsc * bps;
    let data_start = partition_start + (rsc + num_fats * fat32_sz) * bps;
    let cluster_size = spc * bps;

    Some(Fat32Params {
        partition_start,
        fat_offset,
        data_start,
        cluster_size,
        root_cluster: root_clus,
        bps,
    })
}

fn fat32_cluster_offset(params: &Fat32Params, cluster: u32) -> usize {
    params.data_start + (cluster as usize - 2) * params.cluster_size
}

// Follow FAT32 cluster chain; returns the next cluster or None (end-of-chain / free).
fn fat32_next_cluster(src: &[u8], params: &Fat32Params, cluster: u32) -> Option<u32> {
    let off = params.fat_offset + cluster as usize * 4;
    if off + 4 > src.len() {
        return None;
    }
    let next = u32::from_le_bytes(src[off..off + 4].try_into().unwrap_or([0; 4])) & 0x0FFF_FFFF;
    if (2..0x0FFF_FFF8).contains(&next) {
        Some(next)
    } else {
        None
    }
}

// Assemble file bytes by following the cluster chain, with contiguous-cluster
// prediction fallback when FAT entries are cleared (deleted file recovery).
// Returns (data, quality): Fragmented when prediction was used, Partial when
// truncated before size, Complete when the FAT chain was intact end-to-end.
fn fat32_read_file(
    src: &[u8],
    params: &Fat32Params,
    first_cluster: u32,
    size: usize,
) -> (Vec<u8>, Quality) {
    let clusters_needed = size.div_ceil(params.cluster_size);
    let mut data = Vec::with_capacity(size);
    let mut cur = first_cluster;
    let mut predicted = false;

    for _ in 0..clusters_needed {
        if cur < 2 {
            return (data, Quality::Partial);
        }
        let off = fat32_cluster_offset(params, cur);
        if off + params.cluster_size > src.len() {
            return (data, Quality::Partial);
        }
        let take = params.cluster_size.min(size - data.len());
        data.extend_from_slice(&src[off..off + take]);
        if data.len() >= size {
            break;
        }

        match fat32_next_cluster(src, params, cur) {
            Some(next) => cur = next,
            None => {
                predicted = true;
                cur += 1;
            }
        }
    }

    if data.len() < size {
        (data, Quality::Partial)
    } else if predicted {
        (data, Quality::Fragmented)
    } else {
        (data, Quality::Complete)
    }
}

struct Fat32DirEnt {
    name: String,
    first_cluster: u32,
    size: u32,
}

fn fat32_83name(e: &[u8]) -> String {
    let first = if e[0] == 0xE5 { b'?' } else { e[0] };
    let name_iter = std::iter::once(first).chain(e[1..8].iter().copied());
    let name_part: String = name_iter
        .map(|b| b as char)
        .take_while(|c| *c != ' ')
        .collect();
    let ext_part: String = e[8..11]
        .iter()
        .map(|&b| b as char)
        .take_while(|c| *c != ' ')
        .collect();
    if ext_part.is_empty() {
        name_part
    } else {
        format!("{name_part}.{ext_part}")
    }
}

// Walk ALL directories on a FAT32 partition (BFS) for deleted file entries.
// The original root-only scan missed nearly every real file; subdirectory walk is required.
// Active subdirectories are enqueued from live entries; deleted subdirectory clusters are
// also enqueued when the first_cluster field is still legible (FAT entry may be cleared).
fn fat32_deleted_entries(src: &[u8], params: &Fat32Params, start_cluster: u32) -> Vec<Fat32DirEnt> {
    let mut out = Vec::new();
    let mut visited_dirs: std::collections::HashSet<u32> = Default::default();
    let mut dir_queue: Vec<u32> = vec![start_cluster];
    const MAX_DIRS: usize = 50_000;

    while let Some(dir_cluster) = dir_queue.pop() {
        if out.len() + dir_queue.len() > 500_000 {
            break;
        }
        if visited_dirs.len() >= MAX_DIRS {
            break;
        }
        if !visited_dirs.insert(dir_cluster) {
            continue;
        }

        let mut cur = dir_cluster;
        let mut chain_vis: std::collections::HashSet<u32> = Default::default();

        loop {
            if !chain_vis.insert(cur) {
                break;
            }
            let off = fat32_cluster_offset(params, cur);
            if off + params.cluster_size > src.len() {
                break;
            }
            let dir_data = &src[off..off + params.cluster_size];

            for i in 0..(params.cluster_size / 32) {
                let e = &dir_data[i * 32..(i + 1) * 32];
                if e[0] == 0x00 {
                    break;
                } // end-of-directory
                if e[11] == 0x0F {
                    continue;
                } // LFN entry
                if e[11] & 0x08 != 0 {
                    continue;
                } // volume label

                let hi = u16::from_le_bytes([e[20], e[21]]) as u32;
                let lo = u16::from_le_bytes([e[26], e[27]]) as u32;
                let fc = (hi << 16) | lo;

                if e[11] & 0x10 != 0 {
                    // Subdirectory (active or deleted); skip . and ..
                    if e[0] == b'.' {
                        continue;
                    }
                    if fc >= 2 && !visited_dirs.contains(&fc) {
                        dir_queue.push(fc);
                    }
                    continue;
                }

                if e[0] != 0xE5 {
                    continue;
                } // only deleted files

                let sz = u32::from_le_bytes(e[28..32].try_into().unwrap_or([0; 4]));
                if fc >= 2 && sz > 0 {
                    out.push(Fat32DirEnt {
                        name: fat32_83name(e),
                        first_cluster: fc,
                        size: sz,
                    });
                }
            }

            match fat32_next_cluster(src, params, cur) {
                Some(next) => cur = next,
                None => break,
            }
        }
    }
    out
}

fn carve_fat32_stage2(
    src: &[u8],
    findings: &[Finding],
    outdir: &Path,
    sigs: &[DynSig],
    quiet: bool,
    emit_meta: bool,
    state: &mut CarveState,
) -> Result<Vec<Finding>> {
    // Collect unique partition_start offsets from carved fat32_fsinfo findings.
    // FSINFO is at sector 1 of the FAT32 partition; boot sector is one BPS earlier.
    // Attempt BPS=512 (almost universal); skip if the boot sector fails validation.
    let fsinfo_offsets: Vec<usize> = findings
        .iter()
        .filter(|f| f.name == "fat32_fsinfo")
        .map(|f| f.offset)
        .collect();

    if fsinfo_offsets.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut seen_partitions: std::collections::HashSet<usize> = Default::default();

    for fsinfo_off in fsinfo_offsets {
        // Boot sector is typically one 512-byte sector before FSINFO
        let partition_start = match fsinfo_off.checked_sub(512) {
            Some(s) => s,
            None => continue,
        };
        if !seen_partitions.insert(partition_start) {
            continue;
        }

        let params = match fat32_params(src, partition_start) {
            Some(p) => p,
            None => continue,
        };

        if !quiet {
            eprintln!(
                "pala: FAT32 stage-2 — partition@{:08x} cluster={}B root_clus={}",
                partition_start, params.cluster_size, params.root_cluster
            );
            eprintln!();
        }

        let deleted = fat32_deleted_entries(src, &params, params.root_cluster);
        if !quiet && !deleted.is_empty() {
            eprintln!(
                "pala: FAT32 stage-2 — {} deleted entry(ies) in root directory",
                deleted.len()
            );
        }

        for entry in deleted {
            if state.limit_reached() {
                break;
            }
            let (data, fat32_quality) =
                fat32_read_file(src, &params, entry.first_cluster, entry.size as usize);
            if data.is_empty() || state.below_min_size(data.len()) {
                continue;
            }

            let mut h = Sha256::new();
            h.update(&data);
            let sha = format!("{:x}", h.finalize());
            if state.seen_sha256.contains(&sha) {
                continue;
            }
            state.seen_sha256.insert(sha.clone());

            // Type detection: magic first, then 8.3 extension hint
            let (ext, name, desc, special) = if let Some(sig) = detect_sig(&data, sigs) {
                (
                    sig.ext.as_str(),
                    sig.name.as_str(),
                    sig.desc.as_str(),
                    sig.special,
                )
            } else {
                let e = std::path::Path::new(&entry.name)
                    .extension()
                    .and_then(|x| x.to_str())
                    .unwrap_or("dat");
                (e, "unknown", "FAT32 cluster-chain extracted", Special::None)
            };

            let n = {
                let cnt = state
                    .ctr
                    .entry(ext.to_string())
                    .and_modify(|x| *x += 1)
                    .or_insert(1);
                *cnt
            };
            let fname = format!("{ext}_{n:04}.{ext}");
            let out_path = outdir.join(&fname);
            write_new(&out_path, &data)
                .with_context(|| format!("writing {}", out_path.display()))?;

            let meta = if emit_meta {
                extract_meta(&data, special)
            } else {
                None
            };
            let trunc = matches!(fat32_quality, Quality::Partial);

            if !quiet {
                let quality_mark = match fat32_quality {
                    Quality::Partial => " [trunc]",
                    Quality::Fragmented => " [frag]",
                    Quality::Complete => "",
                };
                eprintln!(
                    "         {ext:<5}  {:>8}  fat32  [{name_hint}]{quality_mark}  {fname}",
                    human_size(data.len()),
                    name_hint = entry.name
                );
            }

            out.push(Finding {
                offset: partition_start,
                name: name.to_string(),
                ext: ext.to_string(),
                desc: desc.to_string(),
                size: data.len(),
                path: out_path,
                trunc,
                quality: fat32_quality,
                sha256: sha,
                has_bad_sectors: false,
                meta,
                source: Some(format!("fat32:{:08x}", partition_start)),
            });
            state.record_finding();
        }
    }

    if !quiet && !out.is_empty() {
        eprintln!(
            "pala: FAT32 stage-2 — {} file(s) recovered from cluster chains",
            out.len()
        );
        eprintln!();
    }

    Ok(out)
}

// ─── ZIP container depth ─────────────────────────────────────────────────────
//
// For each carved ZIP/DOCX/XLSX/PPTX finding, open as a zip::ZipArchive and
// extract member files.  SHA256-deduplicates so members already found by the
// sig scan or other phases are not written twice.  Writes member files with
// source="zip:{source_offset}:{member_name}" in the JSON output.

const MAX_ZIP_MEMBERS: usize = 10_000;
const DEFAULT_ZIP_MEMBER_LIMIT: usize = 500 * MB;
const ZIP_TOTAL_LIMIT: usize = GB;

#[allow(clippy::too_many_arguments)]
fn unpack_zip_finding(
    finding: &Finding,
    outdir: &Path,
    sigs: &[DynSig],
    quiet: bool,
    emit_meta: bool,
    max_override: Option<usize>,
    total_extracted: &mut usize,
    state: &mut CarveState,
) -> Result<Vec<Finding>> {
    use std::io::Read as _;

    let raw = match fs::read(&finding.path) {
        Ok(b) => b,
        Err(_) => return Ok(Vec::new()),
    };
    let cursor = std::io::Cursor::new(&raw);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
    let mut skipped = 0usize;
    let member_count = archive.len();
    let member_limit = max_override.unwrap_or(DEFAULT_ZIP_MEMBER_LIMIT);

    for idx in 0..member_count.min(MAX_ZIP_MEMBERS) {
        if state.limit_reached() || *total_extracted >= ZIP_TOTAL_LIMIT {
            break;
        }
        let mut zf = match archive.by_index(idx) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if zf.is_dir() {
            continue;
        }

        let remaining = ZIP_TOTAL_LIMIT - *total_extracted;
        let limit = member_limit.min(remaining);
        if zf.size() > limit as u64 {
            skipped += 1;
            continue;
        }

        let member_name = match zf.name() {
            Ok(name) => name.into_owned(),
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let mut data = Vec::with_capacity((zf.size() as usize).min(8 * MB));
        let read_limit = (limit as u64).saturating_add(1);
        if zf.by_ref().take(read_limit).read_to_end(&mut data).is_err() || data.len() > limit {
            skipped += 1;
            continue;
        }
        if data.is_empty() || state.below_min_size(data.len()) {
            continue;
        }

        let mut h = Sha256::new();
        h.update(&data);
        let sha = format!("{:x}", h.finalize());
        if state.seen_sha256.contains(&sha) {
            continue;
        }
        state.seen_sha256.insert(sha.clone());

        let (ext, name, desc, special) = if let Some(sig) = detect_sig(&data, sigs) {
            (
                sig.ext.as_str(),
                sig.name.as_str(),
                sig.desc.as_str(),
                sig.special,
            )
        } else {
            let e = std::path::Path::new(&member_name)
                .extension()
                .and_then(|x| x.to_str())
                .unwrap_or("dat");
            (e, "unknown", "ZIP member extracted", Special::None)
        };

        let n = {
            let cnt = state
                .ctr
                .entry(ext.to_string())
                .and_modify(|x| *x += 1)
                .or_insert(1);
            *cnt
        };
        let fname = format!("{ext}_{n:04}.{ext}");
        let out_path = outdir.join(&fname);
        write_new(&out_path, &data).with_context(|| format!("writing {}", out_path.display()))?;
        *total_extracted += data.len();

        let meta = if emit_meta {
            extract_meta(&data, special)
        } else {
            None
        };

        if !quiet {
            eprintln!(
                "         {ext:<5}  {:>8}  zip@{:08x}  [{member_name}]  {fname}",
                human_size(data.len()),
                finding.offset
            );
        }

        out.push(Finding {
            offset: finding.offset,
            name: name.to_string(),
            ext: ext.to_string(),
            desc: desc.to_string(),
            size: data.len(),
            path: out_path,
            trunc: false,
            quality: Quality::Complete,
            sha256: sha,
            has_bad_sectors: false,
            meta,
            source: Some(format!("zip:{:08x}:{member_name}", finding.offset)),
        });
        state.record_finding();
    }

    skipped += member_count.saturating_sub(MAX_ZIP_MEMBERS);
    if !quiet && skipped > 0 {
        eprintln!("pala: ZIP depth — skipped {skipped} member(s) exceeding resource limits");
    }
    Ok(out)
}

fn carve_zip_members(
    findings: &[Finding],
    outdir: &Path,
    sigs: &[DynSig],
    quiet: bool,
    emit_meta: bool,
    max_override: Option<usize>,
    state: &mut CarveState,
) -> Result<Vec<Finding>> {
    // Expand ZIP/DOCX/XLSX/PPTX findings.  Depth = 1 to avoid recursive explosion.
    let zip_exts: std::collections::HashSet<&str> = ["zip", "docx", "xlsx", "pptx", "jar", "apk"]
        .iter()
        .copied()
        .collect();
    let candidates: Vec<&Finding> = findings
        .iter()
        .filter(|f| zip_exts.contains(f.ext.as_str()))
        .collect();

    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    if !quiet {
        eprintln!(
            "pala: ZIP depth — expanding {} container(s)",
            candidates.len()
        );
        eprintln!();
    }

    let mut out = Vec::new();
    let mut total_extracted = 0usize;
    for f in candidates {
        if state.limit_reached() || total_extracted >= ZIP_TOTAL_LIMIT {
            break;
        }
        let members = unpack_zip_finding(
            f,
            outdir,
            sigs,
            quiet,
            emit_meta,
            max_override,
            &mut total_extracted,
            state,
        )?;
        out.extend(members);
    }

    if !quiet && !out.is_empty() {
        eprintln!("pala: ZIP depth — {} member file(s) extracted", out.len());
        eprintln!();
    }

    Ok(out)
}

fn carve_inode_phase(
    src_path: &str,
    fs_type: &str,
    outdir: &Path,
    quiet: bool,
    emit_meta: bool,
    state: &mut CarveState,
    sigs: &[DynSig],
) -> Result<Vec<Finding>> {
    // Probe TSK without side effects; io::NotFound → clean warning + fallback.
    if let Err(e) = std::process::Command::new("fls").output() {
        if e.kind() == std::io::ErrorKind::NotFound {
            eprintln!("pala: --filesystem: fls not found — install the sleuthkit package");
            eprintln!("pala: falling back to signature-only scan");
            eprintln!();
        }
        return Ok(Vec::new());
    }

    let deleted = match fls_deleted(src_path, fs_type) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pala: --filesystem: fls failed: {e}");
            return Ok(Vec::new());
        }
    };

    if !quiet {
        eprintln!(
            "pala: inode phase — {} deleted inode(s) queued",
            deleted.len()
        );
    }

    let mut out = Vec::new();
    for (inum, name_hint) in &deleted {
        if state.limit_reached() {
            break;
        }
        let data = match icat_read(src_path, fs_type, *inum) {
            Ok(d) if !d.is_empty() && !state.below_min_size(d.len()) => d,
            _ => continue,
        };

        let mut h = Sha256::new();
        h.update(&data);
        let sha = format!("{:x}", h.finalize());

        if state.seen_sha256.contains(&sha) {
            continue;
        }
        state.seen_sha256.insert(sha.clone());

        let (ext, name, desc, special) = if let Some(sig) = detect_sig(&data, sigs) {
            (
                sig.ext.as_str(),
                sig.name.as_str(),
                sig.desc.as_str(),
                sig.special,
            )
        } else {
            let e = std::path::Path::new(name_hint.as_str())
                .extension()
                .and_then(|x| x.to_str())
                .unwrap_or("dat");
            (e, "unknown", "Unknown (inode-recovered)", Special::None)
        };

        let n = {
            let cnt = state
                .ctr
                .entry(ext.to_string())
                .and_modify(|x| *x += 1)
                .or_insert(1);
            *cnt
        };
        let fname = format!("{ext}_{n:04}.{ext}");
        let out_path = outdir.join(&fname);
        write_new(&out_path, &data).with_context(|| format!("writing {}", out_path.display()))?;

        let meta = if emit_meta {
            extract_meta(&data, special)
        } else {
            None
        };

        if !quiet {
            eprintln!(
                "         {ext:<5}  {:>8}  inode:{inum}  {fname}",
                human_size(data.len())
            );
        }

        out.push(Finding {
            offset: 0,
            name: name.to_string(),
            ext: ext.to_string(),
            desc: desc.to_string(),
            size: data.len(),
            path: out_path,
            trunc: false,
            quality: Quality::Complete,
            sha256: sha,
            has_bad_sectors: false,
            meta,
            source: Some(format!("inode:{inum}")),
        });
        state.record_finding();
    }

    if !quiet && !out.is_empty() {
        eprintln!("pala: inode phase — {} file(s) recovered", out.len());
        eprintln!();
    }
    Ok(out)
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

fn usage() {
    eprintln!(
        "pala {} — filesystem-agnostic file carver\n",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("Usage:  pala <source> <outdir> [OPTIONS]\n");
    eprintln!("Arguments:");
    eprintln!("  source    Disk image file or raw block device to scan (read-only)");
    eprintln!(
        "  outdir    Empty directory for recovered files; use another drive for raw devices\n"
    );
    eprintln!("Options:");
    eprintln!("  -t, --types <csv>       File types to recover (default: all)");
    eprintln!("  -c, --corpus <path>     Load extra signatures from a PALA corpus file");
    eprintln!("  -l, --list              List available types and exit");
    eprintln!("  -q, --quiet             Suppress progress output (use with --json)");
    eprintln!("      --json              Write structured JSON summary to stdout");
    eprintln!("      --meta              Include supported metadata in JSON output");
    eprintln!("      --min-size <bytes>  Skip recovered files smaller than this global minimum");
    eprintln!("      --max-size <bytes>  Override the per-signature maximum carve window");
    eprintln!("  -n, --count <n>         Stop after recovering N files in this run");
    eprintln!("      --resume            Resume from outdir/.pala-state.json");
    eprintln!("      --degraded[=ms]     Delay reads after bad sectors (default: 1ms)");
    eprintln!("      --filesystem <fs>   Sleuth Kit deleted-inode recovery: auto, ext2/3/4,");
    eprintln!("                          ntfs, apfs, fat12/16/32, hfs, ufs1/2 (requires fls/icat)");
    eprintln!("      --align <bytes>     Require signature starts to be multiples of N");
    eprintln!("      --triage-mode <m>   Type preset: media, documents, executables, archives,");
    eprintln!("                          email, memory, filesystem, windows, databases, firmware, forensic");
    eprintln!("      --skip-high-entropy Skip findings starting in sectors with entropy > 7.5");
    eprintln!("      --container-depth   Extract ZIP/DOCX/XLSX/PPTX members with resource limits");
    eprintln!("      --frag-gap <bytes>  Allow zero-filled gaps between fragments (default: 0)");
    eprintln!("      --no-fat32-stage2   Disable FAT32 deleted-entry recovery");
    eprintln!(
        "      --allow-same-device Permit output on the source device (unsafe for raw devices)"
    );
    eprintln!("  -V, --version           Print version and exit");
    eprintln!("  -h, --help              Show this help\n");
    eprintln!("Examples:");
    eprintln!("  pala disk.img /mnt/usb/recovered/");
    eprintln!("  pala /dev/sdb /mnt/usb/recovered/ -t jpeg,png,pdf");
    eprintln!("  pala disk.img out/ --json | jq '.findings[] | {{ext,size}}'");
    eprintln!("  pala disk.img out/ -c custom.pala");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut src: Option<String> = None;
    let mut out: Option<String> = None;
    let mut types: Option<Vec<String>> = None;
    let mut corpus_path: Option<String> = None;
    let mut quiet = false;
    let mut json = false;
    let mut list = false;
    let mut emit_meta = false;
    let mut min_override: Option<usize> = None;
    let mut max_override: Option<usize> = None;
    let mut finding_limit: Option<usize> = None;
    let mut resume = false;
    let mut allow_same_device = false;
    let mut degraded_ms: u64 = 0; // inter-sector delay when bad sectors appear; 0 = disabled
    let mut frag_gap: usize = 0; // gap-tolerant frag merge limit (bytes); 0 = exact-contiguous only
    let mut triage_mode: Option<String> = None;
    let mut filesystem: Option<String> = None; // --filesystem: TSK-assisted inode-map phase
    let mut skip_high_entropy = false; // --skip-high-entropy: skip high-H start sectors
    let mut container_depth = false; // --container-depth: expand ZIP/DOCX/XLSX members
    let mut fat32_stage2 = true; // --no-fat32-stage2 to disable; on by default
    let mut align_bytes: usize = 0; // --align=N: only emit matches at N-byte boundaries

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            "-V" | "--version" => {
                println!("pala {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-l" | "--list" => list = true,
            "-q" | "--quiet" => quiet = true,
            "--json" => json = true,
            "--meta" => emit_meta = true,
            "--resume" => resume = true,
            "--degraded" => {
                // Optional value: if next token is a number consume it, else default to 1ms.
                if i + 1 < args.len() {
                    if let Ok(v) = args[i + 1].parse::<u64>() {
                        i += 1;
                        degraded_ms = v;
                    } else {
                        degraded_ms = 1;
                    }
                } else {
                    degraded_ms = 1;
                }
            }
            a if a.starts_with("--degraded=") => {
                degraded_ms = a[11..]
                    .parse::<u64>()
                    .with_context(|| format!("invalid --degraded: {}", &a[11..]))?;
            }
            "-t" | "--types" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--types requires a value");
                }
                types = Some(args[i].split(',').map(|s| s.trim().to_string()).collect());
            }
            a if a.starts_with("--types=") => {
                types = Some(a[8..].split(',').map(|s| s.trim().to_string()).collect());
            }
            "--min-size" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--min-size requires a value in bytes");
                }
                min_override = Some(
                    args[i]
                        .parse::<usize>()
                        .with_context(|| format!("invalid --min-size: {}", args[i]))?,
                );
            }
            a if a.starts_with("--min-size=") => {
                min_override = Some(
                    a[11..]
                        .parse::<usize>()
                        .with_context(|| format!("invalid --min-size: {}", &a[11..]))?,
                );
            }
            "--max-size" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--max-size requires a value in bytes");
                }
                let value = args[i]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --max-size: {}", args[i]))?;
                if value == 0 {
                    anyhow::bail!("--max-size value must be > 0");
                }
                max_override = Some(value);
            }
            a if a.starts_with("--max-size=") => {
                let value = a[11..]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --max-size: {}", &a[11..]))?;
                if value == 0 {
                    anyhow::bail!("--max-size value must be > 0");
                }
                max_override = Some(value);
            }
            "-n" | "--count" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--count requires a positive integer");
                }
                let value = args[i]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --count: {}", args[i]))?;
                if value == 0 {
                    anyhow::bail!("--count value must be > 0");
                }
                finding_limit = Some(value);
            }
            a if a.starts_with("--count=") => {
                let value = a[8..]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --count: {}", &a[8..]))?;
                if value == 0 {
                    anyhow::bail!("--count value must be > 0");
                }
                finding_limit = Some(value);
            }
            "-c" | "--corpus" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--corpus requires a path");
                }
                corpus_path = Some(args[i].clone());
            }
            a if a.starts_with("--corpus=") => {
                corpus_path = Some(a[9..].to_string());
            }
            "--frag-gap" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--frag-gap requires a value in bytes");
                }
                frag_gap = args[i]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --frag-gap: {}", args[i]))?;
            }
            a if a.starts_with("--frag-gap=") => {
                frag_gap = a[11..]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --frag-gap: {}", &a[11..]))?;
            }
            "--triage-mode" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--triage-mode requires a mode name; run --help for the list");
                }
                triage_mode = Some(args[i].clone());
            }
            a if a.starts_with("--triage-mode=") => {
                triage_mode = Some(a[14..].to_string());
            }
            "--filesystem" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--filesystem requires ext2|ext3|ext4|fat32|ntfs|auto");
                }
                filesystem = Some(args[i].clone());
            }
            a if a.starts_with("--filesystem=") => {
                filesystem = Some(a[13..].to_string());
            }
            "--skip-high-entropy" => skip_high_entropy = true,
            "--container-depth" => container_depth = true,
            "--no-fat32-stage2" => fat32_stage2 = false,
            "--allow-same-device" => allow_same_device = true,
            "--align" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--align requires a value in bytes");
                }
                align_bytes = args[i]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --align: {}", args[i]))?;
                if align_bytes == 0 {
                    anyhow::bail!("--align value must be > 0");
                }
            }
            a if a.starts_with("--align=") => {
                align_bytes = a[8..]
                    .parse::<usize>()
                    .with_context(|| format!("invalid --align: {}", &a[8..]))?;
                if align_bytes == 0 {
                    anyhow::bail!("--align value must be > 0");
                }
            }
            a => {
                if a.starts_with('-') {
                    anyhow::bail!("unknown option: {a}");
                } else if src.is_none() {
                    src = Some(a.to_string());
                } else if out.is_none() {
                    out = Some(a.to_string());
                } else {
                    anyhow::bail!("unexpected argument: {a}");
                }
            }
        }
        i += 1;
    }

    // ── Triage-mode preset expansion ──────────────────────────────────────────
    if let Some(ref mode) = triage_mode {
        let preset: &[&str] = match mode.as_str() {
            "documents" => &["pdf", "rtf", "zip", "ole2"],
            "databases" => &["sqlite", "sqlite_wal", "ese"],
            "media"     => &["jpeg", "png", "gif87a", "gif89a", "bmp", "tiff_le", "tiff_be",
                             "psd", "riff", "mkv", "mp4", "mp3_id3", "flac", "aac",
                             "heic", "heif", "avif", "ogg", "mng", "jng"],
            "executables" => &["elf", "pe", "dex", "art"],
            "archives"  => &["zip", "gz", "7z", "rar", "rar5", "tar", "xz", "bz2", "zstd"],
            "email"     => &["eml"],
            "memory"    => &["lime", "hpak", "pagedump", "pagedu64",
                             "hibr", "hibr_upper", "wake_lower", "wake_upper"],
            "filesystem"=> &["ntfs_mft", "fat32_fsinfo", "ext2_sb", "ufs1_sb", "ufs2_sb", "apfs"],
            "windows"   => &["evtx", "regf", "lnk", "pf", "thumbcache",
                             "hibr", "hibr_upper", "wake_lower", "wake_upper",
                             "pagedump", "pagedu64", "bplist", "mdmp",
                             "usn_rec", "ese"],
            "forensic"  => &["evtx", "regf", "lnk", "pf", "thumbcache",
                             "hibr", "hibr_upper", "wake_lower", "wake_upper",
                             "pagedump", "pagedu64", "mdmp",
                             "ntfs_mft", "fat32_fsinfo", "ext2_sb",
                             "lime", "hpak",
                             "pcap", "pcap_be", "pcapng",
                             "luks", "bitlocker",
                             "usn_rec", "ese"],
            "firmware"  => &["squashfs_le", "squashfs_be", "squashfs_le3", "squashfs_be3",
                             "jffs2_le", "jffs2_be", "ubifs", "uboot", "fit",
                             "cramfs_le", "cramfs_be", "elf"],
            other => anyhow::bail!("unknown --triage-mode: {other}; choose documents|databases|media|executables|archives|email|memory|filesystem|windows|forensic|firmware"),
        };
        let names: Vec<String> = preset.iter().map(|s| s.to_string()).collect();
        types = Some(match types.take() {
            Some(mut t) => {
                t.extend(names);
                t
            }
            None => names,
        });
    }

    // ── Build signature list ───────────────────────────────────────────────────
    let mut all_sigs: Vec<DynSig> = SIGS.iter().map(make_dyn).collect();

    if let Some(ref cp) = corpus_path {
        let bytes = std::fs::read(cp).with_context(|| format!("reading corpus {cp}"))?;
        let extra = corpus::load_corpus(&bytes).with_context(|| format!("parsing corpus {cp}"))?;
        eprintln!("pala: loaded {} extra signature(s) from {cp}", extra.len());
        all_sigs.extend(extra.iter().map(corpus_dyn));
    }

    // ── Filter by type names ───────────────────────────────────────────────────
    let sigs: Vec<DynSig> = if let Some(ref type_names) = types {
        let filtered: Vec<DynSig> = all_sigs
            .into_iter()
            .filter(|s| type_names.iter().any(|n| n == &s.name))
            .collect();
        if filtered.is_empty() {
            anyhow::bail!("no matching types (run `pala --list` to see available types)");
        }
        filtered
    } else {
        all_sigs
    };

    // ── List mode ─────────────────────────────────────────────────────────────
    if list {
        println!("{:<12}  {:<6}  DESCRIPTION", "NAME", "EXT");
        println!("{}", "-".repeat(48));
        for s in &sigs {
            println!("{:<12}  {:<6}  {}", s.name, s.ext, s.desc);
        }
        return Ok(());
    }

    // ── Require source + output ───────────────────────────────────────────────
    let src_path =
        src.ok_or_else(|| anyhow::anyhow!("source path required\n\nRun `pala --help` for usage."))?;
    let out_path = out.ok_or_else(|| {
        anyhow::anyhow!("output directory required\n\nRun `pala --help` for usage.")
    })?;

    let file = File::open(&src_path).with_context(|| format!("opening {src_path}"))?;
    let size = {
        let m = file.metadata()?;
        if m.len() > 0 {
            m.len() as usize
        } else {
            let mut f = File::open(&src_path)?;
            f.seek(SeekFrom::End(0))? as usize
        }
    };
    if size == 0 {
        anyhow::bail!("source is empty");
    }

    if min_override
        .zip(max_override)
        .is_some_and(|(min, max)| min > max)
    {
        anyhow::bail!("--min-size cannot be greater than --max-size");
    }

    let outdir = PathBuf::from(&out_path);
    create_output_dir(&outdir)?;

    #[cfg(unix)]
    let is_blk = {
        use std::os::unix::fs::FileTypeExt;
        file.metadata()
            .map(|m| m.file_type().is_block_device())
            .unwrap_or(false)
    };
    #[cfg(not(unix))]
    let is_blk = false;

    #[cfg(unix)]
    let shares_device = same_device(Path::new(&src_path), &outdir);
    #[cfg(not(unix))]
    let shares_device = false;
    if shares_device {
        if is_blk && !allow_same_device {
            anyhow::bail!(
                "output is on the source block device; choose another drive or explicitly use --allow-same-device"
            );
        }
        eprintln!("WARNING: output directory is on the SAME device as the source.");
        eprintln!("         Recovered output can overwrite deleted data. Use another drive.");
        eprintln!();
    }

    if !resume {
        let has_results = fs::read_dir(&outdir)?
            .filter_map(std::result::Result::ok)
            .any(|entry| {
                let name = entry.file_name();
                name != ".pala-state.json" && name != ".pala-state.json.tmp"
            });
        if has_results {
            anyhow::bail!(
                "output directory is not empty: {out_path}; use an empty directory or --resume"
            );
        }
    }

    if !quiet {
        eprintln!("pala: source  = {src_path} ({})", human_size(size));
        eprintln!("pala: output  = {out_path}");
        eprintln!();
    }

    let state_path = outdir.join(".pala-state.json");

    let mut state = CarveState::new();
    state.skip_high_entropy = skip_high_entropy;
    state.finding_limit = finding_limit;
    state.min_size_override = min_override;

    // Warn if a crashed write left a tmp file; the main state file may be stale.
    let state_tmp = outdir.join(".pala-state.json.tmp");
    if state_tmp.exists() {
        eprintln!("pala: WARNING — .pala-state.json.tmp exists; previous run may have crashed during checkpoint write.");
    }

    // Resume: restore counter + completed-chunk offset from a prior interrupted run.
    if resume {
        match read_checkpoint(&state_path) {
            Some(ps) if ps.source == src_path && ps.source_bytes == size as u64 => {
                state.ctr = ps.ctr;
                state.findings_so_far = ps.findings_so_far;
                state.completed_chunks = ps.completed_chunks as usize;
                state.seen = ps.seen_offsets.iter().map(|&o| o as usize).collect();
                state.seen_sha256 = ps.seen_sha256.into_iter().collect();
                if !quiet {
                    eprintln!(
                        "pala: resuming — {} finding(s) so far, {} chunk(s) skipped",
                        state.findings_so_far, state.completed_chunks
                    );
                    eprintln!();
                }
            }
            Some(ps) => {
                anyhow::bail!(
                    "--resume: state file source mismatch (expected {src_path} @ {}B, got {} @ {}B)",
                    size, ps.source, ps.source_bytes
                );
            }
            None => {
                anyhow::bail!("--resume: no .pala-state.json found in {out_path}");
            }
        }
    }

    let t0 = Instant::now();

    // ── Phase A: filesystem-assisted inode recovery (optional) ────────────────
    // Runs before the sig scan; populates state.seen_sha256 so the sig scan
    // skips files the inode phase already wrote.
    let mut inode_findings: Vec<Finding> = Vec::new();
    if !state.limit_reached() {
        if let Some(ref fs_type) = filesystem {
            inode_findings = carve_inode_phase(
                &src_path, fs_type, &outdir, quiet, emit_meta, &mut state, &sigs,
            )?;
        }
    }

    // ── Phase B: signature scan ────────────────────────────────────────────────
    let mut total_bad_sectors: u64 = 0;
    let mut mft_stage2: Vec<Finding> = Vec::new();
    let mut fat32_found: Vec<Finding> = Vec::new();
    let mut zip_members: Vec<Finding> = Vec::new();
    let mut entropy_zero = 0u64;
    let mut entropy_high = 0u64;
    let mut entropy_total = 0u64;

    let sig_findings = if state.limit_reached() {
        Vec::new()
    } else if is_blk {
        if !quiet {
            eprintln!("pala: block device detected — chunked pread() with bad-sector zero-fill");
            eprintln!();
        }
        let (findings, bad) = carve_device(
            &file,
            size,
            &outdir,
            &sigs,
            quiet,
            emit_meta,
            max_override,
            frag_gap,
            Some(&state_path),
            &src_path,
            degraded_ms * 1000,
            align_bytes,
            &mut state,
        )?;
        total_bad_sectors = bad;
        if !quiet && bad > 0 {
            eprintln!();
            eprintln!("pala: {} sector(s) unreadable — zero-filled in place", bad);
        }
        findings
    } else {
        // SAFETY: PALA opens the source read-only. The image must not be modified
        // by another process while it is memory-mapped.
        let mmap = unsafe { MmapOptions::new().len(size).map(&file) }
            .with_context(|| format!("mmap {src_path}"))?;
        let findings = carve(
            &mmap,
            0,
            &outdir,
            &sigs,
            quiet,
            emit_meta,
            max_override,
            frag_gap,
            align_bytes,
            None,
            &mut state,
        )?;

        // ── Phase C: entropy survey ───────────────────────────────────────────
        let (ez, eh, et) = entropy_survey(&mmap);
        entropy_zero = ez;
        entropy_high = eh;
        entropy_total = et;
        if !quiet && skip_high_entropy {
            eprintln!("pala: entropy — {et} sectors: {ez} zero, {eh} high-entropy (skipping)");
            eprintln!();
        }

        // ── Phase D: NTFS cluster-run stage-2 ────────────────────────────────
        if !state.limit_reached() {
            let cluster_size = ntfs_cluster_size(&mmap);
            mft_stage2 = carve_mft_stage2(
                &mmap,
                &findings,
                cluster_size,
                &outdir,
                &sigs,
                quiet,
                emit_meta,
                &mut state,
            )?;
        }

        // ── Phase E: FAT32 cluster-chain stage-2 ─────────────────────────────
        if fat32_stage2 && !state.limit_reached() {
            fat32_found = carve_fat32_stage2(
                &mmap, &findings, &outdir, &sigs, quiet, emit_meta, &mut state,
            )?;
        }

        // ── Phase F: ZIP container depth ──────────────────────────────────────
        if container_depth && !state.limit_reached() {
            let all_so_far: Vec<Finding> = inode_findings
                .iter()
                .chain(mft_stage2.iter())
                .chain(fat32_found.iter())
                .chain(findings.iter())
                .cloned()
                .collect();
            zip_members = carve_zip_members(
                &all_so_far,
                &outdir,
                &sigs,
                quiet,
                emit_meta,
                max_override,
                &mut state,
            )?;
        }

        write_checkpoint(&state_path, &src_path, size as u64, &state)?;

        findings
    };

    // Phase ordering by recovery confidence:
    // inode phase → MFT stage-2 → FAT32 stage-2 → sig scan → ZIP members
    let findings: Vec<Finding> = inode_findings
        .into_iter()
        .chain(mft_stage2)
        .chain(fat32_found)
        .chain(sig_findings)
        .chain(zip_members)
        .collect();
    let elapsed = t0.elapsed();

    // ── JSON output ───────────────────────────────────────────────────────────
    if json {
        let src_j = serde_json::to_string(&src_path).unwrap();
        let out_j = serde_json::to_string(&out_path).unwrap();
        print!(
            r#"{{"source":{src_j},"output":{out_j},"source_bytes":{size},"elapsed_ms":{},"bad_sectors":{},"found":{},"findings":["#,
            elapsed.as_millis(),
            total_bad_sectors,
            findings.len()
        );
        for (idx, f) in findings.iter().enumerate() {
            if idx > 0 {
                print!(",");
            }
            let path_j = serde_json::to_string(&f.path.to_string_lossy().as_ref()).unwrap();
            let name_j = serde_json::to_string(&f.name).unwrap();
            let ext_j = serde_json::to_string(&f.ext).unwrap();
            let desc_j = serde_json::to_string(&f.desc).unwrap();
            let sha_j = serde_json::to_string(&f.sha256).unwrap();
            let meta_j = if let Some(ref meta) = f.meta {
                format!(
                    ",\"meta\":{}",
                    serde_json::to_string(meta).unwrap_or_default()
                )
            } else {
                String::new()
            };
            let quality_j = serde_json::to_string(f.quality.as_str()).unwrap();
            let hbs_j = if f.has_bad_sectors {
                r#","has_bad_sectors":true"#
            } else {
                ""
            };
            let src_j = if let Some(ref s) = f.source {
                format!(r#","source":{}"#, serde_json::to_string(s).unwrap())
            } else {
                String::new()
            };
            print!(
                r#"{{"offset":{},"type":{name_j},"extension":{ext_j},"description":{desc_j},"size":{},"path":{path_j},"truncated":{},"quality":{quality_j},"sha256":{sha_j}{hbs_j}{src_j}{meta_j}}}"#,
                f.offset, f.size, f.trunc
            );
        }
        let bad_sectors = if is_blk { total_bad_sectors } else { 0 };
        let rate_per_gb = if size >= GB {
            findings.len() as f64 / (size as f64 / GB as f64)
        } else {
            0.0
        };
        // bad_sector_offsets: omit entirely when empty; cap already enforced in read_chunk_resilient
        let bso_j = if state.bad_sector_offsets.is_empty() {
            String::new()
        } else {
            let truncated = if state.bad_sector_offsets.len() >= 1000 {
                r#","bad_sector_offsets_truncated":true"#
            } else {
                ""
            };
            let offsets_j = state
                .bad_sector_offsets
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!(r#","bad_sector_offsets":[{offsets_j}]{truncated}"#)
        };
        let entropy_j = if entropy_total > 0 {
            format!(
                r#","entropy_survey":{{"zero_sectors":{entropy_zero},"high_entropy_sectors":{entropy_high},"total_sectors":{entropy_total},"high_entropy_skipped":{}}}"#,
                state.high_entropy_sectors_skipped
            )
        } else {
            String::new()
        };
        let partial_count = findings
            .iter()
            .filter(|f| matches!(f.quality, Quality::Partial))
            .count();
        print!(
            r#"],"session_summary":{{"bad_sectors":{bad_sectors},"merge_count":{},"partial_count":{partial_count},"files_per_gb":{rate_per_gb:.2}{bso_j}{entropy_j}}}}}"#,
            state.merge_count
        );
        println!();
    }

    // ── Human-readable summary ────────────────────────────────────────────────
    if !quiet {
        eprintln!();
        if findings.is_empty() {
            eprintln!("pala: no files recovered. ({:.1}s)", elapsed.as_secs_f32());
            if size > 100 * MB {
                eprintln!("pala: hint: if the drive was wiped (all zeros) or encrypted, no data can be recovered by carving.");
                eprintln!("pala: hint: try scanning the raw device (/dev/sdX) if you scanned a partition image.");
            }
        } else {
            let mut by_ext: HashMap<&str, usize> = HashMap::new();
            for f in &findings {
                *by_ext.entry(f.ext.as_str()).or_insert(0) += 1;
            }
            let mut groups: Vec<_> = by_ext.iter().collect();
            groups.sort_by_key(|(ext, _)| *ext);
            let summary = groups
                .iter()
                .map(|(ext, n)| format!("{n} {ext}"))
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "pala: recovered {} file(s) in {:.1}s → {out_path}",
                findings.len(),
                elapsed.as_secs_f32()
            );
            eprintln!("pala: {summary}");
        }
        // Session summary: bad sectors, recovery rate, and fragment merges.
        let bad_sectors = if is_blk { total_bad_sectors } else { 0 };
        if bad_sectors > 0 || state.merge_count > 0 || size >= GB {
            let rate_per_gb = if size >= GB {
                findings.len() as f64 / (size as f64 / GB as f64)
            } else {
                0.0
            };
            if is_blk || state.merge_count > 0 {
                eprintln!(
                    "pala: {} bad sector(s) | {} merge(s) | {rate_per_gb:.1} files/GB",
                    bad_sectors, state.merge_count
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pala_test_{name}"))
    }

    // read_chunk_resilient on a clean file returns exact bytes
    #[cfg(unix)]
    #[test]
    fn test_read_chunk_clean() {
        let p = tmp_path("clean");
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        std::fs::write(&p, &data).unwrap();
        let file = File::open(&p).unwrap();
        let mut buf = vec![0u8; 4096];
        let bad = read_chunk_resilient(&file, &mut buf, 0, 0, None);
        let _ = std::fs::remove_file(&p);
        assert_eq!(bad, 0);
        assert_eq!(buf, data);
    }

    // read_chunk_resilient zero-fills sectors past EOF (short read at end of file)
    #[cfg(unix)]
    #[test]
    fn test_read_chunk_short() {
        let p = tmp_path("short");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"GIF89a\x01\x00\x01\x00").unwrap();
        drop(f);
        let file = File::open(&p).unwrap();
        let mut buf = vec![0u8; 512];
        let bad = read_chunk_resilient(&file, &mut buf, 0, 0, None);
        let _ = std::fs::remove_file(&p);
        assert_eq!(bad, 0); // short read is not a bad sector, just EOF
        assert_eq!(&buf[..10], b"GIF89a\x01\x00\x01\x00");
        assert!(buf[10..].iter().all(|&b| b == 0));
    }

    // degraded_delay_us > 0 with no bad sectors: reads correctly, no delay triggered
    #[cfg(unix)]
    #[test]
    fn test_read_chunk_degraded_no_bad() {
        let p = tmp_path("degraded_clean");
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        std::fs::write(&p, &data).unwrap();
        let file = File::open(&p).unwrap();
        let mut buf = vec![0u8; 4096];
        // 1ms delay enabled but 0 bad sectors => no actual sleeping, reads intact
        let bad = read_chunk_resilient(&file, &mut buf, 0, 1000, None);
        let _ = std::fs::remove_file(&p);
        assert_eq!(bad, 0);
        assert_eq!(buf, data);
    }

    // detect_sig: JPEG magic matched against full sig table
    #[test]
    fn test_detect_sig_jpeg() {
        let sigs: Vec<DynSig> = SIGS.iter().map(make_dyn).collect();
        let data = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00";
        let hit = detect_sig(data, &sigs);
        assert!(hit.is_some(), "expected jpeg sig hit");
        assert_eq!(hit.unwrap().name, "jpeg");
    }

    // detect_sig: ZIP magic matched
    #[test]
    fn test_detect_sig_zip() {
        let sigs: Vec<DynSig> = SIGS.iter().map(make_dyn).collect();
        let data = b"PK\x03\x04\x00\x00\x00\x00";
        let hit = detect_sig(data, &sigs);
        assert!(hit.is_some(), "expected zip sig hit");
        assert_eq!(hit.unwrap().name, "zip");
    }

    // detect_sig: random bytes → None
    #[test]
    fn test_detect_sig_no_match() {
        let sigs: Vec<DynSig> = SIGS.iter().map(make_dyn).collect();
        let data = b"\x00\x01\x02\x03\x04\x05\x06\x07";
        assert!(detect_sig(data, &sigs).is_none());
    }

    // SHA256 dedup: a file pre-registered in seen_sha256 is not written by carve()
    #[cfg(unix)]
    #[test]
    fn test_sha256_dedup_skips_inode_recovered() {
        // Build a minimal valid JPEG
        let mut jpeg = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        jpeg.extend_from_slice(b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        let mut img = jpeg.clone();
        img.extend_from_slice(&[0u8; 64]);

        // Compute the SHA256 PALA would see for this JPEG
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(&jpeg);
        let sha = format!("{:x}", h.finalize());

        let td = std::env::temp_dir().join("pala_test_sha256_dedup");
        let _ = std::fs::remove_dir_all(&td);
        std::fs::create_dir_all(&td).unwrap();

        let sigs: Vec<DynSig> = SIGS
            .iter()
            .filter(|s| s.name == "jpeg")
            .map(make_dyn)
            .collect();
        let mut state = CarveState::new();
        state.seen_sha256.insert(sha); // pre-register as if inode phase wrote it

        let findings = carve(
            &img, 0, &td, &sigs, true, false, None, 0, 0, None, &mut state,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&td);
        assert_eq!(
            findings.len(),
            0,
            "sha256 dedup should skip the already-written JPEG"
        );
    }

    #[test]
    fn test_ntfs_cluster_size_from_bpb() {
        // Synthesize a minimal NTFS boot sector:
        //   [0..3]  jump instruction (3 bytes)
        //   [3..11] OEM ID "NTFS    "
        //   [0x0B..0x0D] bytes_per_sector = 512 (u16 LE)
        //   [0x0D]  sectors_per_cluster = 8  → cluster = 512 * 8 = 4096
        let mut boot = vec![0u8; 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[0x0B] = 0x00;
        boot[0x0C] = 0x02; // 512 LE
        boot[0x0D] = 8;
        assert_eq!(ntfs_cluster_size(&boot), 4096);

        // No NTFS signature → default 4096
        let bad = vec![0u8; 512];
        assert_eq!(ntfs_cluster_size(&bad), 4096);

        // Negative spc_raw: spc_raw = -1 → 2^1 = 2 bytes (degenerate; min'd to 512 by max)
        // Actually -1 means 2^1 = 2 bytes per cluster — nonsensical but parses
        let mut boot2 = boot.clone();
        boot2[0x0D] = 0xFF_u8; // i8 -1 → 2^1 = 2
        assert_eq!(ntfs_cluster_size(&boot2), 2);
    }

    #[test]
    fn test_parse_data_runs_basic() {
        // Single run: header=0x21 → len_bytes=1, off_bytes=2
        // run_len = 0x08 (8 clusters)
        // delta   = 0x00 0x10 → 0x1000 = 4096 (LCN 4096)
        let runs_data: Vec<u8> = vec![0x21, 0x08, 0x00, 0x10, 0x00];
        let runs = parse_data_runs(&runs_data, 0);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0], (0x1000, 8));
    }

    #[test]
    fn test_parse_data_runs_two_relative() {
        // Run 1: header=0x11 → len=1, off=1; len=0x20 (32), delta=0x08 → LCN 8
        // Run 2: header=0x11 → len=1, off=1; len=0x10 (16), delta=0x10 → LCN 8+16=24
        // Terminator: 0x00
        let data: Vec<u8> = vec![0x11, 0x20, 0x08, 0x11, 0x10, 0x10, 0x00];
        let runs = parse_data_runs(&data, 0);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0], (8, 32));
        assert_eq!(runs[1], (24, 16));
    }

    #[test]
    fn test_parse_data_runs_negative_delta() {
        // Run 1: LCN=100; Run 2: delta=-4 → LCN=96  (backward run, valid NTFS)
        // header=0x22 → len=2, off=2
        // Run1: len=0x0010 (16), delta=0x6400 → 0x0064 = 100
        // Run2: len=0x0008 (8),  delta=0xFCFF → signed 16-bit = -4 → LCN=96
        let data: Vec<u8> = vec![
            0x22, 0x10, 0x00, 0x64, 0x00, // run1: len=16, delta=+100 → LCN=100
            0x22, 0x08, 0x00, 0xFC, 0xFF, // run2: len=8,  delta=-4   → LCN=96
            0x00,
        ];
        let runs = parse_data_runs(&data, 0);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0], (100, 16));
        assert_eq!(runs[1], (96, 8));
    }

    #[test]
    fn test_parse_data_runs_sparse_skipped() {
        // Sparse run (off_bytes=0): header=0x01 → len_bytes=1, off_bytes=0
        // Should be skipped (no physical LCN)
        // Follow with a real run.
        let data: Vec<u8> = vec![
            0x01, 0x04, // sparse: 4 clusters, no LCN
            0x11, 0x08, 0x0A, // real:   len=8, delta=10 → LCN=10
            0x00,
        ];
        let runs = parse_data_runs(&data, 0);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0], (10, 8));
    }

    #[test]
    fn test_mft_run_info_no_data_attr() {
        // An MFT entry with no attributes at all (just the FILE header)
        // → mft_run_info returns None
        let mut entry = vec![0u8; 1024];
        entry[0..4].copy_from_slice(b"FILE");
        entry[20] = 56;
        entry[21] = 0; // attr_off = 56
                       // Place end marker at offset 56
        entry[56] = 0xFF;
        entry[57] = 0xFF;
        entry[58] = 0xFF;
        entry[59] = 0xFF;
        assert!(mft_run_info(&entry).is_none());
    }

    #[test]
    fn test_mft_run_info_resident_data_skipped() {
        // $DATA resident (non_resident flag = 0) → mft_run_info returns None
        let mut entry = vec![0u8; 1024];
        entry[0..4].copy_from_slice(b"FILE");
        entry[20] = 56;
        entry[21] = 0; // attr_off = 56

        // $DATA attribute at offset 56, length 32, resident
        let attr_off = 56usize;
        entry[attr_off] = 0x80;
        entry[attr_off + 1] = 0; // type = 0x80
        entry[attr_off + 2] = 0;
        entry[attr_off + 3] = 0;
        entry[attr_off + 4] = 32;
        entry[attr_off + 5] = 0; // length = 32
        entry[attr_off + 6] = 0;
        entry[attr_off + 7] = 0;
        entry[attr_off + 8] = 0; // non_resident = 0 (resident)
                                 // End marker after attribute
        entry[attr_off + 32] = 0xFF;
        entry[attr_off + 33] = 0xFF;
        entry[attr_off + 34] = 0xFF;
        entry[attr_off + 35] = 0xFF;
        assert!(mft_run_info(&entry).is_none());
    }

    #[test]
    fn test_zip_member_resource_limit() {
        let td = std::env::temp_dir().join(format!("pala_test_zip_limit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        std::fs::create_dir_all(&td).unwrap();
        let zip_path = td.join("input.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("large.bin", options).unwrap();
        writer.write_all(&[0x41; 1024]).unwrap();
        writer.finish().unwrap();

        let finding = Finding {
            offset: 0,
            name: "zip".to_string(),
            ext: "zip".to_string(),
            desc: "ZIP Archive".to_string(),
            size: std::fs::metadata(&zip_path).unwrap().len() as usize,
            path: zip_path,
            trunc: false,
            quality: Quality::Complete,
            sha256: String::new(),
            has_bad_sectors: false,
            meta: None,
            source: None,
        };
        let sigs: Vec<DynSig> = SIGS.iter().map(make_dyn).collect();
        let mut state = CarveState::new();
        let mut total = 0;
        let findings = unpack_zip_finding(
            &finding,
            &td,
            &sigs,
            true,
            false,
            Some(64),
            &mut total,
            &mut state,
        )
        .unwrap();
        assert!(findings.is_empty());
        assert_eq!(total, 0);
        let _ = std::fs::remove_dir_all(&td);
    }

    fn valid_test_jpeg() -> Vec<u8> {
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        jpeg.extend_from_slice(b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
        jpeg.extend_from_slice(&[0xFF, 0xFE, 0x01, 0xF6]);
        jpeg.extend_from_slice(&[0u8; 500]);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        jpeg
    }

    fn jpeg_signatures() -> Vec<DynSig> {
        SIGS.iter()
            .filter(|s| s.name == "jpeg")
            .map(make_dyn)
            .collect()
    }

    #[test]
    fn test_parse_data_runs_rejects_oversized_fields() {
        assert!(parse_data_runs(&[0x99, 0, 0], 0).is_empty());
    }

    #[test]
    fn test_chunk_overlap_candidate_remains_unseen() {
        let td = std::env::temp_dir().join(format!("pala_test_overlap_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        let sigs = jpeg_signatures();
        let mut state = CarveState::new();
        let img = valid_test_jpeg();

        let deferred = carve(
            &img,
            4096,
            &td,
            &sigs,
            true,
            false,
            None,
            0,
            0,
            Some(4096),
            &mut state,
        )
        .unwrap();
        assert!(deferred.is_empty());
        assert!(state.seen.is_empty());

        let emitted = carve(
            &img, 4096, &td, &sigs, true, false, None, 0, 0, None, &mut state,
        )
        .unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].offset, 4096);
        let _ = std::fs::remove_dir_all(&td);
    }

    #[test]
    fn test_count_leaves_unemitted_candidates_resumable() {
        let td = std::env::temp_dir().join(format!("pala_test_count_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        let sigs = jpeg_signatures();
        let mut state = CarveState::new();
        state.finding_limit = Some(1);
        let first = valid_test_jpeg();
        let mut second = valid_test_jpeg();
        second[24] = 1;
        let img = [first, second].concat();

        let findings = carve(
            &img, 0, &td, &sigs, true, false, None, 0, 0, None, &mut state,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(state.seen.len(), 1);
        let _ = std::fs::remove_dir_all(&td);
    }

    #[test]
    fn test_entropy_filter_uses_chunk_local_offsets() {
        let td = std::env::temp_dir().join(format!("pala_test_entropy_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        let sigs = jpeg_signatures();
        let mut state = CarveState::new();
        state.skip_high_entropy = true;
        let mut img = valid_test_jpeg();
        for (index, byte) in img[24..524].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }

        let findings = carve(
            &img, 8192, &td, &sigs, true, false, None, 0, 0, None, &mut state,
        )
        .unwrap();
        assert!(findings.is_empty());
        assert_eq!(state.high_entropy_sectors_skipped, 1);
        let _ = std::fs::remove_dir_all(&td);
    }

    #[test]
    fn test_checkpoint_preserves_sha256_dedup_state() {
        let path =
            std::env::temp_dir().join(format!("pala_test_state_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut state = CarveState::new();
        state.seen_sha256.insert("abc123".to_string());
        write_checkpoint(&path, "image.img", 1234, &state).unwrap();
        let restored = read_checkpoint(&path).unwrap();
        assert_eq!(restored.seen_sha256, vec!["abc123"]);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn test_private_output_and_no_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let td = std::env::temp_dir().join(format!("pala_test_permissions_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        create_output_dir(&td).unwrap();
        assert_eq!(
            std::fs::metadata(&td).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let path = td.join("finding.jpg");
        write_new(&path, b"original").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_new(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&td);
    }
}
