# PALA operator guide

PALA is intended for incident response, forensic analysis, firmware examination, and accidental-deletion recovery. It cannot recover overwritten data or decrypt encrypted content.

## Small by design

PALA's small size is a recovery-safety feature, not just a convenience. When a person or an LLM coding agent accidentally deletes a file, its old sectors become available for reuse. Downloading and installing a large recovery tool onto that same drive can overwrite the very data being recovered.

The release build is approximately 1 MiB on the primary platform. PALA can be kept on a USB drive before an accident, downloaded with minimal disk activity, and run directly from separate media without installation or a Python runtime. This reduces the footprint of obtaining the recovery tool itself; recovered output and reports must still go to a different drive.

**Keep PALA on hand before you need it: a small, ready-to-run recovery tool for situations where every additional write can destroy deleted data.**

## Safety first

Deleted data is overwritten by subsequent disk activity.

1. Stop using the source device. Do not install software, save reports, or write recovered files to it.
2. Unmount the source when practical, or acquire a forensic image and work from that image.
3. Do not modify a disk image while PALA is scanning it.
4. Write output to a **different physical device** when scanning a raw block device.
5. Run with the least privilege needed. Elevated privileges may be required to read a raw device, but are not required for ordinary image files.

PALA refuses same-device output for raw block devices unless `--allow-same-device` is explicitly supplied. This override can destroy the data you are trying to recover. Disk-image scans emit a warning when the image and output share a filesystem device.

A normal run requires an empty output directory. PALA never overwrites an existing recovered file. Use `--resume` only to continue a previous run with the same source and output directory.

## Recovery methods

PALA combines several recovery phases and deduplicates output by SHA-256.

| Phase | Description | Availability |
|---|---|---|
| Deleted-inode recovery | Uses Sleuth Kit `fls` and `icat` to recover directory entries and file content retained in filesystem metadata | Optional; enabled by `--filesystem`, subject to Sleuth Kit filesystem support |
| Signature carving | Finds and validates magic bytes, then uses end markers or format-specific size parsers to determine file boundaries | Disk images and raw block devices |
| NTFS cluster-run recovery | Parses non-resident MFT `$DATA` run lists and reassembles file content | Regular disk-image files; resident `$DATA` is not recovered by this phase |
| FAT32 deleted-entry recovery | Walks directories and follows available cluster chains, with contiguous-cluster prediction when chains were cleared | Regular disk-image files; heavily fragmented files may be incomplete |
| ZIP member extraction | Expands supported ZIP-based containers one level deep | Optional; enabled by `--container-depth` for disk-image scans |

Signature carving normally expects file content to be contiguous. Fragment merging can join adjacent same-type candidates and tolerate configured zero-filled gaps, but it is not a general fragmented-file recovery algorithm.

Raw block devices are read in 256 MiB windows with 64 MiB overlap. Files larger than the overlap can be incomplete when they cross a window boundary. The NTFS, FAT32, and ZIP post-processing phases currently run only for regular image files.

## Supported platforms and dependencies

| Component | Requirement |
|---|---|
| Build | Rust stable toolchain |
| Primary test platform | Linux |
| Windows | Disk-image functionality is supported; Unix raw-device handling is not available |
| Sleuth Kit | Optional runtime dependency for `--filesystem`; `fls` and `icat` must be on `PATH` |
| Python | Not required to run PALA; Python 3 and Pillow are used by the integration tests |

PALA does not require Python or an AI service at runtime. Filesystem support in `--filesystem=auto` depends on the installed Sleuth Kit build.

## Build and installation

From a source checkout:

```bash
cargo build --release --locked
```

The executable is written to `target/release/pala`. Copy it to a location on your `PATH` or to removable media used for recovery work.

For a locally optimized build:

```bash
cargo install --path . --locked
```

Optional Sleuth Kit installation on Debian/Ubuntu:

```bash
sudo apt install sleuthkit
```

On macOS with Homebrew:

```bash
brew install sleuth-kit
```

## Quick start

List the built-in signature names:

```bash
pala --list
```

Recover all supported types from an image:

```bash
pala disk.img /mnt/recovery/pala-output/
```

Recover selected types from a raw device:

```bash
sudo pala /dev/sdb /mnt/recovery/pala-output/ --types jpeg,png,pdf
```

Produce machine-readable output:

```bash
pala disk.img out/ --quiet --json --meta > findings.json
```

Inspect the JSON without writing progress messages into it:

```bash
jq '.findings[] | {type, extension, size, quality, path}' findings.json
```

Use Sleuth Kit deleted-inode recovery before signature carving:

```bash
pala disk.img out/ --filesystem=auto
```

## Command-line reference

```text
pala <source> <outdir> [OPTIONS]
```

`source` is a disk image or raw block device opened read-only. `outdir` is the recovery output directory.

Most long options accept either `--option value` or `--option=value`.

| Option | Meaning |
|---|---|
| `-t, --types <csv>` | Comma-separated signature names from `--list`; default is all built-in and loaded custom types |
| `-c, --corpus <path>` | Load additional signatures from a PALA v1 corpus file |
| `-l, --list` | List selected signature types and exit |
| `-q, --quiet` | Suppress progress and per-file messages; JSON still goes to stdout |
| `--json` | Write one JSON report to stdout |
| `--meta` | Include supported JPEG, PNG, ELF, PE, NTFS MFT, and SQLite metadata in JSON findings |
| `--min-size <bytes>` | Apply a global minimum recovered-file size; built-in per-type minimums still apply |
| `--max-size <bytes>` | Override each signature's maximum carve window; also limits each extracted ZIP member |
| `-n, --count <n>` | Stop after recovering N files in this invocation; N must be greater than zero |
| `--resume` | Resume using `outdir/.pala-state.json`; source path and byte size must match |
| `--degraded[=ms]` | On Unix raw devices, delay sector reads after repeated read errors; default delay is 1 ms, and 0 disables it |
| `--filesystem <fs>` | Enable Sleuth Kit deleted-inode recovery |
| `--align <bytes>` | Accept only signature starts aligned to N bytes; useful for sector-aligned scans |
| `--triage-mode <mode>` | Restrict signatures to a named operational preset |
| `--skip-high-entropy` | Skip findings whose starting 512-byte sector has Shannon entropy greater than 7.5 bits/byte |
| `--container-depth` | Extract members from recovered ZIP, DOCX, XLSX, PPTX, JAR, and APK files |
| `--frag-gap <bytes>` | Permit up to N zero-filled bytes between merged fragments; default is 0 |
| `--no-fat32-stage2` | Disable FAT32 deleted-entry post-processing |
| `--allow-same-device` | Explicitly permit unsafe output on a raw source device |
| `-V, --version` | Print the package version and exit |
| `-h, --help` | Print command help |

`--filesystem` accepts `auto`, `ext2`, `ext3`, `ext4`, `ntfs`, `apfs`, `fat12`, `fat16`, `fat32`, `hfs`, `ufs1`, and `ufs2`, subject to Sleuth Kit support. If Sleuth Kit is unavailable or cannot read the image, PALA reports the problem and continues with signature carving.

Triage presets are `media`, `documents`, `executables`, `archives`, `email`, `memory`, `filesystem`, `windows`, `databases`, `firmware`, and `forensic`. A preset restricts signatures; it does not invoke an AI service.

## Output and recovery quality

Recovered files use generated names such as `jpg_0001.jpg` and `pdf_0002.pdf`; original names are generally not preserved. Filesystem and container sources are identified in JSON.

Each finding has one of these quality values:

- `complete`: an end marker or usable format-specific boundary was found, or a filesystem-assisted read completed.
- `partial`: the carve window or another limit was reached without a natural boundary.
- `fragmented`: content was merged or assembled from filesystem runs. This label does not prove that every fragment is correct.

A `truncated` Boolean is included separately for compatibility. SHA-256 hashes are calculated over the recovered bytes, not the original file, so a hash match is possible only when recovery is byte-exact.

On Unix, newly created output directories use mode `0700`, and recovered files and checkpoints use mode `0600`. Permissions on pre-existing directories are not changed. On other platforms, normal platform ACLs apply. Review access controls before recovering sensitive material.

## JSON report

`--json` writes to **stdout**. Diagnostics and progress are written to stderr. Redirect stdout to create a report:

```bash
pala disk.img out/ --quiet --json > findings.json
```

Example structure:

```json
{
  "source": "disk.img",
  "output": "out",
  "source_bytes": 1048576,
  "elapsed_ms": 25,
  "bad_sectors": 0,
  "found": 1,
  "findings": [
    {
      "offset": 4096,
      "type": "pdf",
      "extension": "pdf",
      "description": "PDF Document",
      "size": 812,
      "path": "out/pdf_0001.pdf",
      "truncated": false,
      "quality": "complete",
      "sha256": "…",
      "source": "fat32:00000000"
    }
  ],
  "session_summary": {
    "bad_sectors": 0,
    "merge_count": 0,
    "partial_count": 0,
    "files_per_gb": 0.00
  }
}
```

`source` inside a finding is omitted for ordinary signature hits. Other values include `inode:<inode>`, `mft:<offset>`, `fat32:<offset>`, and `zip:<offset>:<member>`. Optional fields include `meta`, `has_bad_sectors`, `bad_sector_offsets`, and `entropy_survey`.

## Checkpoints and resume

PALA writes `.pala-state.json` in the output directory. It records source identity, source size, filename counters, emitted offsets, SHA-256 deduplication state, and completed raw-device chunks.

```bash
pala disk.img out/ --resume
```

For regular images, completed work is deduplicated during a new scan. For raw block devices, completed chunks are skipped. Do not change the source, output directory, or signature configuration between attempts. A mismatched source path or byte size is rejected.

Checkpoint replacement uses a temporary file and rename. A stale `.pala-state.json.tmp` indicates an interrupted checkpoint write and produces a warning.

## ZIP extraction limits

Container expansion is deliberately bounded to reduce decompression-bomb and disk-exhaustion risk:

- At most 10,000 members are examined per archive.
- The default maximum is 500 MiB per member; `--max-size` lowers or overrides this limit.
- At most 1 GiB is extracted across a container-expansion run.
- Nested containers are not recursively expanded.
- Members exceeding a limit are skipped; unrelated recovery continues.

Recovered archives can still be hostile or malformed. Do not open them with privileged applications merely because PALA recovered them.

## Built-in file types

The authoritative list is `pala --list`. Built-in categories include:

| Category | Types |
|---|---|
| Images | JPEG, PNG, GIF87a/89a, BMP, TIFF LE/BE, PSD, MNG, JNG, HEIC, HEIF, AVIF |
| Audio and video | RIFF/WAV/AVI/WebP, MKV/WebM, MP4/MOV, MP3 with ID3, FLAC, AAC/ADTS, OGG |
| Documents | PDF, RTF, OLE2, ZIP and Office Open XML, EML |
| Archives | ZIP, gzip, 7-Zip, RAR4/5, TAR, XZ, bzip2, Zstandard |
| Databases | SQLite, SQLite WAL, ESE/JET Blue |
| Executables | ELF, PE/MZ, DEX, ART |
| Windows artifacts | EVTX, registry hives, LNK, Prefetch, thumbcache, hibernation, crash dumps, minidumps, USN records |
| Filesystem structures | NTFS MFT, FAT32 FSINFO, ext2/3/4 and UFS superblocks, APFS container superblocks |
| Memory acquisitions | LiME and HPAK |
| Network captures | PCAP LE/BE and PCAPng |
| Firmware | SquashFS, JFFS2, UBIFS, U-Boot, FIT/DTB, cramfs |
| Other | LUKS and BitLocker headers, VMDK, VHDX, ISO 9660, binary plist, systemd journal, OpenSSH keys, PEM and DER certificates |

Some formats have exact or bounded size parsers; others rely on conservative maximum windows or end markers. Recovery quality therefore varies by format. Detecting an encryption header does not provide access to encrypted content.

## Custom signatures

Load a PALA v1 corpus with:

```bash
pala disk.img out/ --corpus custom.pala
```

The binary layout is documented in `src/corpus.rs`. This example creates a corpus with one signature and no end marker:

```python
import struct


def make_corpus(signatures):
    output = b"PALA" + b"\x01" + struct.pack("<I", len(signatures))
    for sig in signatures:
        name = sig["name"].encode("utf-8")
        extension = sig["extension"].encode("ascii")
        magic = sig["magic"]
        description = sig["description"].encode("utf-8")
        output += bytes([len(name)]) + name
        output += bytes([len(extension)]) + extension
        output += bytes([len(magic)]) + magic
        output += b"\x00"  # flags: no end marker or special handler
        output += b"\x00"  # magic offset
        output += struct.pack("<Q", sig["max_size"])
        output += struct.pack("<I", sig["min_size"])
        output += bytes([len(description)]) + description
    return output


corpus = make_corpus([{
    "name": "mysave",
    "extension": "sav",
    "magic": b"MYSAVE\x01",
    "max_size": 10 * 1024 * 1024,
    "min_size": 64,
    "description": "My game save",
}])

with open("custom.pala", "wb") as file:
    file.write(corpus)
```

Corpus files are untrusted input. PALA validates record counts, lengths, flags, size relationships, and filename extensions. Extensions are limited to 1–16 ASCII letters, digits, hyphens, or underscores. Empty magic, trailing data, and oversized serialized fields are rejected.

## Operational troubleshooting

**Output directory is not empty**

Use a new directory, or supply `--resume` only when continuing the same recovery. PALA does not overwrite earlier recoveries.

**Output is on the source block device**

Choose output on another physical device. `--allow-same-device` is intentionally unsafe and should not be part of a normal recovery procedure.

**No files were recovered**

Run without `--types`, check `--min-size` and `--align`, try the parent device rather than a partition, and confirm that the source contains unencrypted, unoverwritten data. Files without known signatures require filesystem-assisted recovery or a custom corpus.

**Recovered files are corrupt or unusually large**

The content may be fragmented, overwritten, or bounded only by a maximum carve window. Review `quality`, `truncated`, size, and source fields. Try filesystem-assisted recovery where available.

**Too many false positives**

Restrict `--types`, use `--align=512` for sector-aligned media, consider `--skip-high-entropy`, and review results by hash and quality. Short magic sequences can occur in arbitrary data.

**Sleuth Kit errors**

Confirm that `fls` and `icat` are installed and support the source filesystem. Signature recovery continues without them.

**Memory or disk pressure**

Use `--types`, `--count`, and `--max-size`. Keep container expansion disabled unless needed, and ensure sufficient free space on the output device. Memory-mapped images require virtual address space proportional to image size; raw-device scans use bounded read windows but recovered candidates still consume memory and output space.

## Development and verification

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
python3 tests/test_pala.py
```

The integration suite uses synthetic images and does not require sudo. Some filesystem tests are skipped when their external tools or Python modules are unavailable.

See `CONTRIBUTING.md` for change requirements, `SECURITY.md` for security guidance, and `CHANGELOG.md` for release history.

## Known limitations

- Overwritten sectors are unrecoverable.
- PALA does not decrypt LUKS, BitLocker, or other encrypted content.
- Signature carving does not preserve directory structure and usually does not preserve filenames.
- Arbitrary fragmented files cannot be reconstructed reliably by signature carving alone.
- NTFS resident data, alternate data streams, and every NTFS attribute layout are not covered by the cluster-run phase.
- FAT32 contiguous-cluster prediction can produce incorrect content on heavily fragmented volumes.
- JFFS2, UBIFS, and formats without reliable boundaries may be recovered with trailing data or truncation.
- Raw-device post-processing is more limited than regular-image post-processing.
- Recovered content must be validated before it is trusted or opened.

PALA is a recovery aid, not a guarantee of forensic completeness. For evidentiary use, document acquisition, tool versions, commands, hashes, and independent validation in accordance with your procedures.

## License

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
