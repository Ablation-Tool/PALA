## Capabilities

<details>
<summary>Recovery Engine</summary>

| Capability | Description |
|:---|:---|
| **Signature Carving** | Finds and validates known file contents in raw images and block devices, without relying on filenames or a working filesystem. |
| **Deleted-Inode Recovery** | Uses Sleuth Kit `fls` and `icat` to recover files whose filesystem metadata remains. |
| **NTFS Cluster Runs** | Reassembles non-resident files from MFT `$DATA` run lists. |
| **FAT32 Recovery** | Walks deleted directory entries and follows available cluster chains. |
| **Fragment Merging** | Joins adjacent candidates and configured zero-filled gaps. |
| **Container Expansion** | Extracts members from ZIP, DOCX, XLSX, PPTX, JAR, and APK files with resource limits. |

</details>

<details>
<summary>File Formats</summary>

| Category | Types |
|:---|:---|
| **Media** | JPEG · PNG · GIF · BMP · TIFF · PSD · HEIC · AVIF · MP4 · MKV · MP3 · FLAC · OGG |
| **Documents** | PDF · RTF · OLE2 · DOCX · XLSX · PPTX · EML |
| **Archives** | ZIP · gzip · 7-Zip · RAR4/5 · TAR · XZ · bzip2 · Zstandard |
| **Data & Code** | SQLite · ESE · ELF · PE · DEX · ART |
| **Forensics** | EVTX · registry hives · LNK · Prefetch · memory dumps · USN records · PCAP |
| **Firmware** | SquashFS · JFFS2 · UBIFS · U-Boot · FIT/DTB · cramfs |
| **Other** | NTFS · FAT32 · ext2/3/4 · APFS · LUKS · BitLocker · VMDK · VHDX · ISO 9660 |

The authoritative signature list is `pala --list`.

</details>

<details>
<summary>Automation & Operations</summary>

| Capability | Description |
|:---|:---|
| **JSON Reports** | Offsets, sizes, recovery quality, metadata, source, and SHA-256 hashes for scripts and AI-assisted review. |
| **Metadata Extraction** | JPEG EXIF/GPS, PNG text, ELF/PE headers, NTFS details, and SQLite information. |
| **Checkpoints** | Resume interrupted scans without duplicating previous recoveries. |
| **Custom Signatures** | Add proprietary formats with a validated PALA v1 corpus. |
| **Targeted Recovery** | Filter by type, size, alignment, count, or operational preset. |
| **Safe Output** | Read-only source access, non-overwriting files, private Unix permissions, and raw-device safety checks. |

</details>

## Setup & About

<details>
<summary>AI Agent Install</summary>

Hand this prompt to your AI coding agent. It builds PALA from the locked Rust dependency graph and stops before any recovery operation.

```text
Build PALA from https://github.com/Ablation-Tool/PALA for me.

Check for a stable Rust toolchain with `rustc --version` and `cargo --version`.
Clone the repository if it is not already present and build from that checkout
with:

  cargo build --release --locked

Verify the binary by running `target/release/pala --list`. Report the checkout
path, binary path, Rust version, and verification result.

Keep Sleuth Kit optional and install it only if I separately request
`--filesystem` support and approve the prerequisite installation. Do not use
sudo, install PALA globally, scan a disk or image, access a raw device, or
create recovery output during setup. Recovery requires a separate request with
authorized source and destination paths.
```

</details>

<details>
<summary>Manual Install</summary>

**Requirements:** Rust stable. Sleuth Kit is optional for `--filesystem`.

```bash
cargo build --release --locked
```

Binary: `target/release/pala`

Or install locally:

```bash
cargo install --path . --locked
```

PALA does not need Python or an AI service at runtime.

</details>

<details>
<summary>Quick Start</summary>

```bash
# List supported types
pala --list

# Recover everything from an image
pala disk.img /media/usb/recovered/

# Recover selected types from a raw device
sudo pala /dev/sdb /media/usb/recovered/ -t jpeg,png,pdf

# Use filesystem metadata before carving
pala disk.img out/ --filesystem=auto

# Write structured results for automation
pala disk.img out/ -q --json --meta > findings.json

# Resume an interrupted scan
pala disk.img out/ --resume
```

</details>

<details>
<summary>Command-Line Options</summary>

| Option | Purpose |
|:---|:---|
| `-t, --types <csv>` | Select signature names |
| `-c, --corpus <path>` | Load custom signatures |
| `--min-size <bytes>` | Set a global minimum output size |
| `--max-size <bytes>` | Override carve-window and ZIP member limits |
| `-n, --count <n>` | Stop after N recoveries |
| `--align <bytes>` | Require aligned signature offsets |
| `--triage-mode <mode>` | Use a signature preset |
| `--skip-high-entropy` | Skip findings in high-entropy sectors |
| `--container-depth` | Extract ZIP-based members |
| `--frag-gap <bytes>` | Permit zero-filled fragment gaps |
| `--degraded[=ms]` | Slow reads after bad sectors |
| `--no-fat32-stage2` | Disable FAT32 post-processing |
| `--allow-same-device` | Explicitly permit unsafe raw-device output |
| `-q, --quiet` | Suppress progress output |
| `-l, --list` | List signatures |
| `-V, --version` | Print version |
| `-h, --help` | Full command help |

</details>

<details>
<summary>Safe Recovery</summary>

1. Stop writes to the source immediately.
2. Work from a verified image when possible.
3. Never modify an image while PALA is scanning it.
4. Write output to a different physical device.
5. Use a new, empty output directory; use `--resume` only for the same recovery.
6. Treat recovered files as untrusted and validate them before opening.

On Unix, new output directories use `0700`; recovered files and checkpoints use `0600`. See the [operator guide](docs/operations.md) for checkpoints, JSON fields, resource limits, and troubleshooting.

</details>

<details>
<summary>Limitations</summary>

- Overwritten data cannot be recovered.
- Encrypted content is detected, not decrypted.
- Arbitrary fragmented files and original directory structures are not guaranteed.
- Raw-device post-processing is more limited than regular-image processing.
- Some formats have reliable size parsers; others require conservative boundaries.
- Recovered content is not proof of authenticity, safety, or forensic completeness.

</details>

<details>
<summary>Development & Verification</summary>

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
python3 tests/test_pala.py
```

CI covers Linux and Windows builds, strict lint, integration tests, binary size, and dependency advisories.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development standards and [SECURITY.md](SECURITY.md) for responsible use and private vulnerability reporting.

</details>

---

**MIT OR Apache-2.0** · [License](LICENSE-MIT) · [License](LICENSE-APACHE)
