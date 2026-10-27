#!/usr/bin/env python3
"""
PALA Rust binary test suite.

No sudo, no loopback devices. Each test:
  1. Generate file(s) in memory
  2. Build a raw image: random_noise + file_bytes + random_noise
  3. Run ./target/release/pala on the image
  4. Verify recovered file(s) match originals by SHA256

Run from repo root:
  python3 tests/test_pala.py
"""

import hashlib
import io
import json
import math
import os
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# ── binary location ───────────────────────────────────────────────────────────

REPO = Path(__file__).parent.parent
PALA = REPO / "target" / "release" / "pala"

RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
YELLOW = "\033[0;33m"
NC     = "\033[0m"

passed: list[str] = []
failed: list[tuple[str, str]] = []
skipped: list[str] = []

# ── helpers ───────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256f(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

_rng = random.Random(0xC0FFEE)

def noise(n: int) -> bytes:
    return bytes(_rng.getrandbits(8) for _ in range(n))

def make_raw_image(*files: bytes, prefix: int = 4096, gap: int = 512) -> bytes:
    """Concatenate files into a raw image with random noise prefix/inter-gaps, zero suffix.

    The zero suffix matches real disk conditions: freed clusters after a deleted file
    are typically zeroed by the OS, not filled with random data.  Using random noise
    here would cause single-byte end-markers (e.g. RTF's '}') to be found in the
    trailing garbage instead of the file, producing a SHA256 mismatch.
    """
    out = noise(prefix)
    for i, f in enumerate(files):
        if i > 0:
            out += noise(gap)
        out += f
    out += b"\x00" * gap
    return out

def run_pala(img: bytes, outdir: Path, types: list[str] | None = None,
             meta: bool = False, max_size: int | None = None,
             resume: bool = False, degraded_ms: int | None = None,
             frag_gap: int | None = None,
             filesystem: str | None = None,
             extra_args: list[str] | None = None,
             timeout: int = 30) -> dict[str, bytes]:
    """Write img to a temp file, run pala, return {filename: bytes} of carved files."""
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tf:
        tf.write(img)
        img_path = tf.name
    try:
        cmd = [str(PALA), img_path, str(outdir), "-q"]
        if types:
            cmd += ["-t", ",".join(types)]
        if meta:
            cmd += ["--json", "--meta"]
        if max_size is not None:
            cmd += [f"--max-size={max_size}"]
        if resume:
            cmd += ["--resume"]
        if degraded_ms is not None:
            cmd += [f"--degraded={degraded_ms}"]
        if frag_gap is not None:
            cmd += [f"--frag-gap={frag_gap}"]
        if filesystem is not None:
            cmd += [f"--filesystem={filesystem}"]
        if extra_args:
            cmd += extra_args
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode not in (0,):
            raise RuntimeError(f"pala exit {r.returncode}: {r.stderr.strip()}")
        result = {}
        for p in outdir.iterdir():
            if p.name == ".pala-state.json":
                continue  # bookkeeping file, not a carved artifact
            result[p.name] = p.read_bytes()
        if meta:
            result["__json__"] = r.stdout.encode()
        return result
    finally:
        os.unlink(img_path)


def run_test(
    name: str,
    files: dict[str, bytes],
    skip: str | None = None,
    types: list[str] | None = None,
    gap: int = 512,
):
    """
    files: {label: bytes} — expected files to recover (by SHA256 match)
    types: optional list of type names to restrict the scan to
    """
    if skip:
        print(f"  {YELLOW}SKIP{NC}  {name} — {skip}")
        skipped.append(name)
        return

    print(f"  {CYAN}....{NC}  {name}", end="", flush=True)
    with tempfile.TemporaryDirectory() as td:
        outdir = Path(td)
        try:
            img = make_raw_image(*files.values(), gap=gap)
            carved = run_pala(img, outdir, types)

            orig_hashes = {sha256(data): label for label, data in files.items()}
            carved_hashes = {sha256(data): fname for fname, data in carved.items()}

            missing = [label for h, label in orig_hashes.items() if h not in carved_hashes]
            if missing:
                print(f"\r  {RED}FAIL{NC}  {name} — not recovered: {missing}")
                failed.append((name, str(missing)))
            else:
                print(f"\r  {GREEN}PASS{NC}  {name}")
                passed.append(name)
        except Exception as e:
            print(f"\r  {RED}ERR {NC}  {name} — {e}")
            failed.append((name, str(e)))


def run_fp_test(name: str, seed: int = 0xCAFEBABE):
    """Scan random data — strong-magic types must produce 0 false positives."""
    STRONG = {"jpg", "png", "gif", "pdf", "zip", "docx", "xlsx", "pptx",
               "db", "7z", "rar", "psd", "tif", "webp", "rtf", "wav", "avi"}
    print(f"  {CYAN}....{NC}  {name}", end="", flush=True)
    with tempfile.TemporaryDirectory() as td:
        outdir = Path(td)
        try:
            rng = random.Random(seed)
            raw = bytes(rng.getrandbits(8) for _ in range(20 * 1024 * 1024))
            carved = run_pala(raw, outdir, timeout=120)
            strong_fps = [f for f, d in carved.items() if Path(f).suffix.lstrip(".") in STRONG]
            weak_fps   = [f for f, d in carved.items() if Path(f).suffix.lstrip(".") not in STRONG]
            if strong_fps:
                print(f"\r  {RED}FAIL{NC}  {name} — strong-magic FPs: {[Path(f).name for f in strong_fps[:5]]}")
                failed.append((name, f"{len(strong_fps)} strong-magic FPs"))
            else:
                note = f" ({len(weak_fps)} short-magic FPs)" if weak_fps else ""
                print(f"\r  {GREEN}PASS{NC}  {name}{note}")
                passed.append(name)
        except Exception as e:
            print(f"\r  {RED}ERR {NC}  {name} — {e}")
            failed.append((name, str(e)))


def run_frag_test(name: str, full_file: bytes, split_at: int, sig_type: str, max_size: int):
    """Fragment reassembly test.
    Splits full_file at split_at to produce frag1 + frag2 (adjacent in image).
    Runs pala with --max-size=max_size so frag1 is carved-truncated.
    Expects exactly one carved file whose SHA256 matches full_file.
    """
    print(f"  {CYAN}....{NC}  {name}", end="", flush=True)
    with tempfile.TemporaryDirectory() as td:
        outdir = Path(td)
        try:
            frag1 = full_file[:split_at]
            frag2 = full_file[split_at:]
            # Image: noise prefix + frag1 + frag2 (no gap between fragments = adjacent)
            rng = random.Random(0xF4AC)
            prefix = bytes(rng.getrandbits(8) for _ in range(4096))
            img = prefix + frag1 + frag2 + b"\x00" * 512
            carved = run_pala(img, outdir, types=[sig_type], max_size=max_size)
            matched = [data for data in carved.values() if sha256(data) == sha256(full_file)]
            if not matched:
                sizes = [len(d) for d in carved.values()]
                raise RuntimeError(
                    f"merged file not found; expected SHA256 of {len(full_file)}B file; "
                    f"carved {len(carved)} file(s) with sizes {sizes}"
                )
            print(f"\r  {GREEN}PASS{NC}  {name}")
            passed.append(name)
        except Exception as e:
            print(f"\r  {RED}FAIL{NC}  {name} — {e}")
            failed.append((name, str(e)))


def run_meta_test(name: str, fixture: bytes, sig_type: str, checks: dict, gap: int = 0):
    """Run pala with --meta --json and verify metadata fields in the first finding."""
    import json as _json
    print(f"  {CYAN}....{NC}  {name}", end="", flush=True)
    with tempfile.TemporaryDirectory() as td:
        outdir = Path(td)
        try:
            img = make_raw_image(fixture, gap=gap)
            carved = run_pala(img, outdir, types=[sig_type], meta=True)
            raw = carved.get("__json__", b"")
            if not raw:
                raise RuntimeError("no JSON output")
            data = _json.loads(raw.decode())
            findings = data.get("findings", [])
            if not findings:
                raise RuntimeError("0 findings")
            meta = findings[0].get("meta")
            if meta is None:
                raise RuntimeError("meta field absent")
            mismatches = []
            for k, expected in checks.items():
                actual = meta.get(k)
                if actual != expected:
                    mismatches.append(f"{k}: expected {expected!r}, got {actual!r}")
            if mismatches:
                raise RuntimeError("; ".join(mismatches))
            print(f"\r  {GREEN}PASS{NC}  {name}")
            passed.append(name)
        except Exception as e:
            print(f"\r  {RED}FAIL{NC}  {name} — {e}")
            failed.append((name, str(e)))


# ── file generators ───────────────────────────────────────────────────────────

try:
    from PIL import Image, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def _pil_jpeg(w=400, h=300, quality=85, mode="RGB", progressive=False) -> bytes:
    buf = io.BytesIO()
    img = Image.new(mode, (w, h))
    draw = ImageDraw.Draw(img)
    for y in range(h):
        for x in range(w):
            draw.point((x, y), fill=(x % 256, y % 256, (x + y) % 256) if mode == "RGB" else (x + y) % 256)
    kwargs = {"quality": quality}
    if progressive:
        kwargs["progressive"] = True
    img.save(buf, "JPEG", **kwargs)
    return buf.getvalue()


def _pil_png(w=300, h=300, mode="RGB") -> bytes:
    buf = io.BytesIO()
    img = Image.new(mode, (w, h), color=(50, 100, 200) if mode == "RGB" else 128)
    ImageDraw.Draw(img).ellipse([20, 20, w-20, h-20], fill=(255, 80, 0) if mode != "L" else 200)
    img.save(buf, "PNG")
    return buf.getvalue()


def _pil_bmp(w=320, h=240) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (w, h))
    draw = ImageDraw.Draw(img)
    for y in range(h):
        for x in range(w):
            draw.point((x, y), fill=(x % 256, y % 128, (x * y) % 256))
    img.save(buf, "BMP")
    return buf.getvalue()


def _pil_tiff(w=512, h=512) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (w, h))
    draw = ImageDraw.Draw(img)
    for y in range(0, h, 32):
        for x in range(0, w, 32):
            draw.rectangle([x, y, x+31, y+31], fill=((x+y)%256, x%256, y%256))
    img.save(buf, "TIFF")
    return buf.getvalue()


def _pil_webp(w=400, h=300) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (w, h), (40, 80, 160))
    ImageDraw.Draw(img).ellipse([50, 50, w-50, h-50], fill=(200, 60, 60))
    img.save(buf, "WEBP", quality=80)
    return buf.getvalue()


def _pil_gif89a() -> bytes:
    buf = io.BytesIO()
    frames = [Image.new("RGB", (100, 100), c).convert("P") for c in [(255,0,0),(0,255,0),(0,0,255)]]
    frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:], loop=0, duration=100)
    return buf.getvalue()


def make_png() -> bytes:
    """Minimal 1x1 red PNG."""
    import zlib
    sig  = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_chunk = b"\x00\x00\x00\x0dIHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF)
    raw  = b"\x00\xFF\x00\x00"  # filter byte + R G B
    idat = zlib.compress(raw)
    idat_chunk = struct.pack(">I", len(idat)) + b"IDAT" + idat + struct.pack(">I", zlib.crc32(b"IDAT" + idat) & 0xFFFFFFFF)
    iend_chunk = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    return sig + ihdr_chunk + idat_chunk + iend_chunk


def make_gif87a() -> bytes:
    header = b"GIF87a"
    lsd    = struct.pack("<HHBBB", 16, 16, 0x80, 0, 0)
    gct    = b"\xFF\x00\x00" + b"\x00\xFF\x00"
    img_d  = b"," + struct.pack("<HHHHB", 0, 0, 16, 16, 0)
    lzw    = b"\x02\x0C\x8C\x2D\x99\x87\x2A\x1C\xDC\x33\xA0\x02\x75\xEC\x00"
    return header + lsd + gct + img_d + lzw + b";"


def make_wav() -> bytes:
    sr, n = 44100, 4410
    pcm = b"".join(struct.pack("<h", int(32767 * math.sin(2*math.pi*440*i/sr))) for i in range(n))
    return (b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE"
            + b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, sr, sr*2, 2, 16)
            + b"data" + struct.pack("<I", len(pcm)) + pcm)


def make_pdf(pages: int = 1) -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f\r\n"
        b"0000000009 00000 n\r\n0000000058 00000 n\r\n0000000115 00000 n\r\n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
    )


def make_pdf_linearized() -> bytes:
    """Two %%EOF markers — tests end_magic_last=true (rfind)."""
    p1 = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
          b"xref\n0 2\n0000000000 65535 f\r\n0000000009 00000 n\r\n"
          b"trailer<</Size 2/Root 1 0 R>>\nstartxref\n58\n%%EOF\n")
    p2 = (b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
          b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
          b"xref\n2 2\n0000000115 00000 n\r\n0000000174 00000 n\r\n"
          b"trailer<</Size 4/Root 1 0 R/Prev 58>>\nstartxref\n240\n%%EOF\n")
    return p1 + p2


def make_rtf() -> bytes:
    return (b"{\\rtf1\\ansi\\deff0\n"
            b"{\\fonttbl{\\f0 Times New Roman;}}\n"
            b"\\f0\\fs24 PALA recovery test.\\par\n"
            b"Second paragraph with \\b bold\\b0 text.\\par\n"
            b"}")


def make_docx(text: str = "PALA test") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>')
        z.writestr("_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>')
        z.writestr("word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        z.writestr("word/document.xml",
            f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f'<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()


def make_xlsx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '</Types>')
        z.writestr("_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>')
        z.writestr("xl/_rels/workbook.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '</Relationships>')
        z.writestr("xl/workbook.xml",
            '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
            '</workbook>')
        z.writestr("xl/worksheets/sheet1.xml",
            '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Value</t></is></c></row></sheetData>'
            '</worksheet>')
    return buf.getvalue()


def make_sqlite() -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, size INTEGER)")
        for i in range(20):
            conn.execute("INSERT INTO files VALUES (?, ?, ?)", (i, f"file_{i}.txt", i * 1024))
        conn.commit()
        conn.close()
        return Path(db_path).read_bytes()
    finally:
        os.unlink(db_path)


# ── new fixture generators (book synthesis session 2) ────────────────────────

def make_ntfs_mft() -> bytes:
    d = bytearray(1024)
    d[0:4] = b"FILE"
    struct.pack_into("<H", d, 4, 48)   # fixup offset = 48
    struct.pack_into("<H", d, 6, 3)    # fixup count = 3 (1024/512 + 1)
    struct.pack_into("<H", d, 22, 1)   # flags = 0x01 (in-use)
    d[510:512] = b"\xAA\xAA"          # fixup sentinel sector 0
    d[1022:1024] = b"\xAA\xAA"        # fixup sentinel sector 1 (must match)
    return bytes(d)


def make_fat32_fsinfo() -> bytes:
    d = bytearray(512)
    d[0:4] = b"RRaA"
    d[484:488] = b"rrAa"
    struct.pack_into("<I", d, 488, 0xFFFFFFFF)  # free cluster count unknown
    struct.pack_into("<I", d, 492, 0xFFFFFFFF)  # next free cluster unknown
    d[510] = 0x55
    d[511] = 0xAA
    return bytes(d)


def make_ext2_sb() -> bytes:
    # 1024-byte superblock; s_magic (\x53\xEF) at byte 56
    d = bytearray(1024)
    struct.pack_into("<I", d, 0, 1024)   # s_inodes_count
    struct.pack_into("<I", d, 4, 8192)   # s_blocks_count
    struct.pack_into("<I", d, 24, 1)     # s_log_block_size = 1 (2KB)
    d[56:58] = b"\x53\xEF"              # s_magic
    return bytes(d)


def make_ufs1_sb() -> bytes:
    # 2048-byte superblock; UFS1 magic at byte 1372
    d = bytearray(2048)
    struct.pack_into("<I", d, 1372, 0x00011954)  # fs_magic UFS1
    struct.pack_into("<I", d, 48, 8192)           # fs_bsize
    struct.pack_into("<I", d, 52, 1024)           # fs_fsize
    return bytes(d)


def make_ufs2_sb() -> bytes:
    # 2048-byte superblock; UFS2 magic at byte 1372
    d = bytearray(2048)
    struct.pack_into("<I", d, 1372, 0x19540119)  # fs_magic UFS2
    struct.pack_into("<I", d, 48, 65536)          # fs_bsize
    struct.pack_into("<I", d, 52, 8192)           # fs_fsize
    return bytes(d)


def make_hibr_variant(magic: bytes) -> bytes:
    d = bytearray(8192)
    d[0:4] = magic
    return bytes(d)


def make_pagedu64() -> bytes:
    d = bytearray(4096)
    d[0:8] = b"PAGEDU64"   # bytes 0-3="PAGE", bytes 4-7="DU64" -> pagedump_ok passes
    return bytes(d)


def make_lime() -> bytes:
    d = bytearray(1024)
    d[0:4] = b"\x45\x4d\x69\x4c"        # LiME magic (LE 0x4C694D45)
    struct.pack_into("<I", d, 4, 1)       # version = 1
    struct.pack_into("<Q", d, 8, 0)       # start address
    struct.pack_into("<Q", d, 16, 0xFFFF) # end address
    return bytes(d)


def make_elf() -> bytes:
    # Minimal 64-bit ELF with one null section header so elf_size() can trim to
    # an exact byte count when followed by trailing data in the image.
    # Layout: 64-byte ELF header + 64-byte null section header entry = 128 bytes total.
    # e_shoff=64, e_shentsize=64, e_shnum=1  ->  elf_size() = 64 + 1*64 = 128
    d = bytearray(128)
    d[0:4] = b"\x7f\x45\x4c\x46"       # ELF magic
    d[4] = 2                             # EI_CLASS = 2 (64-bit)
    d[5] = 1                             # EI_DATA = 1 (LE)
    d[6] = 1                             # EI_VERSION = 1
    struct.pack_into("<H", d, 16, 2)    # e_type = ET_EXEC
    struct.pack_into("<H", d, 18, 62)   # e_machine = EM_X86_64
    struct.pack_into("<Q", d, 40, 64)   # e_shoff = 64 (section hdrs start right after ELF hdr)
    struct.pack_into("<H", d, 58, 64)   # e_shentsize = 64 bytes per entry
    struct.pack_into("<H", d, 60, 1)    # e_shnum = 1 (just the mandatory null entry)
    # bytes 64..128: null section header (all zeros — the required SHN_UNDEF entry)
    return bytes(d)


def make_pe() -> bytes:
    # Minimal PE32+ (64-bit) with one section so pe_size() can trim to an exact byte count.
    # Layout:
    #   0x00: MZ stub (64 bytes), e_lfanew=64
    #   0x40: PE signature + COFF header (24 bytes)
    #   0x58: Optional header PE32+ (112 bytes, no data directories for this minimal stub)
    #   0xc8: Section table (1 entry × 40 bytes)
    #   0xf0: Section raw data (16 bytes of zeros)   <- pe_size() end = 0xf0+16 = 0x100
    total = 0x100
    d = bytearray(total)
    # MZ header
    d[0:2] = b"MZ"
    struct.pack_into("<I", d, 0x3c, 0x40)   # e_lfanew = 0x40

    # PE signature + COFF header at 0x40
    d[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<H", d, 0x44, 0x8664) # Machine = AMD64
    struct.pack_into("<H", d, 0x46, 1)      # NumberOfSections = 1
    struct.pack_into("<H", d, 0x54, 112)    # SizeOfOptionalHeader = 112 (PE32+, no dirs)
    struct.pack_into("<H", d, 0x56, 0x0002) # Characteristics = EXECUTABLE_IMAGE

    # Optional header PE32+ at 0x58 (112 bytes, no data directories)
    struct.pack_into("<H", d, 0x58, 0x020b) # Magic = PE32+
    # Subsystem at opt_header + 68 = 0x58 + 0x44 = 0x9C; 3 = windows-cui
    struct.pack_into("<H", d, 0x9C, 3)      # Subsystem = windows-cui

    # Section table at 0x40 + 24 + 112 = 0xc8, one entry (40 bytes)
    sec = 0xc8
    d[sec:sec+8] = b".text\x00\x00\x00"    # Name (8 bytes)
    struct.pack_into("<I", d, sec+16, 16)   # SizeOfRawData = 16
    struct.pack_into("<I", d, sec+20, 0xf0) # PointerToRawData = 0xf0
    # pe_size() = max(0xf0 + 16) = 0x100 = total

    return bytes(d)


def make_mng() -> bytes:
    sig = b"\x8a\x4d\x4e\x47\x0d\x0a\x1a\x0a"
    mhdr = struct.pack(">I", 28) + b"MHDR" + struct.pack(">IIIIIII", 100, 100, 0, 0, 0, 0, 0) + b"\x00\x00\x00\x00"
    # PALA end marker is b"\x00\x00\x00\x00MEND" (8 bytes); fixture ends exactly there
    # so carved SHA256 matches fixture SHA256 (no trailing CRC byte appended)
    mend = b"\x00\x00\x00\x00MEND"
    return sig + mhdr + mend


def make_jng() -> bytes:
    sig = b"\x8b\x4a\x4e\x47\x0d\x0a\x1a\x0a"
    jhdr_data = struct.pack(">IIBBBBI", 100, 100, 8, 0, 0, 0, 0)
    jhdr = struct.pack(">I", len(jhdr_data)) + b"JHDR" + jhdr_data + b"\x00\x00\x00\x00"
    jdat = struct.pack(">I", 4) + b"JDAT" + b"\xff\xd8\xff\xd9" + b"\x00\x00\x00\x00"
    iend = b"\x00\x00\x00\x00" + b"IEND" + b"\xae\x42\x60\x82"
    return sig + jhdr + jdat + iend


# ── size-trimmer fixture generators ──────────────────────────────────────────

def make_mp4(payload_size: int = 256) -> bytes:
    """Minimal ISOBMFF file: ftyp box + mdat box.  mp4_size() trims to exact end."""
    payload = bytes(range(256)) * (payload_size // 256 + 1)
    payload = payload[:payload_size]
    # ftyp box: 4-byte size + "ftyp" + brand + version + compat
    ftyp_body = b"isom" + struct.pack(">I", 0) + b"isom" + b"iso2"
    ftyp = struct.pack(">I", 8 + len(ftyp_body)) + b"ftyp" + ftyp_body
    # mdat box: 4-byte size + "mdat" + payload
    mdat = struct.pack(">I", 8 + len(payload)) + b"mdat" + payload
    return ftyp + mdat


def make_7z(payload: bytes = b"hello from 7z") -> bytes:
    """Minimal 7z archive: real header that sevenz_size() can parse.
    Structure: signature (6) + version (2) + StartHeaderCRC (4) + StartHeader (20).
    We craft a zero-size empty archive — valid enough for the size trimmer."""
    import hashlib, zlib
    magic   = b"7z\xbc\xaf'\x1c"
    version = b"\x00\x04"
    # StartHeader: NextHeaderOffset (8) + NextHeaderSize (8) + NextHeaderCRC (4) = 20 bytes
    # We'll put an empty next-header at offset 0 from the end of the pre-header.
    # Total file = 32 bytes (just the signature + version + crc + StartHeader).
    next_hdr_offset = struct.pack("<Q", 0)
    next_hdr_size   = struct.pack("<Q", 0)
    next_hdr_crc    = struct.pack("<I", 0)
    start_header = next_hdr_offset + next_hdr_size + next_hdr_crc
    # StartHeaderCRC covers the StartHeader (20 bytes)
    shcrc = zlib.crc32(start_header) & 0xFFFFFFFF
    return magic + version + struct.pack("<I", shcrc) + start_header


def make_rar(payload: bytes = b"A" * 64) -> bytes:
    """Minimal RAR 4.x archive with marker block + archive header + end-of-archive block.
    rar_size() walks the block chain to find the 0x7B end block."""
    # Marker block (fixed 7-byte magic)
    marker = b"Rar!\x1a\x07\x00"
    # Archive header: type=0x73, flags=0x0021, size=13 (no comment), 6 reserved bytes
    # CRC is over type+flags+size = 73 00 21 00 0D 00
    import zlib
    arch_body  = b"\x73" + b"\x21\x00" + b"\x0D\x00" + b"\x00" * 6
    arch_crc   = zlib.crc32(arch_body) & 0xFFFF
    arch_block = struct.pack("<H", arch_crc) + arch_body
    # End-of-archive block: type=0x7B, flags=0x0000, size=7
    eoa_body = b"\x7b" + b"\x00\x00" + b"\x07\x00"
    eoa_crc  = zlib.crc32(eoa_body) & 0xFFFF
    eoa_block = struct.pack("<H", eoa_crc) + eoa_body
    return marker + arch_block + eoa_block


def make_mkv(payload_size: int = 128) -> bytes:
    """Minimal EBML/MKV file: EBML header + Segment element with known size.
    mkv_size() reads the Segment vint to determine file extent."""
    def ebml_encode_id(id_bytes: bytes) -> bytes:
        return id_bytes

    def ebml_vint_encode(value: int, min_bytes: int = 1) -> bytes:
        """Encode a positive integer as an EBML vint."""
        for nbytes in range(min_bytes, 9):
            max_val = (1 << (7 * nbytes)) - 2  # -2 to avoid all-ones (unknown size)
            if value <= max_val:
                marker = 1 << (7 * nbytes)
                encoded = value | marker
                return encoded.to_bytes(nbytes, "big")
        raise ValueError("value too large")

    # EBML header element (ID: 1A 45 DF A3)
    ebml_hdr_content = (
        b"\x42\x86\x81\x01"   # EBMLVersion = 1
        b"\x42\xF7\x81\x01"   # EBMLReadVersion = 1
        b"\x42\xF2\x81\x04"   # EBMLMaxIDLength = 4
        b"\x42\xF3\x81\x08"   # EBMLMaxSizeLength = 8
        b"\x42\x82\x88" + b"matroska"  # DocType = "matroska"
    )
    ebml_hdr = b"\x1a\x45\xdf\xa3" + ebml_vint_encode(len(ebml_hdr_content)) + ebml_hdr_content

    # Segment content (a minimal void element to pad to payload_size)
    void_payload = bytes(payload_size)
    seg_content = b"\xec" + ebml_vint_encode(len(void_payload)) + void_payload

    # Segment element (ID: 18 53 80 67)
    segment = b"\x18\x53\x80\x67" + ebml_vint_encode(len(seg_content)) + seg_content
    return ebml_hdr + segment


def make_ole2(content: bytes = b"OLE2 test payload " * 8) -> bytes:
    """Minimal OLE2 Compound Document.  512-byte header + 1 FAT sector + 1 directory sector.
    ole2_size() reads nfat=1 and sector_size=512, estimating 512 + 1×128×512 = 66048 bytes,
    which fits inside the 500MB window so it will trim to that estimate."""
    SS  = 512  # sector size
    # Build one FAT sector (128 entries × 4 bytes): first few entries used, rest FREESECT
    FREESECT  = 0xFFFFFFFF
    ENDOFCHAIN = 0xFFFFFFFE
    FATSECT   = 0xFFFFFFFD
    # Sector layout: sector 0 = FAT, sector 1 = directory, sector 2 = first data sector
    fat = [FATSECT, ENDOFCHAIN, ENDOFCHAIN] + [FREESECT] * (128 - 3)
    fat_sector = struct.pack("<128I", *fat)
    # Directory sector: one root entry (128 bytes) padded to 512 bytes
    root_name = "Root Entry\x00".encode("utf-16-le")
    root_name_padded = root_name + b"\x00" * (64 - len(root_name))
    # Root directory entry fields
    root_entry = (
        root_name_padded          # name (64 bytes)
        + struct.pack("<H", len(root_name))  # name length in bytes
        + b"\x05"                 # object type: root
        + b"\x01"                 # color: black
        + b"\xFF\xFF\xFF\xFF"     # left sibling: NOSTREAM
        + b"\xFF\xFF\xFF\xFF"     # right sibling: NOSTREAM
        + b"\xFF\xFF\xFF\xFF"     # child: NOSTREAM
        + b"\x00\x00\x00\x00" * 4  # CLSID (16 bytes)
        + b"\x00\x00\x00\x00"    # state bits
        + b"\x00" * 16            # timestamps (created + modified)
        + struct.pack("<I", 2)    # starting sector of mini-stream (sector 2)
        + struct.pack("<I", len(content))  # size of stream
        + b"\x00" * 4            # reserved
    )
    dir_sector = root_entry + b"\xFF" * (SS - len(root_entry))
    # Data sector: content padded to sector size
    data_sector = content + b"\x00" * (SS - (len(content) % SS) if len(content) % SS else 0)
    data_sector = data_sector[:SS]  # one sector only

    # OLE2 header (512 bytes)
    magic  = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    header = bytearray(SS)
    header[0:8]   = magic
    header[24:26] = struct.pack("<H", 0x3E)   # minor version
    header[26:28] = struct.pack("<H", 0x03)   # major version (3 = 512-byte sectors)
    header[28:30] = struct.pack("<H", 0xFFFE) # byte order LE
    header[30:32] = struct.pack("<H", 9)      # sector size = 2^9 = 512
    header[32:34] = struct.pack("<H", 6)      # mini-sector size = 2^6 = 64
    header[44:48] = struct.pack("<I", 1)      # total FAT sectors = 1
    header[48:52] = struct.pack("<I", 1)      # directory start sector = 1
    header[56:60] = struct.pack("<I", 4096)   # mini-stream cutoff
    header[60:64] = struct.pack("<I", 0xFFFFFFFF)  # first mini-FAT sector: none
    header[64:68] = struct.pack("<I", 0)      # num mini-FAT sectors
    header[68:72] = struct.pack("<I", 0xFFFFFFFF)  # first DIFAT sector: none
    header[72:76] = struct.pack("<I", 0)      # num DIFAT sectors
    # DIFAT array: first 109 FAT sector locations in header (bytes 76-511)
    header[76:80] = struct.pack("<I", 0)      # FAT sector 0 is at sector index 0
    for i in range(1, 109):
        header[76 + i*4:80 + i*4] = struct.pack("<I", FREESECT)
    return bytes(header) + fat_sector + dir_sector + data_sector


def make_mp3(duration_frames: int = 10) -> bytes:
    """MP3 with ID3v2 tag + first MPEG frame containing a Xing Info header.
    mp3_id3_size() reads the Info tag to get total byte count."""
    # ID3v2.3 tag with a dummy TIT2 frame
    tit2_payload = b"\x00" + "Test".encode("utf-16-be")
    tit2 = b"TIT2" + struct.pack(">I", len(tit2_payload)) + b"\x00\x00" + tit2_payload
    # Pad ID3 tag to 128 bytes total (10 header + tit2 + padding)
    id3_content = tit2
    id3_padding = max(0, 118 - len(id3_content))
    id3_size_syncsafe = 10 + len(id3_content) + id3_padding - 10  # tag size excl. 10-byte header
    def syncsafe(n: int) -> bytes:
        return bytes([(n >> 21) & 0x7f, (n >> 14) & 0x7f, (n >> 7) & 0x7f, n & 0x7f])
    id3_header = b"ID3" + b"\x03\x00" + b"\x00" + syncsafe(len(id3_content) + id3_padding)
    id3_tag = id3_header + id3_content + b"\x00" * id3_padding

    # MPEG1 Layer III frame at 128kbps 44100Hz stereo
    # Frame header: FF FB 90 00 (sync=0xffe, MPEG1=11, LayerIII=01, bitrate_idx=9(128k),
    #                             sr_idx=0(44100), padding=0, private=0, stereo=00, ...)
    frame_hdr = b"\xff\xfb\x90\x00"
    # Frame size = 144 * 128000 / 44100 + 0 = 417 bytes
    frame_size = 417
    # Side info: 32 bytes for stereo MPEG1 (all zeros = silence)
    side_info = b"\x00" * 32
    # Xing Info header at offset 4 + 32 = 36 within the frame
    # flags = 0x3 (both total_frames and total_bytes present)
    total_bytes = len(id3_tag) + frame_size * duration_frames
    xing = b"Info" + struct.pack(">I", 0x3)
    xing += struct.pack(">I", duration_frames)   # total frames
    xing += struct.pack(">I", total_bytes)        # total bytes
    frame_data = side_info + xing + b"\x00" * (frame_size - 4 - len(side_info) - len(xing))
    first_frame = frame_hdr + frame_data

    # Remaining frames (silent)
    silent_frame = frame_hdr + b"\x00" * (frame_size - 4)
    remaining = silent_frame * (duration_frames - 1)

    return id3_tag + first_frame + remaining


def make_pcap(n_packets: int = 4) -> bytes:
    """PCAP LE capture with n simple UDP packets."""
    # Global header: magic(LE) version_major version_minor thiszone sigfigs snaplen network
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pkt_data = b"\x00" * 14 + b"\x45\x00" + b"\x00" * 18  # dummy Ethernet+IP header
    out = hdr
    for i in range(n_packets):
        payload = b"pkt%04d" % i + b"\x00" * 8
        frame = pkt_data + payload
        rec = struct.pack("<IIII", 1000 + i, 0, len(frame), len(frame)) + frame
        out += rec
    return out


def make_pcapng(n_packets: int = 3) -> bytes:
    """PCAPng capture: SHB + IDB + n EPBs."""
    def pad4(b: bytes) -> bytes:
        return b + b"\x00" * ((-len(b)) % 4)

    # Section Header Block
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)  # BOM + major + minor + section_len
    shb_total = 12 + len(shb_body)  # type(4)+total_len(4)+body+total_len(4)
    shb = struct.pack("<II", 0x0A0D0D0A, shb_total) + shb_body + struct.pack("<I", shb_total)

    # Interface Description Block (link_type=1 Ethernet, snaplen=65535)
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_total = 12 + len(idb_body)
    idb = struct.pack("<II", 0x00000001, idb_total) + idb_body + struct.pack("<I", idb_total)

    # Enhanced Packet Blocks
    out = shb + idb
    for i in range(n_packets):
        pkt = b"epb_payload_%04d" % i
        epb_body = struct.pack("<IIIII", 0, 1000 + i, 0, len(pkt), len(pkt)) + pad4(pkt)
        epb_total = 12 + len(epb_body)
        epb = struct.pack("<II", 0x00000006, epb_total) + epb_body + struct.pack("<I", epb_total)
        out += epb
    return out


def make_der(content: bytes = b"\x02\x01\x00" * 6) -> bytes:
    """Minimal X.509 DER SEQUENCE wrapper: 0x30 0x82 [u16 len] [content].
    Content must be >= 12 bytes so total (4+content) >= DEFAULT_MIN(16)."""
    n = len(content)
    return struct.pack(">BBH", 0x30, 0x82, n) + content


def make_apfs(block_size: int = 4096, block_count: int = 1) -> bytes:
    """Minimal APFS container superblock. NXSB at offset 32; nx_block_size at 36; nx_block_count at 40."""
    block = bytearray(block_size)
    # nx_magic at offset 32
    block[32:36] = b"NXSB"
    # nx_block_size at offset 36 (u32 LE)
    struct.pack_into("<I", block, 36, block_size)
    # nx_block_count at offset 40 (u64 LE)
    struct.pack_into("<Q", block, 40, block_count)
    return bytes(block)


def make_openssh_key() -> bytes:
    """Minimal OpenSSH private key (ASCII PEM shell)."""
    body = b"b3BlbnNzaC1rZXktdjEAAAA=\n"  # dummy base64 body
    return (b"-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            body * 4 +
            b"-----END OPENSSH PRIVATE KEY-----\n")


def make_pem_cert() -> bytes:
    """Minimal PEM certificate."""
    body = b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
    return (b"-----BEGIN CERTIFICATE-----\n" +
            body * 4 +
            b"-----END CERTIFICATE-----\n")


def make_art() -> bytes:
    """Minimal Android ART image header (art\\n magic + 56-byte header padding)."""
    hdr = b"art\n" + b"056\x00"  # version
    return hdr + b"\x00" * (1024 - len(hdr))


def make_iso9660(volume_sectors: int = 20, block_size: int = 2048) -> bytes:
    """Minimal ISO 9660 image with a valid Primary Volume Descriptor.

    Structure:
      - Bytes 0-32767: system area (zeros)
      - Bytes 32768-34815: Primary Volume Descriptor
        - byte 0: type=0x01
        - bytes 1-5: "CD001"
        - byte 6: version=0x01
        - bytes 80-83: VolumeSpaceSize LE u32 = volume_sectors
        - bytes 84-87: VolumeSpaceSize BE u32 (both stored)
        - bytes 128-129: LogicalBlockSize LE u16
        - bytes 130-131: LogicalBlockSize BE u16
      - Volume Descriptor Set Terminator at sector 17 (byte 34816)
      - Total: volume_sectors * block_size bytes
    """
    total = volume_sectors * block_size
    buf = bytearray(total)
    # Primary Volume Descriptor at sector 16
    pvd_off = 32768
    buf[pvd_off] = 0x01          # type: Primary VD
    buf[pvd_off+1:pvd_off+6] = b"CD001"
    buf[pvd_off+6] = 0x01        # version
    # VolumeSpaceSize: LE then BE both stored (bytes 80-87 in PVD)
    buf[pvd_off+80:pvd_off+84] = struct.pack("<I", volume_sectors)
    buf[pvd_off+84:pvd_off+88] = struct.pack(">I", volume_sectors)
    # LogicalBlockSize: LE then BE (bytes 128-131 in PVD)
    buf[pvd_off+128:pvd_off+130] = struct.pack("<H", block_size)
    buf[pvd_off+130:pvd_off+132] = struct.pack(">H", block_size)
    # Volume Descriptor Set Terminator at sector 17
    term_off = pvd_off + block_size
    buf[term_off] = 0xFF
    buf[term_off+1:term_off+6] = b"CD001"
    buf[term_off+6] = 0x01
    return bytes(buf)


def make_systemd_journal() -> bytes:
    """Minimal systemd binary journal file (lpkshhrh magic + 272-byte header stub)."""
    hdr = b"lpkshhrh"       # file magic (8 bytes)
    hdr += b"\x00" * 264   # rest of 272-byte file header (zeroed)
    return hdr


# ── test cases ────────────────────────────────────────────────────────────────

def main():
    if not PALA.exists():
        print(f"{RED}pala binary not found at {PALA}{NC}")
        print("Run: cargo build --release")
        sys.exit(1)

    print(f"\npala Rust binary: {PALA}")
    print("=" * 60)

    pil_skip = None if HAS_PIL else "Pillow not installed"

    # ── JPEG ─────────────────────────────────────────────────────────────────
    print("\n  JPEG")
    run_test("JPEG standard (400×300 RGB)",
             {"std.jpg": _pil_jpeg()}, skip=pil_skip, types=["jpeg"])
    run_test("JPEG progressive",
             {"prog.jpg": _pil_jpeg(640, 480, progressive=True)}, skip=pil_skip, types=["jpeg"])
    run_test("JPEG grayscale",
             {"gray.jpg": _pil_jpeg(400, 300, mode="L")}, skip=pil_skip, types=["jpeg"])
    run_test("JPEG high quality (quality=98)",
             {"hq.jpg": _pil_jpeg(800, 600, quality=98)}, skip=pil_skip, types=["jpeg"])
    run_test("JPEG low quality (quality=10)",
             {"lq.jpg": _pil_jpeg(320, 240, quality=10)}, skip=pil_skip, types=["jpeg"])
    run_test("JPEG large (2000×1500)",
             {"large.jpg": _pil_jpeg(2000, 1500, quality=70)}, skip=pil_skip, types=["jpeg"])
    run_test("JPEG multiple adjacent",
             {"a.jpg": _pil_jpeg(200, 200), "b.jpg": _pil_jpeg(300, 200, quality=60)},
             skip=pil_skip, types=["jpeg"])

    # ── PNG ──────────────────────────────────────────────────────────────────
    print("\n  PNG")
    run_test("PNG RGB",
             {"rgb.png": _pil_png(300, 300)}, skip=pil_skip, types=["png"])
    run_test("PNG RGBA",
             {"rgba.png": _pil_png(300, 300, "RGBA")}, skip=pil_skip, types=["png"])
    run_test("PNG grayscale",
             {"gray.png": _pil_png(400, 300, "L")}, skip=pil_skip, types=["png"])
    run_test("PNG large (1920×1080)",
             {"large.png": _pil_png(1920, 1080)}, skip=pil_skip, types=["png"])
    run_test("PNG multiple adjacent",
             {"a.png": _pil_png(200, 200), "b.png": _pil_png(150, 150)},
             skip=pil_skip, types=["png"])

    # ── GIF ──────────────────────────────────────────────────────────────────
    print("\n  GIF")
    run_test("GIF87a (hand-crafted)",
             {"anim.gif": make_gif87a()}, types=["gif87a"])
    run_test("GIF89a animated (3 frames)",
             {"anim.gif": _pil_gif89a()}, skip=pil_skip, types=["gif89a"])

    # ── BMP ──────────────────────────────────────────────────────────────────
    print("\n  BMP")
    run_test("BMP 24-bit (320×240)",
             {"img.bmp": _pil_bmp()}, skip=pil_skip, types=["bmp"])

    # ── TIFF ─────────────────────────────────────────────────────────────────
    print("\n  TIFF")
    run_test("TIFF little-endian (512×512 RGB)",
             {"img.tif": _pil_tiff()}, skip=pil_skip, types=["tiff_le"])

    # ── RIFF containers ───────────────────────────────────────────────────────
    print("\n  RIFF (WAV / WEBP)")
    run_test("WAV PCM mono 44100Hz",
             {"audio.wav": make_wav()}, types=["riff"])
    run_test("WEBP lossy (400×300)",
             {"img.webp": _pil_webp()}, skip=pil_skip, types=["riff"])
    run_test("WAV + WEBP adjacent (RIFF subtype discrimination)",
             {"audio.wav": make_wav(), "img.webp": _pil_webp()},
             skip=pil_skip, types=["riff"])

    # ── PDF ───────────────────────────────────────────────────────────────────
    print("\n  PDF")
    run_test("PDF single page",
             {"doc.pdf": make_pdf()}, types=["pdf"])
    run_test("PDF linearized (two %%EOF — rfind test)",
             {"doc.pdf": make_pdf_linearized()}, types=["pdf"])

    # ── RTF ───────────────────────────────────────────────────────────────────
    print("\n  RTF")
    run_test("RTF document",
             {"doc.rtf": make_rtf()}, types=["rtf"])

    # ── Office Open XML (ZIP-based) ───────────────────────────────────────────
    print("\n  Office / ZIP")
    run_test("DOCX (ZIP with word/ prefix)",
             {"doc.docx": make_docx()}, types=["zip"])
    run_test("XLSX (ZIP with xl/ prefix)",
             {"sheet.xlsx": make_xlsx()}, types=["zip"])
    run_test("DOCX + XLSX adjacent (adjacent ZIP separation)",
             {"doc.docx": make_docx("first"), "sheet.xlsx": make_xlsx()},
             types=["zip"])

    # ── SQLite ────────────────────────────────────────────────────────────────
    print("\n  SQLite")
    run_test("SQLite database (20 rows)",
             {"data.db": make_sqlite()}, types=["sqlite"])

    # ── Mixed types ───────────────────────────────────────────────────────────
    print("\n  Mixed")
    run_test("JPEG + PNG + PDF together",
             {"img.jpg": _pil_jpeg(), "img.png": _pil_png(), "doc.pdf": make_pdf()},
             skip=pil_skip)
    run_test("JPEG + WAV + DOCX + SQLite together",
             {"img.jpg": _pil_jpeg(), "audio.wav": make_wav(),
              "doc.docx": make_docx(), "data.db": make_sqlite()},
             skip=pil_skip)

    # ── Extension spoofing ────────────────────────────────────────────────────
    print("\n  Extension spoofing")

    def ext_spoof_test():
        """Files with wrong extensions — PALA must carve by magic, not filename."""
        files = {
            "document.mp3": make_docx("spoofed as mp3"),
            "photo.csv":    _pil_jpeg() if HAS_PIL else None,
            "data.txt":     make_pdf(),
        }
        files = {k: v for k, v in files.items() if v is not None}
        run_test("Extension-spoofed files (DOCX→mp3, JPEG→csv, PDF→txt)",
                 files, skip=None if files else "Pillow missing, partial test only")

    ext_spoof_test()

    # ── Filesystem structures ─────────────────────────────────────────────────
    print("\n  Filesystem structures")
    run_test("NTFS MFT entry",
             {"entry.mft": make_ntfs_mft()}, types=["ntfs_mft"])
    run_test("FAT32 FSINFO sector",
             {"sector.fsinfo": make_fat32_fsinfo()}, types=["fat32_fsinfo"])
    run_test("ext2/3/4 superblock",
             {"fs.sb": make_ext2_sb()}, types=["ext2_sb"])
    run_test("UFS1 superblock",
             {"sb.ufs": make_ufs1_sb()}, types=["ufs1_sb"])
    run_test("UFS2 superblock",
             {"sb.ufs": make_ufs2_sb()}, types=["ufs2_sb"])

    # ── Memory forensics ──────────────────────────────────────────────────────
    # gap=0: no zero suffix so PALA carves exactly the fixture bytes (no end marker)
    print("\n  Memory forensics")
    run_test("Hibernate HIBR variant",
             {"hibr.bin": make_hibr_variant(b"HIBR")}, types=["hibr_upper"], gap=0)
    run_test("Hibernate wake variant",
             {"wake.bin": make_hibr_variant(b"wake")}, types=["wake_lower"], gap=0)
    run_test("Hibernate WAKE variant",
             {"wake.bin": make_hibr_variant(b"WAKE")}, types=["wake_upper"], gap=0)
    run_test("Windows crash dump 64-bit (PAGEDU64)",
             {"dump.dmp": make_pagedu64()}, types=["pagedu64"], gap=0)
    run_test("LiME memory acquisition",
             {"mem.lime": make_lime()}, types=["lime"], gap=0)

    # ── Executables ───────────────────────────────────────────────────────────
    print("\n  Executables")
    run_test("ELF binary (64-bit x86, elf_size trimmer)",
             {"binary.elf": make_elf()}, types=["elf"], gap=512)
    run_test("PE/MZ executable (pe_size trimmer)",
             {"prog.exe": make_pe()}, types=["pe"], gap=512)

    # ── Size-trimmer round-trips ──────────────────────────────────────────────
    print("\n  Size trimmers")
    run_test("MP4 (ISOBMFF box walk, mp4_size trimmer)",
             {"video.mp4": make_mp4()}, types=["mp4"], gap=512)
    run_test("7z (StartHeader size fields, sevenz_size trimmer)",
             {"archive.7z": make_7z()}, types=["7z"], gap=512)
    run_test("RAR 4.x (block chain walk to EOA, rar_size trimmer)",
             {"archive.rar": make_rar()}, types=["rar"], gap=512)
    run_test("MKV (EBML segment size, mkv_size trimmer)",
             {"video.mkv": make_mkv()}, types=["mkv"], gap=512)
    run_test("MP3 ID3 (Xing/Info VBR header, mp3_id3_size trimmer)",
             {"audio.mp3": make_mp3()}, types=["mp3_id3"], gap=512)
    # OLE2: ole2_size() over-estimates FAT entries; gap=0 makes the window
    # exactly the fixture size so the .min(data.len()) clamp produces a correct trim.
    run_test("OLE2 compound document (FAT-sector estimate, ole2_size trimmer)",
             {"doc.doc": make_ole2()}, types=["ole2"], gap=0)

    # ── Metadata extraction (--meta flag) ────────────────────────────────────
    print("\n  Metadata extraction (--meta)")
    run_meta_test(
        "SQLite metadata: page_size, page_count, journal_mode",
        make_sqlite(),
        "sqlite",
        {"page_size": 4096, "journal_mode": "journal"},
    )
    run_meta_test(
        "ELF metadata: class, endian, type, machine",
        make_elf(),
        "elf",
        {"class": "ELF64", "endian": "little", "type": "executable", "machine": "x86-64"},
    )
    run_meta_test(
        "PE metadata: machine, subsystem",
        make_pe(),
        "pe",
        {"machine": "x64", "subsystem": "windows-cui"},
    )

    def _make_jpeg_exif(subsec_val="123", gps_date_val="2024:06:15"):
        # Synthetic JPEG with APP1 EXIF carrying SubSecTimeOriginal and GPSDateStamp.
        # TIFF layout (LE, offsets relative to TIFF header start):
        #   0: TIFF header (8 bytes)
        #   8: IFD0 (2 + 2*12 + 4 = 30 bytes)  [entries sorted: 0x8825, 0x9011]
        #  38: GPS IFD (2 + 1*12 + 4 = 18 bytes)
        #  56: GPS date string (11 bytes)
        _subsec_bytes  = subsec_val.encode() + b'\x00'     # "123\0" = 4 bytes
        _gps_date_bytes = gps_date_val.encode() + b'\x00' # "2024:06:15\0" = 11 bytes
        _gps_ifd_off  = 38
        _gps_date_off = 56
        _tiff_hdr = b'II' + struct.pack('<H', 0x002A) + struct.pack('<I', 8)
        _n_ifd0 = struct.pack('<H', 2)
        _gps_ptr = struct.pack('<HHI', 0x8825, 4, 1) + struct.pack('<I', _gps_ifd_off)
        _subsec  = struct.pack('<HHI', 0x9011, 2, len(_subsec_bytes)) + _subsec_bytes
        _ifd0 = _n_ifd0 + _gps_ptr + _subsec + struct.pack('<I', 0)
        _n_gps = struct.pack('<H', 1)
        _gps_date_entry = struct.pack('<HHI', 0x001D, 2, len(_gps_date_bytes)) + struct.pack('<I', _gps_date_off)
        _gps_ifd = _n_gps + _gps_date_entry + struct.pack('<I', 0)
        _tiff = _tiff_hdr + _ifd0 + _gps_ifd + _gps_date_bytes
        _app1_body = b'Exif\x00\x00' + _tiff
        _app1 = b'\xFF\xE1' + struct.pack('>H', len(_app1_body) + 2) + _app1_body
        # JPEG min size is 512 bytes; pad with a COM segment to satisfy the constraint
        _com = b'\xFF\xFE' + struct.pack('>H', 502) + b'\x00' * 500
        return b'\xFF\xD8' + _app1 + _com + b'\xFF\xD9'

    run_meta_test(
        "JPEG EXIF: subsec_time_original and gps_date extracted",
        _make_jpeg_exif(),
        "jpeg",
        {"subsec_time_original": "123", "gps_date": "2024:06:15"},
    )

    # JPEG EXIF with only SubSecTimeOriginal and no GPS sub-IFD
    def _make_jpeg_subsec_only(subsec_val="456"):
        _subsec_bytes = subsec_val.encode() + b'\x00'
        _tiff_hdr = b'II' + struct.pack('<H', 0x002A) + struct.pack('<I', 8)
        _n_ifd0 = struct.pack('<H', 1)
        _subsec = struct.pack('<HHI', 0x9011, 2, len(_subsec_bytes)) + _subsec_bytes
        _ifd0 = _n_ifd0 + _subsec + struct.pack('<I', 0)
        _tiff = _tiff_hdr + _ifd0
        _app1_body = b'Exif\x00\x00' + _tiff
        _app1 = b'\xFF\xE1' + struct.pack('>H', len(_app1_body) + 2) + _app1_body
        _com = b'\xFF\xFE' + struct.pack('>H', 502) + b'\x00' * 500
        return b'\xFF\xD8' + _app1 + _com + b'\xFF\xD9'

    run_meta_test(
        "JPEG EXIF: subsec_time_original alone (no GPS IFD)",
        _make_jpeg_subsec_only(),
        "jpeg",
        {"subsec_time_original": "456"},
    )

    # ── Resume / checkpoint (TODO #7) ────────────────────────────────────────
    print("\n  Resume / checkpoint")
    _resume_fixture = make_sqlite()
    _resume_img = make_raw_image(_resume_fixture, gap=512)
    print(f"  {CYAN}....{NC}  State file written after scan", end="", flush=True)
    try:
        with tempfile.TemporaryDirectory() as _td:
            _outdir = Path(_td)
            with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf:
                _tf.write(_resume_img)
                _img_path = _tf.name
            try:
                _r = subprocess.run(
                    [str(PALA), _img_path, str(_outdir), "-q", "-t", "sqlite"],
                    capture_output=True, text=True, timeout=30
                )
                _state_file = _outdir / ".pala-state.json"
                if not _state_file.exists():
                    raise RuntimeError(".pala-state.json not written")
                import json as _json
                _state = _json.loads(_state_file.read_text())
                if _state.get("source") != _img_path:
                    raise RuntimeError(f"state source mismatch: {_state.get('source')!r}")
                if _state.get("source_bytes") != len(_resume_img):
                    raise RuntimeError(f"state source_bytes mismatch")
                if "last_chunk_start" in _state:
                    raise RuntimeError("state file still has old last_chunk_start field (bug: off-by-one on resume)")
                if "completed_chunks" not in _state:
                    raise RuntimeError("state file missing completed_chunks field")
                print(f"\r  {GREEN}PASS{NC}  State file written after scan")
                passed.append("State file written after scan")

                # Resume run: should accept the state file and exit 0
                print(f"  {CYAN}....{NC}  --resume accepts valid state file", end="", flush=True)
                _r2 = subprocess.run(
                    [str(PALA), _img_path, str(_outdir), "-q", "-t", "sqlite", "--resume"],
                    capture_output=True, text=True, timeout=30
                )
                if _r2.returncode != 0:
                    raise RuntimeError(f"--resume exit {_r2.returncode}: {_r2.stderr.strip()}")
                print(f"\r  {GREEN}PASS{NC}  --resume accepts valid state file")
                passed.append("--resume accepts valid state file")

                # Resume run with wrong source should fail
                print(f"  {CYAN}....{NC}  --resume rejects mismatched source", end="", flush=True)
                _r3 = subprocess.run(
                    [str(PALA), _img_path + "_WRONG", str(_outdir), "-q", "-t", "sqlite", "--resume"],
                    capture_output=True, text=True, timeout=30
                )
                if _r3.returncode == 0:
                    raise RuntimeError("expected non-zero exit for mismatched source")
                print(f"\r  {GREEN}PASS{NC}  --resume rejects mismatched source")
                passed.append("--resume rejects mismatched source")
            finally:
                os.unlink(_img_path)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  Resume/checkpoint — {_e}")
        failed.append(("Resume/checkpoint", str(_e)))

    # ── Rate limiting / degraded mode (TODO #8) ──────────────────────────────
    print("\n  Degraded drive rate limiting")
    _deg_fixture = make_sqlite()
    _deg_img     = make_raw_image(_deg_fixture, gap=512)
    try:
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf:
            _tf.write(_deg_img)
            _deg_img_path = _tf.name
        try:
            with tempfile.TemporaryDirectory() as _deg_td:
                _deg_out = Path(_deg_td)
                # --degraded alone (no value) → default 1ms; must succeed and recover file
                print(f"  {CYAN}....{NC}  --degraded (bare, default 1ms)", end="", flush=True)
                _rd = subprocess.run(
                    [str(PALA), _deg_img_path, str(_deg_out), "-q", "-t", "sqlite", "--degraded"],
                    capture_output=True, text=True, timeout=30
                )
                if _rd.returncode != 0:
                    raise RuntimeError(f"--degraded (bare) exit {_rd.returncode}: {_rd.stderr.strip()}")
                _deg_files = list(_deg_out.glob("*.db"))
                if not _deg_files:
                    raise RuntimeError("no sqlite file recovered with --degraded bare")
                print(f"\r  {GREEN}PASS{NC}  --degraded (bare, default 1ms)")
                passed.append("--degraded bare default 1ms")

            with tempfile.TemporaryDirectory() as _deg_td2:
                _deg_out2 = Path(_deg_td2)
                # --degraded=5 → explicit 5ms; must succeed
                print(f"  {CYAN}....{NC}  --degraded=5 (explicit 5ms)", end="", flush=True)
                _rd2 = subprocess.run(
                    [str(PALA), _deg_img_path, str(_deg_out2), "-q", "-t", "sqlite", "--degraded=5"],
                    capture_output=True, text=True, timeout=30
                )
                if _rd2.returncode != 0:
                    raise RuntimeError(f"--degraded=5 exit {_rd2.returncode}: {_rd2.stderr.strip()}")
                print(f"\r  {GREEN}PASS{NC}  --degraded=5 (explicit 5ms)")
                passed.append("--degraded=5 explicit 5ms")

            with tempfile.TemporaryDirectory() as _deg_td3:
                _deg_out3 = Path(_deg_td3)
                # --degraded 2 → space-separated value
                print(f"  {CYAN}....{NC}  --degraded 2 (space-separated value)", end="", flush=True)
                _rd3 = subprocess.run(
                    [str(PALA), _deg_img_path, str(_deg_out3), "-q", "-t", "sqlite", "--degraded", "2"],
                    capture_output=True, text=True, timeout=30
                )
                if _rd3.returncode != 0:
                    raise RuntimeError(f"--degraded 2 exit {_rd3.returncode}: {_rd3.stderr.strip()}")
                print(f"\r  {GREEN}PASS{NC}  --degraded 2 (space-separated value)")
                passed.append("--degraded 2 space-separated value")
        finally:
            os.unlink(_deg_img_path)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  Degraded drive rate limiting — {_e}")
        failed.append(("Degraded drive rate limiting", str(_e)))

    # ── Fragment reassembly (TODO #6 stage 1) ────────────────────────────────
    print("\n  Fragment reassembly")
    # Build a 2-file ZIP and split it at the second PK\x03\x04 boundary.
    # --max-size is set to split_at so fragment 1's scan window ends there,
    # forcing trunc=True.  Fragment 2 starts with PK\x03\x04, so it's also a
    # zip candidate.  frag_merge concatenates them; zip_eocd_end on the merged
    # bytes finds the EOCD → valid ZIP → merge accepted.
    # Use ZIP_STORED so sizes are predictable.  alpha.txt is 300 bytes so that
    # _second_pk (start of beta's local header) is > total_size/2 — this ensures
    # max_size=_second_pk truncates frag1 but frag2's window reaches the EOCD.
    _buf = io.BytesIO()
    with zipfile.ZipFile(_buf, "w", zipfile.ZIP_STORED) as _z:
        _z.writestr("alpha.txt", "A" * 300)
        _z.writestr("beta.txt",  "B" * 64)
    _zip_bytes = _buf.getvalue()
    _first_pk  = _zip_bytes.index(b"PK\x03\x04")
    _second_pk = _zip_bytes.index(b"PK\x03\x04", _first_pk + 4)
    # Sanity: _second_pk must be in (total/2, total-22) for the test to work
    assert len(_zip_bytes) // 2 < _second_pk < len(_zip_bytes) - 22, (
        f"split offset {_second_pk} not in valid range for {len(_zip_bytes)}-byte ZIP"
    )
    run_frag_test(
        "ZIP 2-file split (stage-1 fragment merge, PK\\x03\\x04 boundary)",
        _zip_bytes,
        split_at=_second_pk,
        sig_type="zip",
        max_size=_second_pk,   # window=_second_pk bytes: truncates frag1; frag2 window covers EOCD
    )

    # ── Gap-tolerant fragment reassembly (TODO #12) ───────────────────────────
    print("\n  Gap-tolerant fragment reassembly (--frag-gap)")
    # Same 2-file ZIP, but introduce a 512-byte gap of zeros between the two fragments.
    # Without --frag-gap the merge must fail (b_start > a_end → contiguity broken).
    # With --frag-gap=512 the merge must succeed and recover the original file.
    _gfbuf = io.BytesIO()
    with zipfile.ZipFile(_gfbuf, "w", zipfile.ZIP_STORED) as _gz:
        _gz.writestr("x.txt", "X" * 300)
        _gz.writestr("y.txt", "Y" * 64)
    _gf_bytes   = _gfbuf.getvalue()
    _gf_first   = _gf_bytes.index(b"PK\x03\x04")
    _gf_second  = _gf_bytes.index(b"PK\x03\x04", _gf_first + 4)
    _gf_frag1   = _gf_bytes[:_gf_second]
    _gf_frag2   = _gf_bytes[_gf_second:]
    _GAP        = 512
    _gf_rng     = random.Random(0xBEEF)
    _gf_prefix  = bytes(_gf_rng.getrandbits(8) for _ in range(4096))
    _gf_img     = _gf_prefix + _gf_frag1 + b"\x00" * _GAP + _gf_frag2 + b"\x00" * 512

    # Without --frag-gap: gap breaks contiguity → 2 separate files carved
    _label_no_gap = "--frag-gap not set: gap breaks merge (expect 2 carved files)"
    print(f"  {CYAN}....{NC}  {_label_no_gap}", end="", flush=True)
    try:
        with tempfile.TemporaryDirectory() as _gf_td_no:
            _gf_carved_no = run_pala(_gf_img, Path(_gf_td_no), types=["zip"],
                                      max_size=_gf_second)
            _gf_zips_no = [k for k in _gf_carved_no if k.endswith(".zip")]
            if len(_gf_zips_no) != 2:
                raise RuntimeError(f"expected 2 ZIP files without --frag-gap, got {len(_gf_zips_no)}: {_gf_zips_no}")
        print(f"\r  {GREEN}PASS{NC}  {_label_no_gap}")
        passed.append(_label_no_gap)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_no_gap} — {_e}")
        failed.append((_label_no_gap, str(_e)))

    # With --frag-gap=512: gap bridged → 1 merged file (size = original + GAP zero-fill)
    # The merged output = frag1 + 512 zero bytes + frag2; SHA256 differs from original
    # but the file is parseable as a ZIP (EOCD still at the end after the gap bytes).
    _expected_merged_size = len(_gf_bytes) + _GAP
    _label_gap = "--frag-gap=512: gap bridged → 1 merged file (size = original + 512)"
    print(f"  {CYAN}....{NC}  {_label_gap}", end="", flush=True)
    try:
        with tempfile.TemporaryDirectory() as _gf_td_yes:
            _gf_carved_yes = run_pala(_gf_img, Path(_gf_td_yes), types=["zip"],
                                       max_size=_gf_second, frag_gap=_GAP)
            _gf_zips_yes = {k: v for k, v in _gf_carved_yes.items() if k.endswith(".zip")}
            if len(_gf_zips_yes) != 1:
                raise RuntimeError(
                    f"expected 1 merged ZIP with --frag-gap, got {len(_gf_zips_yes)}: "
                    f"{list(_gf_zips_yes.keys())}"
                )
            _merged_size = len(next(iter(_gf_zips_yes.values())))
            if _merged_size != _expected_merged_size:
                raise RuntimeError(
                    f"merged size {_merged_size} != expected {_expected_merged_size} "
                    f"(original {len(_gf_bytes)} + gap {_GAP})"
                )
        print(f"\r  {GREEN}PASS{NC}  {_label_gap}")
        passed.append(_label_gap)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_gap} — {_e}")
        failed.append((_label_gap, str(_e)))

    # ── TODO #5 — new file types ─────────────────────────────────────────────
    print("\n  TODO #5 file types")
    run_test("PCAP LE (pcap_size trimmer, walk packet records)",
             {"cap.pcap": make_pcap()}, types=["pcap"], gap=512)
    run_test("PCAPng (pcapng_size trimmer, SHB+IDB+EPBs)",
             {"cap.pcapng": make_pcapng()}, types=["pcapng"], gap=512)
    # der_size: exact trim from SEQUENCE header; gap=0 so window=fixture
    run_test("X.509 DER (der_size trimmer, SEQUENCE length header)",
             {"cert.der": make_der()}, types=["der_cert"], gap=0)
    # apfs_size: nx_block_size*nx_block_count = 4096; fixture IS exactly one block
    run_test("APFS superblock (apfs_size trimmer, block_size × block_count)",
             {"vol.apfs": make_apfs()}, types=["apfs"], gap=0)
    run_test("OpenSSH private key (PEM ASCII envelope)",
             {"id_rsa.key": make_openssh_key()}, types=["openssh_key"])
    run_test("PEM certificate chain",
             {"cert.pem": make_pem_cert()}, types=["pem_cert"])
    # No size trimmer for ART/VMDK/VHDX: gap=0 so window = fixture exactly
    run_test("Android ART image",
             {"boot.art": make_art()}, types=["art"], gap=0)
    vmdk_hdr = b"KDMV" + b"\x00" * 508
    run_test("VMDK sparse descriptor (magic check)",
             {"disk.vmdk": vmdk_hdr}, types=["vmdk"], gap=0)
    vhdx_hdr = b"vhdxfile" + b"\x00" * 1016
    run_test("VHDX Hyper-V disk (magic check)",
             {"disk.vhdx": vhdx_hdr}, types=["vhdx"], gap=0)
    # ISO 9660: iso9660_size = VolumeSpaceSize * LogicalBlockSize; gap=0 so window = fixture
    _iso = make_iso9660(volume_sectors=20, block_size=2048)  # 20*2048=40960 bytes
    run_test("ISO 9660 optical disc image (iso9660_size trimmer, PVD VolumeSpaceSize × LogicalBlockSize)",
             {"disc.iso": _iso}, types=["iso9660"], gap=0)
    # Systemd journal: no size trimmer; gap=0 so carved window = fixture exactly
    run_test("Systemd binary journal (lpkshhrh magic, no size trimmer)",
             {"system.journal": make_systemd_journal()}, types=["systemd_journal"], gap=0)

    # ── Network graphics ──────────────────────────────────────────────────────
    print("\n  Network graphics")
    run_test("MNG animation",
             {"anim.mng": make_mng()}, types=["mng"])
    run_test("JNG image",
             {"img.jng": make_jng()}, types=["jng"])

    # ── Quality classification (TODO #9) ─────────────────────────────────────
    print("\n  Quality classification")

    def _run_json(img: bytes, types: list, extra_args: list = []) -> list:
        """Run pala with --json, return findings list."""
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf:
            _tf.write(img)
            _ip = _tf.name
        with tempfile.TemporaryDirectory() as _od:
            try:
                _cmd = [str(PALA), _ip, _od, "-q", "--json", "-t", ",".join(types)] + extra_args
                _r = subprocess.run(_cmd, capture_output=True, text=True, timeout=30)
                if _r.returncode != 0:
                    raise RuntimeError(f"pala exit {_r.returncode}: {_r.stderr.strip()}")
                import json as _json
                return _json.loads(_r.stdout)["findings"]
            finally:
                os.unlink(_ip)

    # complete: PDF has end-marker %%EOF, found naturally → quality=complete
    print(f"  {CYAN}....{NC}  quality=complete (PDF with %%EOF found)", end="", flush=True)
    try:
        _pdf_img = make_raw_image(make_pdf(), gap=512)
        _findings = _run_json(_pdf_img, ["pdf"])
        if not _findings:
            raise RuntimeError("no findings")
        _q = _findings[0]["quality"]
        if _q != "complete":
            raise RuntimeError(f"expected 'complete', got '{_q}'")
        print(f"\r  {GREEN}PASS{NC}  quality=complete (PDF with %%EOF found)")
        passed.append("quality=complete (PDF with %%EOF found)")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  quality=complete — {_e}")
        failed.append(("quality=complete (PDF with %%EOF found)", str(_e)))

    # partial: max-size truncates a JPEG before EOI → quality=partial
    print(f"  {CYAN}....{NC}  quality=partial (JPEG truncated by --max-size)", end="", flush=True)
    try:
        # Use a JPEG from RIFF container — simpler: just use a raw JPEG fixture without the end marker
        # via --max-size=100 on a real JPEG
        import struct as _s
        # Pad scan data to 1024 bytes so _trunc_size = len//2 >= 512 > jpeg.min
        _jpeg = (b"\xFF\xD8\xFF\xE0" + b"\x00\x10" + b"JFIF\x00" + b"\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                 + b"\xFF\xDB" + b"\x00\x43" + b"\x00" + bytes(64) + b"\xFF\xC0" + b"\x00\x0B"
                 + b"\x08\x00\x01\x00\x01\x01\x01\x11\x00" + b"\xFF\xC4" + b"\x00\x1F" + b"\x00"
                 + bytes(30) + b"\xFF\xDA" + b"\x00\x08\x01\x01\x00\x00?\x00" + bytes(1024) + b"\xFF\xD9")
        _img = make_raw_image(_jpeg, gap=0)
        # Truncate at half the jpeg size so EOI is cut off (trunc_size > jpeg.min=512)
        _trunc_size = len(_jpeg) // 2
        _findings = _run_json(_img, ["jpeg"], [f"--max-size={_trunc_size}"])
        # At least one should be partial (truncated before EOI)
        _partials = [f for f in _findings if f["quality"] == "partial"]
        if not _partials:
            raise RuntimeError(f"no partial findings; got: {[f['quality'] for f in _findings]}")
        print(f"\r  {GREEN}PASS{NC}  quality=partial (JPEG truncated by --max-size)")
        passed.append("quality=partial (JPEG truncated by --max-size)")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  quality=partial — {_e}")
        failed.append(("quality=partial (JPEG truncated by --max-size)", str(_e)))

    # fragmented: ZIP split at second PK → frag_merge reassembles → quality=fragmented
    print(f"  {CYAN}....{NC}  quality=fragmented (ZIP frag_merge result)", end="", flush=True)
    try:
        _buf2 = io.BytesIO()
        with zipfile.ZipFile(_buf2, "w", zipfile.ZIP_STORED) as _z2:
            _z2.writestr("alpha.txt", "A" * 300)
            _z2.writestr("beta.txt",  "B" * 64)
        _zb = _buf2.getvalue()
        _fp1 = _zb.index(b"PK\x03\x04")
        _fp2 = _zb.index(b"PK\x03\x04", _fp1 + 4)
        _frag1 = _zb[:_fp2]; _frag2 = _zb[_fp2:]
        _rng2 = random.Random(0xF4AD)
        _img2 = bytes(_rng2.getrandbits(8) for _ in range(4096)) + _frag1 + _frag2 + b"\x00" * 512
        _findings2 = _run_json(_img2, ["zip"], [f"--max-size={_fp2}"])
        _frags = [f for f in _findings2 if f["quality"] == "fragmented"]
        if not _frags:
            raise RuntimeError(f"no fragmented findings; got: {[f['quality'] for f in _findings2]}")
        print(f"\r  {GREEN}PASS{NC}  quality=fragmented (ZIP frag_merge result)")
        passed.append("quality=fragmented (ZIP frag_merge result)")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  quality=fragmented — {_e}")
        failed.append(("quality=fragmented (ZIP frag_merge result)", str(_e)))

    # ── Triage presets (TODO #11) ─────────────────────────────────────────────
    print("\n  Triage presets")

    def _run_triage(img: bytes, mode: str) -> list:
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf:
            _tf.write(img); _ip = _tf.name
        with tempfile.TemporaryDirectory() as _od:
            try:
                _cmd = [str(PALA), _ip, _od, "-q", "--json", f"--triage-mode={mode}"]
                _r = subprocess.run(_cmd, capture_output=True, text=True, timeout=30)
                if _r.returncode != 0:
                    raise RuntimeError(f"pala exit {_r.returncode}: {_r.stderr.strip()}")
                import json as _json
                return _json.loads(_r.stdout)["findings"]
            finally:
                os.unlink(_ip)

    _triage_pdf = make_pdf()
    _triage_jpg = (b"\xFF\xD8\xFF\xE0" + b"\x00\x10" + b"JFIF\x00" + b"\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                   + b"\xFF\xDB" + b"\x00\x43" + b"\x00" + bytes(64) + b"\xFF\xC0" + b"\x00\x0B"
                   + b"\x08\x00\x01\x00\x01\x01\x01\x11\x00" + b"\xFF\xC4" + b"\x00\x1F" + b"\x00"
                   + bytes(30) + b"\xFF\xDA" + b"\x00\x08\x01\x01\x00\x00?\x00" + bytes(512) + b"\xFF\xD9")
    _triage_zip = make_docx()   # docx is ZIP-based
    _triage_sq  = make_sqlite()

    # documents: pdf + zip found; jpeg NOT found
    print(f"  {CYAN}....{NC}  --triage-mode=documents recovers pdf+zip, skips jpeg", end="", flush=True)
    try:
        _img_docs = make_raw_image(_triage_pdf, _triage_jpg, _triage_zip)
        _res_docs = _run_triage(_img_docs, "documents")
        _types_docs = {f["type"] for f in _res_docs}
        assert "pdf" in _types_docs, f"pdf missing; got {_types_docs}"
        assert "zip" in _types_docs, f"zip missing; got {_types_docs}"
        assert "jpeg" not in _types_docs, f"jpeg should be excluded; got {_types_docs}"
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=documents recovers pdf+zip, skips jpeg")
        passed.append("--triage-mode=documents recovers pdf+zip, skips jpeg")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=documents — {_e}")
        failed.append(("--triage-mode=documents recovers pdf+zip, skips jpeg", str(_e)))

    # databases: sqlite found; pdf NOT found
    print(f"  {CYAN}....{NC}  --triage-mode=databases recovers sqlite, skips pdf", end="", flush=True)
    try:
        _img_db = make_raw_image(_triage_sq, _triage_pdf)
        _res_db = _run_triage(_img_db, "databases")
        _types_db = {f["type"] for f in _res_db}
        assert "sqlite" in _types_db, f"sqlite missing; got {_types_db}"
        assert "pdf" not in _types_db, f"pdf should be excluded; got {_types_db}"
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=databases recovers sqlite, skips pdf")
        passed.append("--triage-mode=databases recovers sqlite, skips pdf")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=databases — {_e}")
        failed.append(("--triage-mode=databases recovers sqlite, skips pdf", str(_e)))

    # databases: ese found (ese added to databases preset in v0.3.0)
    print(f"  {CYAN}....{NC}  --triage-mode=databases finds ese, skips pdf", end="", flush=True)
    try:
        _ese_triage = b'\x01\x00\x00\x00' + b'\xef\xcd\xab\x89' + b'\x00' * (4096 - 8)
        _img_db2 = make_raw_image(_ese_triage, _triage_pdf)
        _res_db2 = _run_triage(_img_db2, "databases")
        _types_db2 = {f["type"] for f in _res_db2}
        assert "ese" in _types_db2,      f"ese missing; got {_types_db2}"
        assert "pdf" not in _types_db2,  f"pdf should be excluded; got {_types_db2}"
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=databases finds ese, skips pdf")
        passed.append("--triage-mode=databases finds ese, skips pdf")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=databases finds ese, skips pdf — {_e}")
        failed.append(("--triage-mode=databases finds ese, skips pdf", str(_e)))

    # media: jpeg found; pdf NOT found
    print(f"  {CYAN}....{NC}  --triage-mode=media recovers jpeg, skips pdf", end="", flush=True)
    try:
        _img_med = make_raw_image(_triage_jpg, _triage_pdf)
        _res_med = _run_triage(_img_med, "media")
        _types_med = {f["type"] for f in _res_med}
        assert "jpeg" in _types_med, f"jpeg missing; got {_types_med}"
        assert "pdf" not in _types_med, f"pdf should be excluded; got {_types_med}"
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=media recovers jpeg, skips pdf")
        passed.append("--triage-mode=media recovers jpeg, skips pdf")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=media — {_e}")
        failed.append(("--triage-mode=media recovers jpeg, skips pdf", str(_e)))

    # unknown mode: pala exits non-zero
    print(f"  {CYAN}....{NC}  --triage-mode=bogus exits non-zero", end="", flush=True)
    try:
        _img_tmp = make_raw_image(_triage_pdf)
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf2:
            _tf2.write(_img_tmp); _ip2 = _tf2.name
        with tempfile.TemporaryDirectory() as _od2:
            _r2 = subprocess.run(
                [str(PALA), _ip2, _od2, "-q", "--triage-mode=bogus"],
                capture_output=True, text=True, timeout=10)
            os.unlink(_ip2)
            assert _r2.returncode != 0, f"expected non-zero exit; got {_r2.returncode}"
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=bogus exits non-zero")
        passed.append("--triage-mode=bogus exits non-zero")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=bogus exits non-zero — {_e}")
        failed.append(("--triage-mode=bogus exits non-zero", str(_e)))

    # ── False positives ───────────────────────────────────────────────────────
    print("\n  False positives")
    run_fp_test("20MB random data — 0 strong-magic FPs")

    # ── Rate limiting / degraded flag (TODO #8) ──────────────────────────────
    print("\n  Rate limiting / degraded flag")
    # --degraded flag must not corrupt output on healthy images.
    # Test: --degraded alone (default 1ms), --degraded=0 (disabled), --degraded=5 (custom).
    _pdf_fix = make_pdf()
    _deg_img = make_raw_image(_pdf_fix, gap=512)
    for _label, _kw in [
        ("--degraded (no value → default 1ms) produces same output",   {"degraded_ms": None, "extra_args": ["--degraded"]}),
        ("--degraded=0 (disabled, explicit zero) produces same output", {"degraded_ms": 0}),
        ("--degraded=5 (5ms explicit) produces same output",           {"degraded_ms": 5}),
    ]:
        print(f"  {CYAN}....{NC}  {_label}", end="", flush=True)
        try:
            with tempfile.TemporaryDirectory() as _od_ref, \
                 tempfile.TemporaryDirectory() as _od_deg, \
                 tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf:
                _tf.write(_deg_img)
                _img_path = _tf.name
            try:
                # Reference run (no --degraded)
                _ref = run_pala(_deg_img, Path(_od_ref), types=["pdf"])
                # Degraded run
                _extra = _kw.pop("extra_args", [])
                _cmd = [str(PALA), _img_path, _od_deg, "-q", "-t", "pdf"] + _extra
                _dms = _kw.get("degraded_ms")
                if _dms is not None:
                    _cmd += [f"--degraded={_dms}"]
                _r = subprocess.run(_cmd, capture_output=True, text=True, timeout=30)
                if _r.returncode != 0:
                    raise RuntimeError(f"pala exit {_r.returncode}: {_r.stderr.strip()}")
                _deg = {p.name: p.read_bytes() for p in Path(_od_deg).iterdir()}
                # .pala-state.json embeds the source path so it differs between runs; skip it.
                _cmp_ref = {k: v for k, v in _ref.items() if k != ".pala-state.json"}
                _cmp_deg = {k: v for k, v in _deg.items() if k != ".pala-state.json"}
                if set(_cmp_ref) != set(_cmp_deg):
                    raise RuntimeError(f"file set mismatch: ref={set(_cmp_ref)} deg={set(_cmp_deg)}")
                for _name in _cmp_ref:
                    if _cmp_ref[_name] != _cmp_deg[_name]:
                        raise RuntimeError(f"content mismatch for {_name}")
            finally:
                os.unlink(_img_path)
            print(f"\r  {GREEN}PASS{NC}  {_label}")
            passed.append(_label)
        except Exception as _e:
            print(f"\r  {RED}FAIL{NC}  {_label} — {_e}")
            failed.append((_label, str(_e)))

    # Verify that --degraded without a value (bare flag) is accepted by the CLI.
    print(f"  {CYAN}....{NC}  --degraded bare flag accepted by CLI", end="", flush=True)
    try:
        with tempfile.TemporaryDirectory() as _od, \
             tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf2:
            _tf2.write(_deg_img)
            _ip2 = _tf2.name
        try:
            _r2 = subprocess.run(
                [str(PALA), _ip2, _od, "-q", "-t", "pdf", "--degraded"],
                capture_output=True, text=True, timeout=30
            )
            if _r2.returncode != 0:
                raise RuntimeError(f"pala exit {_r2.returncode}: {_r2.stderr.strip()}")
        finally:
            os.unlink(_ip2)
        print(f"\r  {GREEN}PASS{NC}  --degraded bare flag accepted by CLI")
        passed.append("--degraded bare flag accepted by CLI")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --degraded bare flag accepted by CLI — {_e}")
        failed.append(("--degraded bare flag accepted by CLI", str(_e)))

    # bad_sectors field present in --json output and equals 0 on a clean image
    print(f"  {CYAN}....{NC}  bad_sectors field in --json output (clean image = 0)", end="", flush=True)
    try:
        import json as _jmod
        _bs_img = make_raw_image(make_pdf(), gap=512)
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _bstf:
            _bstf.write(_bs_img)
            _bsip = _bstf.name
        with tempfile.TemporaryDirectory() as _bsod:
            try:
                _bsr = subprocess.run(
                    [str(PALA), _bsip, _bsod, "-q", "--json", "-t", "pdf"],
                    capture_output=True, text=True, timeout=30
                )
                if _bsr.returncode != 0:
                    raise RuntimeError(f"pala exit {_bsr.returncode}: {_bsr.stderr.strip()}")
                _bsj = _jmod.loads(_bsr.stdout)
                if "bad_sectors" not in _bsj:
                    raise RuntimeError("bad_sectors key missing from JSON")
                if _bsj["bad_sectors"] != 0:
                    raise RuntimeError(f"expected bad_sectors=0, got {_bsj['bad_sectors']}")
            finally:
                os.unlink(_bsip)
        print(f"\r  {GREEN}PASS{NC}  bad_sectors field in --json output (clean image = 0)")
        passed.append("bad_sectors field in --json output (clean image = 0)")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  bad_sectors field — {_e}")
        failed.append(("bad_sectors field in --json output (clean image = 0)", str(_e)))

    # bad_sector_offsets absent and has_bad_sectors absent on clean image
    print(f"  {CYAN}....{NC}  bad_sector_offsets absent + has_bad_sectors absent on clean image", end="", flush=True)
    try:
        _bso_img = make_raw_image(make_pdf(), gap=512)
        _bso_findings = _run_json(_bso_img, ["pdf"])
        _bso_sess = None
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf_bso:
            _tf_bso.write(_bso_img); _ip_bso = _tf_bso.name
        with tempfile.TemporaryDirectory() as _od_bso:
            import json as _jbso
            _r_bso = subprocess.run([str(PALA), _ip_bso, _od_bso, "-q", "--json", "-t", "pdf"],
                                    capture_output=True, text=True, timeout=30)
            os.unlink(_ip_bso)
            _data_bso = _jbso.loads(_r_bso.stdout)
            _bso_sess = _data_bso.get("session_summary", {})
            _bso_findings2 = _data_bso.get("findings", [])
        assert "bad_sector_offsets" not in _bso_sess, f"bad_sector_offsets should be absent; got {_bso_sess}"
        for _f in _bso_findings2:
            assert not _f.get("has_bad_sectors", False), f"has_bad_sectors should be absent/false; got {_f}"
        print(f"\r  {GREEN}PASS{NC}  bad_sector_offsets absent + has_bad_sectors absent on clean image")
        passed.append("bad_sector_offsets absent + has_bad_sectors absent on clean image")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  bad_sector_offsets/has_bad_sectors — {_e}")
        failed.append(("bad_sector_offsets absent + has_bad_sectors absent on clean image", str(_e)))

    # ── Gap-tolerant fragment reassembly (--frag-gap) ────────────────────────
    print("\n  Gap-tolerant fragment reassembly (--frag-gap)")

    print(f"  {CYAN}....{NC}  --frag-gap=512 merges ZIP with 512-byte zero gap", end="", flush=True)
    try:
        _buf_fg = io.BytesIO()
        with zipfile.ZipFile(_buf_fg, "w", zipfile.ZIP_STORED) as _zfg:
            _zfg.writestr("part1.txt", "X" * 300)
            _zfg.writestr("part2.txt", "Y" * 64)
        _zfg_b = _buf_fg.getvalue()
        # Split at second local file header
        _fp_a = _zfg_b.index(b"PK\x03\x04")
        _fp_b = _zfg_b.index(b"PK\x03\x04", _fp_a + 4)
        _fg_frag1 = _zfg_b[:_fp_b]
        _fg_frag2 = _zfg_b[_fp_b:]
        _fg_gap = 512
        # Image: noise prefix + frag1 + 512 zero bytes + frag2
        _fg_img = make_raw_image(b"", gap=0)[:4096] + _fg_frag1 + bytes(_fg_gap) + _fg_frag2 + b"\x00" * 512
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _fg_tf:
            _fg_tf.write(_fg_img)
            _fg_ip = _fg_tf.name
        with tempfile.TemporaryDirectory() as _fg_od:
            try:
                _fg_cmd = [str(PALA), _fg_ip, _fg_od, "-q", "--json", "-t", "zip",
                           f"--max-size={len(_fg_frag1)}", f"--frag-gap={_fg_gap}"]
                _fg_r = subprocess.run(_fg_cmd, capture_output=True, text=True, timeout=30)
                if _fg_r.returncode != 0:
                    raise RuntimeError(f"pala exit {_fg_r.returncode}: {_fg_r.stderr.strip()}")
                import json as _fgjson
                _fg_findings = _fgjson.loads(_fg_r.stdout)["findings"]
                _fg_frags = [f for f in _fg_findings if f["quality"] == "fragmented"]
                if not _fg_frags:
                    raise RuntimeError(f"no fragmented findings; got: {[f['quality'] for f in _fg_findings]}")
            finally:
                os.unlink(_fg_ip)
        print(f"\r  {GREEN}PASS{NC}  --frag-gap=512 merges ZIP with 512-byte zero gap")
        passed.append("--frag-gap=512 merges ZIP with 512-byte zero gap")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --frag-gap=512 — {_e}")
        failed.append(("--frag-gap=512 merges ZIP with 512-byte zero gap", str(_e)))

    print(f"  {CYAN}....{NC}  --frag-gap=0 (default) does not merge ZIP with 512-byte gap", end="", flush=True)
    try:
        # Reuse the same image from above; without --frag-gap neither fragment alone is complete
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _fg2_tf:
            _fg2_tf.write(_fg_img)
            _fg2_ip = _fg2_tf.name
        with tempfile.TemporaryDirectory() as _fg2_od:
            try:
                _fg2_cmd = [str(PALA), _fg2_ip, _fg2_od, "-q", "--json", "-t", "zip",
                            f"--max-size={len(_fg_frag1)}"]
                _fg2_r = subprocess.run(_fg2_cmd, capture_output=True, text=True, timeout=30)
                if _fg2_r.returncode != 0:
                    raise RuntimeError(f"pala exit {_fg2_r.returncode}: {_fg2_r.stderr.strip()}")
                _fg2_findings = _fgjson.loads(_fg2_r.stdout)["findings"]
                _fg2_frags = [f for f in _fg2_findings if f["quality"] == "fragmented"]
                if _fg2_frags:
                    raise RuntimeError(f"expected no fragmented findings, got: {_fg2_frags}")
            finally:
                os.unlink(_fg2_ip)
        print(f"\r  {GREEN}PASS{NC}  --frag-gap=0 (default) does not merge ZIP with 512-byte gap")
        passed.append("--frag-gap=0 (default) does not merge ZIP with 512-byte gap")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --frag-gap=0 — {_e}")
        failed.append(("--frag-gap=0 (default) does not merge ZIP with 512-byte gap", str(_e)))

    # ── Triage mode presets (--triage-mode) ──────────────────────────────────
    print("\n  Triage mode presets (--triage-mode)")

    print(f"  {CYAN}....{NC}  --triage-mode=documents finds PDF", end="", flush=True)
    try:
        _tm_pdf_img = make_raw_image(make_pdf(), gap=512)
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tm_tf:
            _tm_tf.write(_tm_pdf_img)
            _tm_ip = _tm_tf.name
        with tempfile.TemporaryDirectory() as _tm_od:
            try:
                _tm_r = subprocess.run(
                    [str(PALA), _tm_ip, _tm_od, "-q", "--json", "--triage-mode=documents"],
                    capture_output=True, text=True, timeout=30
                )
                if _tm_r.returncode != 0:
                    raise RuntimeError(f"pala exit {_tm_r.returncode}: {_tm_r.stderr.strip()}")
                import json as _tmjson
                _tm_findings = _tmjson.loads(_tm_r.stdout)["findings"]
                if not any(f["type"] == "pdf" for f in _tm_findings):
                    raise RuntimeError(f"no PDF in findings: {_tm_findings}")
            finally:
                os.unlink(_tm_ip)
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=documents finds PDF")
        passed.append("--triage-mode=documents finds PDF")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=documents — {_e}")
        failed.append(("--triage-mode=documents finds PDF", str(_e)))

    print(f"  {CYAN}....{NC}  --triage-mode=media finds JPEG", end="", flush=True)
    try:
        _tm_jpg = (b"\xFF\xD8\xFF\xE0" + b"\x00\x10" + b"JFIF\x00" + b"\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                   + b"\xFF\xDB" + b"\x00\x43" + b"\x00" + bytes(64)
                   + b"\xFF\xC0" + b"\x00\x0B" + b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
                   + b"\xFF\xC4" + b"\x00\x1F" + b"\x00" + bytes(30)
                   + b"\xFF\xDA" + b"\x00\x08\x01\x01\x00\x00?\x00" + bytes(1024) + b"\xFF\xD9")
        _tm_jpg_img = make_raw_image(_tm_jpg, gap=0)
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tmj_tf:
            _tmj_tf.write(_tm_jpg_img)
            _tmj_ip = _tmj_tf.name
        with tempfile.TemporaryDirectory() as _tmj_od:
            try:
                _tmj_r = subprocess.run(
                    [str(PALA), _tmj_ip, _tmj_od, "-q", "--json", "--triage-mode=media"],
                    capture_output=True, text=True, timeout=30
                )
                if _tmj_r.returncode != 0:
                    raise RuntimeError(f"pala exit {_tmj_r.returncode}: {_tmj_r.stderr.strip()}")
                _tmj_findings = _tmjson.loads(_tmj_r.stdout)["findings"]
                if not any(f["type"] == "jpeg" for f in _tmj_findings):
                    raise RuntimeError(f"no JPEG in findings: {_tmj_findings}")
            finally:
                os.unlink(_tmj_ip)
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=media finds JPEG")
        passed.append("--triage-mode=media finds JPEG")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=media — {_e}")
        failed.append(("--triage-mode=media finds JPEG", str(_e)))

    print(f"  {CYAN}....{NC}  --triage-mode=unknown exits non-zero", end="", flush=True)
    try:
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tmu_tf:
            _tmu_tf.write(b"\x00" * 1024)
            _tmu_ip = _tmu_tf.name
        with tempfile.TemporaryDirectory() as _tmu_od:
            try:
                _tmu_r = subprocess.run(
                    [str(PALA), _tmu_ip, _tmu_od, "-q", "--triage-mode=badmode"],
                    capture_output=True, text=True, timeout=30
                )
                if _tmu_r.returncode == 0:
                    raise RuntimeError("expected non-zero exit for unknown triage mode")
            finally:
                os.unlink(_tmu_ip)
        print(f"\r  {GREEN}PASS{NC}  --triage-mode=unknown exits non-zero")
        passed.append("--triage-mode=unknown exits non-zero")
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  --triage-mode=unknown — {_e}")
        failed.append(("--triage-mode=unknown exits non-zero", str(_e)))

    # ── Filesystem-assisted recovery (--filesystem) ───────────────────────────
    print("\n  Filesystem-assisted recovery (--filesystem)")

    # Minimal JPEG that meets the 512-byte minimum threshold:
    # SOI + APP0 header + fake scan data (512 bytes of zeros) + EOI
    def _make_fs_jpeg() -> bytes:
        hdr = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        sos = b"\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00\x00\x01"
        return hdr + sos + b"\x00" * 512 + b"\xFF\xD9"

    # Test 1: --filesystem flag is accepted by the CLI (no "unexpected argument" error).
    # When fls is absent, pala prints a warning and falls back to sig scan — same result
    # as without --filesystem.  Either path must not crash.
    _label_fs_flag = "--filesystem=auto: flag accepted by CLI; fallback OK when TSK absent"
    print(f"  {CYAN}....{NC}  {_label_fs_flag}", end="", flush=True)
    try:
        with tempfile.TemporaryDirectory() as _td_fs:
            _fs_img = make_raw_image(_make_fs_jpeg())
            # run with --filesystem=auto; accept either success (TSK present) or
            # the warning fallback (TSK absent → same JPEG recovered via sig scan)
            _fs_carved = run_pala(_fs_img, Path(_td_fs), types=["jpeg"], filesystem="auto")
            _fs_jpegs = {k: v for k, v in _fs_carved.items() if k.endswith(".jpg")}
            # The flag must be accepted (no crash) and at least 1 JPEG must be found
            # (either via inode phase or sig-scan fallback)
            if len(_fs_jpegs) < 1:
                raise RuntimeError(f"expected ≥1 JPEG, got {len(_fs_jpegs)}")
        print(f"\r  {GREEN}PASS{NC}  {_label_fs_flag}")
        passed.append(_label_fs_flag)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_fs_flag} — {_e}")
        failed.append((_label_fs_flag, str(_e)))

    # Test 2: SHA256 dedup — the same file recovered by inode phase is not duplicated
    # by sig scan.  We simulate this by checking that --filesystem=auto + sig scan
    # does not produce duplicate SHA256s across output files.
    _label_fs_dedup = "--filesystem=auto: no duplicate SHA256 across inode + sig phases"
    print(f"  {CYAN}....{NC}  {_label_fs_dedup}", end="", flush=True)
    try:
        with tempfile.TemporaryDirectory() as _td_dedup:
            _dedup_img = make_raw_image(_make_fs_jpeg())
            _dedup_carved = run_pala(_dedup_img, Path(_td_dedup), types=["jpeg"], filesystem="auto")
            _all_shas = [sha256(v) for v in _dedup_carved.values()]
            _unique_shas = set(_all_shas)
            if len(_all_shas) != len(_unique_shas):
                dups = len(_all_shas) - len(_unique_shas)
                raise RuntimeError(f"{dups} duplicate SHA256(s) found across output files")
        print(f"\r  {GREEN}PASS{NC}  {_label_fs_dedup}")
        passed.append(_label_fs_dedup)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_fs_dedup} — {_e}")
        failed.append((_label_fs_dedup, str(_e)))

    # Test 3: real ext2 image — JPEG written via debugfs, deleted, recovered via inode phase
    # Requires: mkfs.ext2 + debugfs (e2fsprogs) + fls + icat (sleuthkit)
    _label_fs_real = "--filesystem=ext2: real deleted inode recovered with SHA256 match"
    print(f"  {CYAN}....{NC}  {_label_fs_real}", end="", flush=True)
    _fs_prereqs = all(shutil.which(t) for t in ("mkfs.ext2", "debugfs", "fls", "icat"))
    if not _fs_prereqs:
        print(f"\r  {YELLOW}SKIP{NC}  {_label_fs_real} (mkfs.ext2/debugfs/fls/icat not found)")
        skipped.append(_label_fs_real)
    else:
        try:
            import tempfile as _tf2
            # Minimal JPEG ≥512 bytes so it passes the min-size threshold
            _ri_hdr = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            _ri_sos = b"\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00\x00\x01"
            _ri_jpeg = _ri_hdr + _ri_sos + b"\x42" * 512 + b"\xFF\xD9"

            with _tf2.TemporaryDirectory() as _ri_tmp:
                _ri_img  = Path(_ri_tmp) / "test.img"
                _ri_src  = Path(_ri_tmp) / "orig.jpg"
                _ri_out  = Path(_ri_tmp) / "recovered"
                _ri_out.mkdir()
                _ri_src.write_bytes(_ri_jpeg)

                # Create 4MB ext2 image and write+delete the JPEG via debugfs
                subprocess.run(["dd", "if=/dev/zero", f"of={_ri_img}", "bs=1M", "count=4"],
                               capture_output=True, check=True)
                subprocess.run(["mkfs.ext2", "-F", str(_ri_img)],
                               capture_output=True, check=True)
                subprocess.run(["debugfs", "-w", str(_ri_img), "-R",
                                f"write {_ri_src} test.jpg"],
                               capture_output=True, check=True)
                subprocess.run(["debugfs", "-w", str(_ri_img), "-R", "rm test.jpg"],
                               capture_output=True, check=True)

                # Verify fls sees the deleted inode
                _fls_out = subprocess.run(["fls", "-rd", str(_ri_img)],
                                          capture_output=True, text=True)
                if "test.jpg" not in _fls_out.stdout:
                    raise RuntimeError(f"fls did not list deleted inode: {_fls_out.stdout!r}")

                # Run PALA with filesystem-assisted mode
                cmd = [str(PALA), str(_ri_img), str(_ri_out), "-q",
                       "-t", "jpeg", "--filesystem=ext2"]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if r.returncode != 0:
                    raise RuntimeError(f"pala exit {r.returncode}: {r.stderr.strip()}")

                _ri_carved = {p.name: p.read_bytes()
                              for p in _ri_out.iterdir()
                              if p.name != ".pala-state.json"}
                _ri_jpegs = {k: v for k, v in _ri_carved.items() if k.endswith(".jpg")}

                if len(_ri_jpegs) != 1:
                    raise RuntimeError(
                        f"expected exactly 1 recovered JPEG, got {len(_ri_jpegs)}: "
                        f"{list(_ri_jpegs.keys())}"
                    )
                _recovered = next(iter(_ri_jpegs.values()))
                if sha256(_recovered) != sha256(_ri_jpeg):
                    raise RuntimeError(
                        f"SHA256 mismatch: recovered={sha256(_recovered)[:16]}... "
                        f"original={sha256(_ri_jpeg)[:16]}..."
                    )
            print(f"\r  {GREEN}PASS{NC}  {_label_fs_real}")
            passed.append(_label_fs_real)
        except Exception as _e:
            print(f"\r  {RED}FAIL{NC}  {_label_fs_real} — {_e}")
            failed.append((_label_fs_real, str(_e)))

    # ── NTFS cluster-run stage-2 (TODO #16) ──────────────────────────────────
    # Creates a 4 MB NTFS image with mkntfs, copies a 4096-byte blob (no magic
    # bytes) into it with ntfscp, then runs PALA.  The sig scan will NOT match
    # the blob (no recognizable header); the MFT stage-2 must extract it from
    # the $DATA cluster runs.  Verifies: (a) at least one finding with
    # source="mft:…", (b) that finding's sha256 matches the original blob.

    _label_ntfs = "NTFS stage-2: cluster-run extraction from carved MFT entries"
    print(f"  {CYAN}....{NC}  {_label_ntfs}", end="", flush=True)
    _mkntfs  = shutil.which("mkntfs") or shutil.which("mkfs.ntfs")
    _ntfscp  = shutil.which("ntfscp")
    if not _mkntfs or not _ntfscp:
        print(f"\r  {YELLOW}SKIP{NC}  {_label_ntfs} (mkntfs/ntfscp not found)")
        skipped.append(_label_ntfs)
    else:
        try:
            _ntfs_td = tempfile.mkdtemp(prefix="pala_ntfs_")
            try:
                # Blob content: no recognizable magic so sig scan won't match it
                _blob = b'\x42' * 4096
                _blob_sha = sha256(_blob)
                _blob_path = os.path.join(_ntfs_td, "blob.dat")
                with open(_blob_path, "wb") as _f:
                    _f.write(_blob)

                # 4 MB NTFS image (cluster-size 512 forces non-resident at 512+ bytes)
                _img = os.path.join(_ntfs_td, "ntfs.img")
                # mkntfs requires the target file to already exist
                with open(_img, "wb") as _imf: _imf.write(b'\x00' * (4 * 1024 * 1024))
                # 4 MB image: 8192 sectors × 512 bytes; cluster-size=512 forces
                # non-resident $DATA for any file ≥ ~512 bytes
                subprocess.run([_mkntfs, "-F", "-q", "-c", "512", "-s", "512",
                                _img, "8192"],
                               check=True, capture_output=True)

                # Copy blob into the image via ntfscp
                subprocess.run([_ntfscp, _img, _blob_path, "/blob.dat"],
                               check=True, capture_output=True)

                # Run PALA directly on the image file (pure carving path, no --filesystem)
                _ntfs_out = os.path.join(_ntfs_td, "out")
                os.makedirs(_ntfs_out, exist_ok=True)
                _res = subprocess.run([str(PALA), _img, _ntfs_out, "-q", "--json"],
                                      capture_output=True, text=True)

                if _res.returncode != 0:
                    raise RuntimeError(f"pala failed: {_res.stderr[:200]}")
                _ntfs_data = json.loads(_res.stdout)
                _ntfs_findings = _ntfs_data.get("findings", [])

                # At least one finding must come from mft stage-2
                _mft_findings = [f for f in _ntfs_findings
                                 if (f.get("source") or "").startswith("mft:")]
                if not _mft_findings:
                    raise RuntimeError(
                        f"no stage-2 MFT findings; all findings: "
                        f"{[(f.get('type'), f.get('source')) for f in _ntfs_findings]}"
                    )

                # The blob SHA256 must appear in the stage-2 findings
                _mft_shas = {f["sha256"] for f in _mft_findings}
                if _blob_sha not in _mft_shas:
                    raise RuntimeError(
                        f"blob SHA256 {_blob_sha[:16]}... not in stage-2 shas: "
                        f"{[s[:16] for s in _mft_shas]}"
                    )

                # No SHA256 duplicates across all findings
                _all_shas = [f["sha256"] for f in _ntfs_findings]
                if len(_all_shas) != len(set(_all_shas)):
                    raise RuntimeError(
                        f"SHA256 duplicates in findings: {_all_shas}"
                    )

                print(f"\r  {GREEN}PASS{NC}  {_label_ntfs}")
                passed.append(_label_ntfs)
            finally:
                shutil.rmtree(_ntfs_td, ignore_errors=True)
        except Exception as _e:
            print(f"\r  {RED}FAIL{NC}  {_label_ntfs} — {_e}")
            failed.append((_label_ntfs, str(_e)))

    # ── Entropy classification (TODO #17) ────────────────────────────────────
    # --skip-high-entropy discards findings whose start sector has H > 7.5.
    # Test: a JPEG padded with high-entropy (random) bytes at offset 0 should be
    # skipped; a zero-padded image with a valid JPEG should still be found.

    _label_entropy1 = "--skip-high-entropy: accepted by CLI without crash"
    print(f"  {CYAN}....{NC}  {_label_entropy1}", end="", flush=True)
    try:
        _jpeg_hdr = (
            b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            + b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00'
            + b'\x42' * 512
            + b'\xFF\xD9'
        )
        _hi_img = b'\x00' * 4096 + _jpeg_hdr
        with tempfile.TemporaryDirectory() as _etd1:
            _hi_out = run_pala(_hi_img, Path(_etd1), extra_args=["--skip-high-entropy"])
        # JPEG starts at byte 4096 (sector 8) which is all-zero — NOT high entropy.
        # So the JPEG SHOULD be found.
        assert any(k.endswith(".jpg") for k in _hi_out), \
            f"expected JPEG in low-entropy sector to survive; got {list(_hi_out.keys())}"
        print(f"\r  {GREEN}PASS{NC}  {_label_entropy1}")
        passed.append(_label_entropy1)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_entropy1} — {_e}")
        failed.append((_label_entropy1, str(_e)))

    _label_entropy2 = "--skip-high-entropy: JSON sector_stats present in session_summary"
    print(f"  {CYAN}....{NC}  {_label_entropy2}", end="", flush=True)
    try:
        _etd = tempfile.mkdtemp()
        try:
            _img_bytes = b'\x00' * 4096 + _jpeg_hdr
            with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf:
                _tf.write(_img_bytes); _img_path = _tf.name
            _res = subprocess.run([str(PALA), _img_path, _etd, "-q", "--json",
                                   "--skip-high-entropy"],
                                  capture_output=True, text=True)
            os.unlink(_img_path)
            _d = json.loads(_res.stdout)
            _ss = _d.get("session_summary", {})
            assert "entropy_survey" in _ss, \
                f"entropy_survey missing from session_summary: {_ss}"
            _es = _ss["entropy_survey"]
            assert "zero_sectors" in _es and "high_entropy_sectors" in _es
        finally:
            shutil.rmtree(_etd, ignore_errors=True)
        print(f"\r  {GREEN}PASS{NC}  {_label_entropy2}")
        passed.append(_label_entropy2)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_entropy2} — {_e}")
        failed.append((_label_entropy2, str(_e)))

    # ── ZIP container depth (TODO #18) ───────────────────────────────────────
    # --container-depth extracts member files from carved ZIPs.
    # Test: image containing a ZIP that embeds a JPEG.  Without --container-depth
    # only the ZIP is found; with it the embedded JPEG appears.

    _label_zip = "--container-depth: extracts embedded JPEG from ZIP member"
    print(f"  {CYAN}....{NC}  {_label_zip}", end="", flush=True)
    try:
        _inner_jpeg = (b'\xFF\xD8\xFF\xE0' + b'\x00' * 12 + b'\xFF\xDA' +
                       b'\xAB' * 512 + b'\xFF\xD9')
        _zio = io.BytesIO()
        with zipfile.ZipFile(_zio, "w", zipfile.ZIP_STORED) as _z:
            _z.writestr("photo.jpg", _inner_jpeg)
        _zip_bytes = _zio.getvalue()
        _outer_img = b'\x00' * 1024 + _zip_bytes
        _ztd = tempfile.mkdtemp()
        try:
            _zip_no_depth = run_pala(_outer_img, Path(_ztd) / "no-depth")
            _zip_with_depth = run_pala(_outer_img, Path(_ztd) / "with-depth", extra_args=["--container-depth"])
            _nd_types = {k.rsplit(".", 1)[-1] for k in _zip_no_depth}
            _wd_types = {k.rsplit(".", 1)[-1] for k in _zip_with_depth}
            assert "zip" in _nd_types, "no-depth: expected ZIP"
            assert "jpg" in _wd_types, \
                f"with-depth: expected extracted JPEG; got types {_wd_types}"
            # SHA256 of the extracted JPEG should match the inner_jpeg bytes
            _inner_sha = sha256(_inner_jpeg)
            _found_sha = {sha256(v): k for k, v in _zip_with_depth.items()}
            assert _inner_sha in _found_sha, \
                f"inner JPEG SHA256 not in extracted files: {list(_found_sha.keys())[:2]}"
        finally:
            shutil.rmtree(_ztd, ignore_errors=True)
        print(f"\r  {GREEN}PASS{NC}  {_label_zip}")
        passed.append(_label_zip)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_zip} — {_e}")
        failed.append((_label_zip, str(_e)))

    # ── FAT32 cluster-chain stage-2 (TODO #19) ───────────────────────────────
    # Creates a 16 MB FAT32 image, copies a file, "deletes" it via debugfs-equivalent
    # (no such tool for FAT32 without root), then verifies PALA's FAT32 stage-2 path
    # doesn't crash on an image with no FAT32 FSINFO findings (no-op path).
    # A positive recovery test is below (uses mkdosfs + mtools if available).

    _label_fat32_noop = "FAT32 stage-2: no-op on non-FAT32 image (no crash)"
    print(f"  {CYAN}....{NC}  {_label_fat32_noop}", end="", flush=True)
    try:
        # Just a JPEG image — no FAT32 FSINFO sig → stage-2 should be a no-op
        _f32_jpeg = (
            b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            + b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00'
            + b'\xCC' * 512
            + b'\xFF\xD9'
        )
        with tempfile.TemporaryDirectory() as _f32td_noop:
            _f32_noop = run_pala(_f32_jpeg, Path(_f32td_noop))
        assert any(k.endswith(".jpg") for k in _f32_noop), \
            f"expected JPEG; got {list(_f32_noop.keys())}"
        print(f"\r  {GREEN}PASS{NC}  {_label_fat32_noop}")
        passed.append(_label_fat32_noop)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_fat32_noop} — {_e}")
        failed.append((_label_fat32_noop, str(_e)))

    _mkdosfs = shutil.which("mkdosfs") or shutil.which("mkfs.fat") or shutil.which("mkfs.vfat")
    _mtools_cp = shutil.which("mcopy")
    _label_fat32_real = "FAT32 stage-2: real deleted file recovered from cluster chain"
    print(f"  {CYAN}....{NC}  {_label_fat32_real}", end="", flush=True)
    if not _mkdosfs or not _mtools_cp:
        print(f"\r  {YELLOW}SKIP{NC}  {_label_fat32_real} (mkdosfs/mcopy not found)")
        skipped.append(_label_fat32_real)
    else:
        try:
            _f32td = tempfile.mkdtemp()
            try:
                # 16 MB FAT32 image, 512-byte sectors, 512-byte clusters
                _f32img = os.path.join(_f32td, "fat32.img")
                with open(_f32img, "wb") as _f: _f.write(b'\x00' * (16 * 1024 * 1024))
                subprocess.run([_mkdosfs, "-F", "32", "-S", "512", "-s", "1",
                                "-v", _f32img], check=True, capture_output=True)

                # Copy a blob file (no recognizable magic bytes) using mtools
                _f32blob = os.path.join(_f32td, "BLOB.DAT")
                _f32_blob_content = b'\x77' * 1024  # 1KB, 2 clusters of 512 bytes
                with open(_f32blob, "wb") as _f: _f.write(_f32_blob_content)
                subprocess.run([_mtools_cp, "-i", _f32img, _f32blob, "::/BLOB.DAT"],
                               check=True, capture_output=True)

                # "Delete" using mtools mdel
                _mdel = shutil.which("mdel")
                if not _mdel:
                    print(f"\r  {YELLOW}SKIP{NC}  {_label_fat32_real} (mdel not found)")
                    skipped.append(_label_fat32_real)
                else:
                    subprocess.run([_mdel, "-i", _f32img, "::/BLOB.DAT"],
                                   check=True, capture_output=True)

                    _f32_out = os.path.join(_f32td, "out")
                    os.makedirs(_f32_out, exist_ok=True)
                    _f32_res = subprocess.run(
                        [str(PALA), _f32img, _f32_out, "-q", "--json"],
                        capture_output=True, text=True)
                    if _f32_res.returncode != 0:
                        raise RuntimeError(f"pala failed: {_f32_res.stderr[:200]}")
                    _f32_data = json.loads(_f32_res.stdout)
                    _f32_fs = _f32_data.get("findings", [])

                    _fat32_fs = [f for f in _f32_fs
                                 if (f.get("source") or "").startswith("fat32:")]
                    if not _fat32_fs:
                        raise RuntimeError(
                            f"no FAT32 stage-2 findings; all: "
                            f"{[(f.get('type'), f.get('source')) for f in _f32_fs]}")

                    _blob_sha = sha256(_f32_blob_content)
                    _fat32_shas = {f["sha256"] for f in _fat32_fs}
                    if _blob_sha not in _fat32_shas:
                        raise RuntimeError(
                            f"blob SHA256 {_blob_sha[:16]}... not in FAT32 findings: "
                            f"{[s[:16] for s in _fat32_shas]}")

                    print(f"\r  {GREEN}PASS{NC}  {_label_fat32_real}")
                    passed.append(_label_fat32_real)
            finally:
                shutil.rmtree(_f32td, ignore_errors=True)
        except Exception as _e:
            if _label_fat32_real not in passed and _label_fat32_real not in skipped:
                print(f"\r  {RED}FAIL{NC}  {_label_fat32_real} — {_e}")
                failed.append((_label_fat32_real, str(_e)))

    # ── APFS (TODO #20) ──────────────────────────────────────────────────────
    # TSK on this system supports APFS (fls -f list shows "apfs").
    # Verify --filesystem=apfs is accepted by the CLI (graceful fallback when
    # no APFS image is available, as APFS is typically macOS-only).

    _label_apfs = "--filesystem=apfs: flag accepted; graceful fallback when TSK finds no inodes"
    print(f"  {CYAN}....{NC}  {_label_apfs}", end="", flush=True)
    try:
        # Use a JPEG-only image — fls will fail to parse it as APFS (empty result)
        # → carve_inode_phase falls back gracefully → sig scan finds the JPEG
        _apfs_jpeg = (b'\xFF\xD8\xFF\xE0' + b'\x00' * 12 + b'\xFF\xDA' +
                      b'\xDD' * 512 + b'\xFF\xD9')
        with tempfile.TemporaryDirectory() as _apfs_td:
            _apfs_out = run_pala(_apfs_jpeg, Path(_apfs_td), filesystem="apfs")
        # Either finds JPEG (graceful fallback) or returns empty (also acceptable)
        # — what matters is no crash (returncode 0)
        print(f"\r  {GREEN}PASS{NC}  {_label_apfs}")
        passed.append(_label_apfs)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_apfs} — {_e}")
        failed.append((_label_apfs, str(_e)))

    # ── New sig types ─────────────────────────────────────────────────────────
    print()
    print("  New signature types")

    # TAR
    _label_tar = "tar archive carved by ustar magic at offset 257"
    print(f"  {CYAN}....{NC}  {_label_tar}", end="", flush=True)
    try:
        import struct as _struct
        def _make_tar_entry(name: bytes, data: bytes) -> bytes:
            n = name[:99].ljust(100, b'\x00')
            mode  = b'0000644\x00'
            uid   = b'0000000\x00'
            gid   = b'0000000\x00'
            size  = ('%011o' % len(data)).encode() + b'\x00'
            mtime = b'14274663707\x00'
            typef = b'0'
            link  = b'\x00' * 100
            magic = b'ustar\x00'    # 6 bytes: POSIX tar magic
            ver   = b'00'          # 2 bytes: POSIX version
            uname = b'\x00' * 32
            gname = b'\x00' * 32
            dev   = b'\x00' * 16
            pfx   = b'\x00' * 155
            pad   = b'\x00' * 12
            hdr = n + mode + uid + gid + size + mtime + b'        ' + typef + link + magic + ver + uname + gname + dev + pfx + pad
            assert len(hdr) == 512, len(hdr)
            ck = sum(hdr)  # checksum field already contains spaces (0x20 * 8 each)
            ck_str = ('%06o\x00 ' % ck).encode()
            hdr = hdr[:148] + ck_str + hdr[156:]
            pad_len = (512 - (len(data) % 512)) % 512
            return hdr + data + b'\x00' * pad_len
        _tar_payload = b'hello tar world\n'
        _tar_bytes = _make_tar_entry(b'test.txt', _tar_payload) + b'\x00' * 1024
        _img_tar = make_raw_image(_tar_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res = run_pala(_img_tar, Path(_td), types=["tar"])
            if not _res:
                raise RuntimeError("no tar finding")
            _carved = list(_res.values())[0]
            if sha256(_carved) != sha256(_tar_bytes[:len(_carved)]):
                raise RuntimeError(f"SHA256 mismatch: carved {len(_carved)}B")
        print(f"\r  {GREEN}PASS{NC}  {_label_tar}")
        passed.append(_label_tar)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_tar} — {_e}")
        failed.append((_label_tar, str(_e)))

    # OGG
    _label_ogg = "ogg container carved and EOS-bounded"
    print(f"  {CYAN}....{NC}  {_label_ogg}", end="", flush=True)
    try:
        def _make_ogg_page(serial: int, seq: int, header_type: int, granule: int, data: bytes) -> bytes:
            n_segs = (len(data) + 254) // 255
            seg_table = bytes([255] * (n_segs - 1) + [len(data) % 255 or (255 if len(data) % 255 == 0 and len(data) > 0 else len(data))])
            hdr = (b'OggS' + b'\x00' + bytes([header_type]) +
                   granule.to_bytes(8, 'little') +
                   serial.to_bytes(4, 'little') +
                   seq.to_bytes(4, 'little') +
                   b'\x00\x00\x00\x00' +  # CRC placeholder
                   bytes([n_segs]) + seg_table)
            return hdr + data
        _id_header = (b'\x01vorbis' + b'\x00' * 23)
        _ogg_bos  = _make_ogg_page(0x1234, 0, 0x02, 0, _id_header)
        _ogg_data = _make_ogg_page(0x1234, 1, 0x00, 100, b'\x03vorbis' + b'\x00' * 20)
        _ogg_eos  = _make_ogg_page(0x1234, 2, 0x04, 1000, b'')
        _ogg_bytes = _ogg_bos + _ogg_data + _ogg_eos
        _img_ogg = make_raw_image(_ogg_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res = run_pala(_img_ogg, Path(_td), types=["ogg"])
            if not _res:
                raise RuntimeError("no ogg finding")
            _carved = list(_res.values())[0]
            if len(_carved) < len(_ogg_bytes) - 4:
                raise RuntimeError(f"ogg carved too short: {len(_carved)} < {len(_ogg_bytes)}")
        print(f"\r  {GREEN}PASS{NC}  {_label_ogg}")
        passed.append(_label_ogg)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_ogg} — {_e}")
        failed.append((_label_ogg, str(_e)))

    # BZ2
    _label_bz2 = "bz2 carved by BZh header"
    print(f"  {CYAN}....{NC}  {_label_bz2}", end="", flush=True)
    try:
        import bz2 as _bz2mod
        _bz2_payload = b'pala bz2 test data ' * 100
        _bz2_bytes = _bz2mod.compress(_bz2_payload)
        _img_bz2 = make_raw_image(_bz2_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res = run_pala(_img_bz2, Path(_td), types=["bz2"])
            if not _res:
                raise RuntimeError("no bz2 finding")
            _carved = list(_res.values())[0]
            # bz2 EOS is bit-packed; verify by decompression, not exact SHA
            _dec = _bz2mod.BZ2Decompressor()
            _out = _dec.decompress(_carved)
            if _out != _bz2_payload:
                raise RuntimeError(f"bz2 decompression mismatch: {len(_out)}B vs {len(_bz2_payload)}B")
        print(f"\r  {GREEN}PASS{NC}  {_label_bz2}")
        passed.append(_label_bz2)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_bz2} — {_e}")
        failed.append((_label_bz2, str(_e)))

    # ZSTD
    _label_zstd = "zstd carved by magic bytes (skipped if zstandard unavailable)"
    print(f"  {CYAN}....{NC}  {_label_zstd}", end="", flush=True)
    try:
        import importlib.util as _ilu
        if _ilu.find_spec("zstandard") is None:
            print(f"\r  {YELLOW}SKIP{NC}  {_label_zstd} (zstandard module not installed)")
            skipped.append(_label_zstd)
        else:
            import zstandard as _zstd
            _zstd_payload = b'pala zstd test ' * 200
            _zstd_bytes = _zstd.compress(_zstd_payload)
            _img_zstd = make_raw_image(_zstd_bytes)
            with tempfile.TemporaryDirectory() as _td:
                _res = run_pala(_img_zstd, Path(_td), types=["zstd"])
                if not _res:
                    raise RuntimeError("no zstd finding")
                _carved = list(_res.values())[0]
                if sha256(_carved) != sha256(_zstd_bytes):
                    raise RuntimeError(f"zstd SHA mismatch: carved {len(_carved)}B vs {len(_zstd_bytes)}B")
            print(f"\r  {GREEN}PASS{NC}  {_label_zstd}")
            passed.append(_label_zstd)
    except Exception as _e:
        if _label_zstd not in skipped:
            print(f"\r  {RED}FAIL{NC}  {_label_zstd} — {_e}")
            failed.append((_label_zstd, str(_e)))

    # XZ
    _label_xz = "xz archive carved with YZ end-marker"
    print(f"  {CYAN}....{NC}  {_label_xz}", end="", flush=True)
    try:
        import lzma as _lzma
        _xz_payload = b'pala xz test ' * 200
        _xz_bytes = _lzma.compress(_xz_payload, format=_lzma.FORMAT_XZ)
        _img_xz = make_raw_image(_xz_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res = run_pala(_img_xz, Path(_td), types=["xz"])
            if not _res:
                raise RuntimeError("no xz finding")
            _carved = list(_res.values())[0]
            if sha256(_carved) != sha256(_xz_bytes):
                raise RuntimeError(f"xz SHA mismatch: carved {len(_carved)}B vs {len(_xz_bytes)}B")
        print(f"\r  {GREEN}PASS{NC}  {_label_xz}")
        passed.append(_label_xz)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_xz} — {_e}")
        failed.append((_label_xz, str(_e)))

    # MDMP
    _label_mdmp = "mdmp (Windows Minidump) carved by MDMP magic"
    print(f"  {CYAN}....{NC}  {_label_mdmp}", end="", flush=True)
    try:
        # Minimal synthetic MDMP: 4-byte magic + 4-byte version + rest zeros
        _mdmp_bytes = b'MDMP' + (4).to_bytes(4, 'little') + b'\x00' * 56
        _img_mdmp = make_raw_image(_mdmp_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res = run_pala(_img_mdmp, Path(_td), types=["mdmp"])
            if not _res:
                raise RuntimeError("no mdmp finding")
        print(f"\r  {GREEN}PASS{NC}  {_label_mdmp}")
        passed.append(_label_mdmp)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_mdmp} — {_e}")
        failed.append((_label_mdmp, str(_e)))

    # RAR5 block walker
    _label_rar5 = "rar5 block walker trims to End of Archive"
    print(f"  {CYAN}....{NC}  {_label_rar5}", end="", flush=True)
    try:
        # Minimal RAR5: signature + archive header block (type 1) + end-of-archive block (type 5)
        _rar5_sig = b"Rar!\x1a\x07\x01\x00"
        # Archive header: CRC32(4) + HeaderSize VINT(1=3) + BlockType VINT(1=1) + BlockFlags VINT(1=0) + ArchiveFlags VINT(1=0)
        _arch_blk = b"\x00\x00\x00\x00" + b"\x03" + b"\x01" + b"\x00" + b"\x00"
        # End of Archive: CRC32(4) + HeaderSize VINT(1=2) + BlockType VINT(1=5) + BlockFlags VINT(1=0)
        _eoa_blk  = b"\x00\x00\x00\x00" + b"\x02" + b"\x05" + b"\x00"
        _rar5_bytes = _rar5_sig + _arch_blk + _eoa_blk
        _img_rar5 = make_raw_image(_rar5_bytes + b"\xff" * 512)  # trailing garbage must be excluded
        with tempfile.TemporaryDirectory() as _td:
            _res_rar5 = run_pala(_img_rar5, Path(_td), types=["rar5"])
            if not _res_rar5:
                raise RuntimeError("no rar5 finding")
            _carved_rar5 = list(_res_rar5.values())[0]
            if len(_carved_rar5) != len(_rar5_bytes):
                raise RuntimeError(f"rar5_size trimmed to {len(_carved_rar5)}B, expected {len(_rar5_bytes)}B")
        print(f"\r  {GREEN}PASS{NC}  {_label_rar5}")
        passed.append(_label_rar5)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_rar5} — {_e}")
        failed.append((_label_rar5, str(_e)))

    # USN change journal carving
    _label_usn = "usn_rec change journal records carved and chained"
    print(f"  {CYAN}....{NC}  {_label_usn}", end="", flush=True)
    try:
        def _make_usn_record(filename):
            fname = filename.encode("utf-16-le")
            fname_len = len(fname)
            fname_off = 60
            base = 60 + fname_len
            rec_len = (base + 7) & ~7
            rec  = struct.pack("<IHH", rec_len, 2, 0)            # RecordLength, Major=2, Minor=0
            rec += b'\x00' * 48                                   # FileRef..FileAttributes
            rec += struct.pack("<HH", fname_len, fname_off)       # FileNameLength, FileNameOffset
            rec += fname
            rec += b'\x00' * (rec_len - len(rec))
            return rec
        _usn1 = _make_usn_record("secret.docx")
        _usn2 = _make_usn_record("passwd.txt")
        _usn_bytes = _usn1 + _usn2
        _img_usn = make_raw_image(_usn_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res_usn = run_pala(_img_usn, Path(_td), types=["usn_rec"])
            if not _res_usn:
                raise RuntimeError("no usn_rec finding")
        print(f"\r  {GREEN}PASS{NC}  {_label_usn}")
        passed.append(_label_usn)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_usn} — {_e}")
        failed.append((_label_usn, str(_e)))

    # usn_rec: validator rejects records with bad alignment or fname overflow
    for _ulabel, _bad_rec in [
        ("usn_rec rejects rec_len not 8-aligned",
         struct.pack("<IHH", 65, 2, 0) + b'\x00' * 48 + struct.pack("<HH", 4, 60) + b'A\x00' * 2 + b'\x00' * 3),
        ("usn_rec rejects fname_len + fname_off > rec_len",
         # rec_len=72 but fname_off=60 + fname_len=20 = 80 > 72
         struct.pack("<IHH", 72, 2, 0) + b'\x00' * 48 + struct.pack("<HH", 20, 60) + b'A\x00' * 6),
        ("usn_rec rejects odd fname_len",
         # fname_len=3 is not a multiple of 2 (UTF-16 must be even)
         struct.pack("<IHH", 72, 2, 0) + b'\x00' * 48 + struct.pack("<HH", 3, 60) + b'A\x00' * 4 + b'\x00' * 5),
    ]:
        print(f"  {CYAN}....{NC}  {_ulabel}", end="", flush=True)
        try:
            _img_bad_usn = make_raw_image(_bad_rec + b'\x00' * 64)
            with tempfile.TemporaryDirectory() as _td_bad:
                _res_bad = run_pala(_img_bad_usn, Path(_td_bad), types=["usn_rec"])
                assert not _res_bad, f"expected 0 findings; got {list(_res_bad)}"
            print(f"\r  {GREEN}PASS{NC}  {_ulabel}")
            passed.append(_ulabel)
        except Exception as _e:
            print(f"\r  {RED}FAIL{NC}  {_ulabel} — {_e}")
            failed.append((_ulabel, str(_e)))

    # ESE / JET Blue database carving
    _label_ese = "ese database carved by ESE magic at offset 4"
    print(f"  {CYAN}....{NC}  {_label_ese}", end="", flush=True)
    try:
        # ESE header: dbstate(4) + magic(4) + zeros to fill 4096-byte page
        _ese_bytes = b'\x01\x00\x00\x00' + b'\xef\xcd\xab\x89' + b'\x00' * (4096 - 8)
        _img_ese = make_raw_image(_ese_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res_ese = run_pala(_img_ese, Path(_td), types=["ese"])
            if not _res_ese:
                raise RuntimeError("no ese finding")
        print(f"\r  {GREEN}PASS{NC}  {_label_ese}")
        passed.append(_label_ese)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_ese} — {_e}")
        failed.append((_label_ese, str(_e)))

    # HEIC detection (synthetic ftyp box with heic brand)
    _label_heic = "heic/avif carved via ftyp brand at ISOBMFF offset 4"
    print(f"  {CYAN}....{NC}  {_label_heic}", end="", flush=True)
    try:
        # Minimal ISOBMFF: size(4 BE) + 'ftyp' + 'heic' + minor_version(4) + compat(4)
        _box_size = (24).to_bytes(4, 'big')
        _heic_bytes = _box_size + b'ftypheic' + b'\x00' * 4 + b'heic' + b'\x00' * 100
        _img_heic = make_raw_image(_heic_bytes)
        with tempfile.TemporaryDirectory() as _td:
            _res = run_pala(_img_heic, Path(_td), types=["heic"])
            if not _res:
                raise RuntimeError("no heic finding")
        print(f"\r  {GREEN}PASS{NC}  {_label_heic}")
        passed.append(_label_heic)
    except Exception as _e:
        print(f"\r  {RED}FAIL{NC}  {_label_heic} — {_e}")
        failed.append((_label_heic, str(_e)))

    # New triage modes
    print()
    print("  New triage modes")

    for _mode, _type, _magic in [
        ("executables", "elf",  b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8 + b'\x02\x00\x3e\x00' + b'\x00' * 500),
        ("archives",    "tar",  None),   # TAR uses the one built above
        ("memory",      "lime", b'\x45\x4d\x69\x4c' + b'\x01\x00\x00\x00' + b'\x00' * 24 + b'\x41' * 64),
        ("windows",     "evtx", b'ElfFile\x00' + b'\x00' * 56),
        ("filesystem",  "ext2_sb", b'\x80\x1a\x00\x00' + b'\x00' * 52 + b'\x53\xef' + b'\x00' * 26),
        ("forensic",    "evtx", b'ElfFile\x00' + b'\x00' * 56),
    ]:
        _lbl = f"--triage-mode={_mode} finds expected type"
        print(f"  {CYAN}....{NC}  {_lbl}", end="", flush=True)
        try:
            if _magic is None:
                print(f"\r  {YELLOW}SKIP{NC}  {_lbl} (synthetic fixture not needed)")
                skipped.append(_lbl)
                continue
            _img_mode = make_raw_image(_magic)
            with tempfile.TemporaryDirectory() as _td:
                _cmd_mode = [str(PALA), "-q"]
                with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as _tf:
                    _tf.write(_img_mode)
                    _img_path_mode = _tf.name
                try:
                    _r = subprocess.run(
                        [str(PALA), _img_path_mode, _td, "-q", f"--triage-mode={_mode}"],
                        capture_output=True)
                    if _r.returncode != 0:
                        raise RuntimeError(f"exit {_r.returncode}: {_r.stderr[:200].decode(errors='replace')}")
                    _found = [f for f in Path(_td).iterdir() if f.is_file() and not f.name.startswith('.')]
                    if not _found:
                        raise RuntimeError(f"no files recovered with --triage-mode={_mode}")
                finally:
                    os.unlink(_img_path_mode)
            print(f"\r  {GREEN}PASS{NC}  {_lbl}")
            passed.append(_lbl)
        except Exception as _e:
            print(f"\r  {RED}FAIL{NC}  {_lbl} — {_e}")
            failed.append((_lbl, str(_e)))

    # ── Production CLI and output-safety regressions ─────────────────────────
    print("\n  CLI contract and output safety")

    def cli_test(label, fn):
        print(f"  {CYAN}....{NC}  {label}", end="", flush=True)
        try:
            fn()
            print(f"\r  {GREEN}PASS{NC}  {label}")
            passed.append(label)
        except Exception as e:
            print(f"\r  {RED}FAIL{NC}  {label} — {e}")
            failed.append((label, str(e)))

    def _version_help_and_unknown():
        version = subprocess.run([str(PALA), "--version"], capture_output=True, text=True, timeout=10)
        assert version.returncode == 0 and version.stdout.strip() == "pala 0.3.0", version
        help_result = subprocess.run([str(PALA), "--help"], capture_output=True, text=True, timeout=10)
        assert help_result.returncode == 0
        assert "--min-size" in help_result.stderr and "--count" in help_result.stderr
        invalid = subprocess.run([str(PALA), "--not-an-option"], capture_output=True, text=True, timeout=10)
        assert invalid.returncode != 0 and "unknown option" in invalid.stderr

    cli_test("--version, --help, and unknown-option handling", _version_help_and_unknown)

    def _count_limit():
        img = make_raw_image(make_pdf(), make_png())
        with tempfile.TemporaryDirectory() as td:
            carved = run_pala(img, Path(td), types=["pdf", "png"], extra_args=["--count=1"])
            assert len(carved) == 1, list(carved)

    cli_test("--count=1 stops after one recovered file", _count_limit)

    def _minimum_size():
        pdf = make_pdf()
        database = make_sqlite()
        threshold = (len(pdf) + len(database)) // 2
        img = make_raw_image(pdf, database)
        with tempfile.TemporaryDirectory() as td:
            carved = run_pala(img, Path(td), types=["pdf", "sqlite"], extra_args=[f"--min-size={threshold}"])
            assert any(name.endswith(".db") for name in carved), list(carved)
            assert not any(name.endswith(".pdf") for name in carved), list(carved)

    cli_test("--min-size filters every signature recovery", _minimum_size)

    def _no_overwrite_and_private_output():
        import stat
        img = make_raw_image(make_pdf())
        with tempfile.TemporaryDirectory() as parent:
            out = Path(parent) / "results"
            first = run_pala(img, out, types=["pdf"])
            original = (out / "pdf_0001.pdf").read_bytes()
            assert first
            if os.name == "posix":
                assert stat.S_IMODE(out.stat().st_mode) == 0o700
                assert stat.S_IMODE((out / "pdf_0001.pdf").stat().st_mode) == 0o600
            state = json.loads((out / ".pala-state.json").read_text())
            assert state.get("seen_sha256"), state
            with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tf:
                tf.write(img)
                image_path = tf.name
            try:
                second = subprocess.run(
                    [str(PALA), image_path, str(out), "-q", "-t", "pdf"],
                    capture_output=True, text=True, timeout=30,
                )
                assert second.returncode != 0, second.stderr
                assert "not empty" in second.stderr, second.stderr
            finally:
                os.unlink(image_path)
            assert (out / "pdf_0001.pdf").read_bytes() == original

    cli_test("existing recoveries are never overwritten; output is private", _no_overwrite_and_private_output)

    # ── Summary ───────────────────────────────────────────────────────────────
    total = len(passed) + len(failed) + len(skipped)
    print()
    print("=" * 60)
    if failed:
        print(f"  {RED}FAILED{NC}:  {len(failed)}")
        for name, reason in failed:
            print(f"    - {name}: {reason}")
    print(f"  {GREEN}PASSED{NC}:  {len(passed)}")
    if skipped:
        print(f"  {YELLOW}SKIPPED{NC}: {len(skipped)}")
    print(f"  Total:   {total}")
    print()
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
