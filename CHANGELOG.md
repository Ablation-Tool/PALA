# Changelog

Notable changes to PALA are recorded here. The format follows Keep a Changelog, and versions follow Semantic Versioning.

## Unreleased

### Added

- Implemented `--version`, `--min-size`, and `-n/--count`; added strict unknown-option handling.
- Added raw-device same-device refusal with the explicit `--allow-same-device` override.
- Added SHA-256 deduplication state to checkpoints while retaining compatibility with older checkpoint files.
- Added corpus validation, bounded ZIP expansion, output overwrite prevention, and private Unix output permissions.
- Added regression tests for CLI behavior, chunk overlap, entropy offsets, malformed input, checkpoints, ZIP limits, and output safety.
- Added security, contributing, and changelog documentation; rewrote the operator and agent guides.
- Added formatting, lint, locked-build, platform, and dependency-advisory CI checks.

### Fixed

- Prevented raw-device overlap candidates from being written but omitted from results and suppressed in later chunks.
- Corrected entropy filtering to translate global offsets into chunk-local buffer offsets.
- Rejected malformed NTFS run-list widths before shifts and parsing.
- Prevented custom corpus extensions from escaping the output directory and excessive record counts from forcing large allocations.
- Prevented recovered files from being overwritten by subsequent runs.
- Made checkpoint write failures visible to the caller.
- Restored Windows disk-image builds with an explicit non-Unix raw-device fallback.
- Upgraded to `zip 9.1.2` to address published archive-extraction advisories; malformed member names are skipped safely.

### Changed

- Normal runs now require an output directory without existing recovery results; use `--resume` to continue a previous run.
- ZIP member extraction is limited to 10,000 examined members per archive, 500 MiB per member by default, and 1 GiB total per expansion run.
- Replaced marketing-oriented documentation with operational behavior, support boundaries, resource limits, and recovery limitations.
- Redesigned the README as a compact capability overview and moved the complete production runbook to `docs/operations.md`.

## 0.3.0

- Added RAR5 block walking, NTFS USN journal carving, and ESE/JET Blue database recovery.
- Added EXIF improvements, forensic triage presets, and database/ESE filters.
- Added regression coverage for triage modes, USN validation, and EXIF fields.

## 0.2.0

- Added firmware and forensic signatures and size parsers.
- Added FAT32 directory-tree walking and cluster-chain recovery improvements.
- Added fragment merging, metadata extraction, container expansion, entropy filtering, and filesystem-assisted recovery.
