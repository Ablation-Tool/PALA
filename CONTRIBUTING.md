# Contributing to PALA

## Development principles

PALA handles damaged and untrusted input and is used in situations where further writes can cause permanent data loss. Prioritize read-only source handling, bounded parsing, deterministic output, and non-overwriting recovery.

Do not add broad claims or features that cannot be tested. Document format and platform limitations with the implementation.

## Setup

Install Rust stable. Python 3 and Pillow are needed for the full integration suite. Filesystem recovery tests may additionally use Sleuth Kit, e2fsprogs, ntfs-3g utilities, dosfstools, and mtools; tests that require unavailable tools are skipped.

## Required checks

Run before submitting a change:

```bash
cargo fmt
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
python3 tests/test_pala.py
```

Do not suppress lint warnings broadly or weaken tests to make a change pass. Update `Cargo.lock` only when dependency or package metadata changes require it.

## Tests

- Add focused Rust unit tests for parsers, boundary arithmetic, checkpoint behavior, and failure cases.
- Add end-to-end cases to `tests/test_pala.py` for CLI behavior and recovery semantics.
- Test both valid and malformed input. Verify that malformed data fails without a panic, excessive allocation, or output outside the destination.
- Recovery tests should compare SHA-256 hashes where byte-exact recovery is expected.
- Tests must not require sudo, real block devices, or access to user data.
- Keep fixtures synthetic, minimal, and free of secrets or personal data.

## Code changes

- Use checked or saturating arithmetic at untrusted offsets and sizes.
- Bound loops, allocations, archive extraction, and output wherever input controls the amount of work.
- Preserve non-overwriting output behavior and Unix `0700` directory / `0600` file permissions.
- Keep JSON on stdout and diagnostics on stderr. Preserve JSON compatibility where practical and document intentional schema changes.
- Avoid unnecessary dependencies and large refactors mixed with behavior changes.
- Update comments and documentation when behavior changes.

## Documentation and releases

Update `README.md` and `CHANGELOG.md` for user-visible changes. Add security-relevant operational guidance to `SECURITY.md` when appropriate.

A release should have a changelog entry, a passing full test suite, locked dependency builds, and reviewed release artifacts. Do not claim guaranteed recovery, universal format support, certification, or production safety that the tests do not establish.

## Reporting security issues

Follow `SECURITY.md`. Do not submit sensitive proof-of-concept data or security vulnerabilities through public issues.
