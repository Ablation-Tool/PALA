# Security policy

## Supported versions

Security fixes are applied to the current `main` branch and the latest release. Older releases should be upgraded before processing sensitive or untrusted media.

## Reporting a vulnerability

Do not open a public issue containing a working exploit, sensitive disk image, recovered credentials, or other private data.

Use GitHub's private vulnerability reporting for `Ablation-Tool/PALA` when available. Otherwise, contact the repository owner through their GitHub profile to request a private reporting channel.

Include:

- PALA version and commit
- Operating system and architecture
- A minimal, non-sensitive reproduction case
- Expected and actual behavior
- Impact and any suggested mitigation

Do not send real forensic images or recovered secrets.

## Security model

PALA parses disk images, filesystem metadata, custom corpora, and archives that may be malformed or actively hostile. Treat all recovered content as untrusted.

PALA opens sources read-only. Do not modify an image while it is being scanned, and do not run recovered programs or open recovered documents with elevated privileges.

### Source and output safety

- Write output to a different physical device when scanning a raw device.
- A normal run requires an empty output directory, and recovered files are created without overwrite.
- `--allow-same-device` disables an important raw-device safety check and can cause data loss.
- On Unix, newly created output directories use `0700`; recovered files and checkpoints use `0600`. Review permissions on pre-existing directories and on non-Unix platforms.
- JSON reports can contain filenames, metadata, offsets, and hashes. Protect them as sensitive recovery artifacts.

### Resource limits

Use `--types`, `--count`, and `--max-size` to bound work on untrusted media. ZIP expansion is disabled unless requested and has member-count, per-member, and total-output limits. Keep enough free space for recovered output and checkpoints.

### Optional external tools

`--filesystem` invokes Sleuth Kit `fls` and `icat` from `PATH`. Install them from a trusted package source and run PALA in an environment with a trusted `PATH`. Filesystem support and parser behavior depend on the installed Sleuth Kit version.

## Operational security recommendations

- Work from a verified forensic image when possible.
- Record source and output hashes, PALA version, command lines, and validation results.
- Use the least privilege required to read the source.
- Keep analysis systems patched and isolate hostile recovered content.
- Do not interpret successful carving as proof of authenticity, integrity, safety, or forensic completeness.
