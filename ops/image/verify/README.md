# Offline image-evidence validator

`validate-release.py` performs provider-free schema and content validation for a
locally supplied image-evidence fixture. It uses PyYAML and Python 3.12 or newer. With
`--base <git-revision>`, it additionally checks that existing release
directories were not added, modified, deleted, or renamed; README mutability is
preserved. Git path output is parsed NUL-safely, and staged, unstaged,
untracked, ignored, and index/worktree inconsistencies in existing releases are
rejected. The staged index tree is also validated as the candidate release
state. Without a base it makes no append-only history claim.

The validator does not inspect Docker, host state, credentials, deployment state,
or live evidence, and its result is not a release or promotion claim. YAML is
strict: duplicate keys, anchors/aliases, unsupported tags,
binary scalars, unknown keys, and missing keys are rejected. Every release
directory contains exactly `release.yaml` plus the five regular evidence files.
PyYAML is the runtime/test parser dependency and pytest runs the focused tests.
The dependency declaration is
`ops/image/verify/requirements.txt`. Test fixtures create their own temporary
release directories; this public snapshot intentionally contains no release
records or compatibility pointer.

`release.yaml` requires `schema_version: 1`, matching `release_id`, accepted
status, `accepted_at` no later than `recorded_at`, `reproducibility: not_guaranteed`, full
profile/image/base identities, Hermes fields, operator attestation, exact
evidence/hash declarations, and these exact build inputs:
`recipe`, `apt_packages`, `python_requirements`, and `capability_check`. Each
build input must be an existing regular file under `ops/image/recipe/`.

Inventories use exact headers and deterministic normalized ordering. R session
information must identify R, Platform, and attached base packages. Capability
output must contain exactly the eight lines emitted by
`ops/image/recipe/check-capabilities.sh`, in order, with numeric Python and R
versions. Legitimate `/usr` and `/opt`
paths in R session information are allowed; known host roots, credentials,
PEM/token/session-cookie/JWT patterns, and raw live-evidence categories are not.

Run the CLI with `--help` for options. Tests are under
`ops/image/verify/tests/` and use provider-free temporary Git repositories.
