# StatePort diagnostics

This package provides the stable `SP-*` diagnostic contract and a read-only
`Doctor` runner. `Diagnostic` and `DoctorReport` serialize to deterministic,
JSON-safe data and redact secret-like fields and values. `Doctor` checks the
Python runtime, Git worktree, path/symlink safety, local configuration, and the
synthetic host capability fixture. UI/API checks are opt-in and use bounded
read-only probes; the package never mutates the checkout.
