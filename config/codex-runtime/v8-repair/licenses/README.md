# Retained third-party material in this preparation recipe

The recipe is preparation software; these notices describe the small upstream
source patches, regression inputs and metadata actually retained in Git. They
are not an inventory of licenses in a future full native archive or Codex binary.

| Material | Original terms and notice |
| --- | --- |
| `../v8-security-update.patch` | V8 BSD-3-Clause; `V8-BSD-3-Clause.txt`, including upstream exceptions. The 53 changed paths do not include the listed external test suites. |
| `../native-Cargo.lock` | Generated lock metadata from MIT-licensed rusty_v8; `Rusty-V8-MIT.txt`. Dependencies keep their separate licenses. |
| `../codex-consumer-compat.patch` | OpenAI Codex Apache-2.0 source context; `Codex-Apache-2.0.txt` and `Codex-NOTICE.txt`. |
| `../icu-corrections/*.patch` | Unicode-3.0; exact notice in `../icu-corrections/LICENSE-ICU`. Original source headers and patch authorship remain intact. |
| `../native-backports/libsqlite3-sys.patch` and `sqlite-upstream-regression.test` | SQLite public-domain source; the regression's original copyright disclaimer/blessing is preserved. The patch modifies only SQLite amalgamation code, not the Rust wrapper. |
| `../native-backports/lzma-sys.patch` | Maintained XZ v5.2 `src/liblzma/common/index.c`, author Lasse Collin, explicitly placed in the public domain. This is the native source patch, not a relicensing of the Rust wrapper. |
| `../native-backports/xz-upstream-regression.patch` | Current XZ test source carries SPDX `0BSD`; `XZ-0BSD.txt`. Original patch author is retained. |

Immutable source URLs and SHA-256 digests for verbatim notices are in
`sources.json`; ICU notice identity is in the parent recipe manifest. XZ source
scope was checked at exact upstream commits:

- https://github.com/tukaani-project/xz/blob/4343f5e7ceab1d3eee1b5e29bfa2340fb2d4ac54/src/liblzma/common/index.c
- https://github.com/tukaani-project/xz/blob/a3ea8832bec11128597c454f5d14d05ef6010e3f/tests/test_index.c

The downloaded toolchains, full source crates and binary artifacts are not
vendored or authorized for publication by these exact-path rules. Any future
binary/source distribution must preserve all applicable notices across the
complete selected dependency graph. Factual dependency manifests are source
provenance records and do not grant licenses to the referenced dependencies.


The additional Chromium vendor input set is external: 45 complete upstream trees
with exact license files retained during restoration. Their declared terms are
MIT, Apache-2.0, Unicode-3.0 and the combinations recorded per package in
`../chromium-vendor.json`. The factual tree/version/license manifest is committed;
the actual crate source, test data and license payloads remain in verified
external archives. Native source restoration preserves every pinned file, not
only files named by the compiler. Public distribution of those archives or the
resulting binary needs the full corresponding notices; the recipe allowlist does
not publish these input payloads.
