# Native backports for the new Codex consumer tree

Preparation only. The current release pins and retained r6/r7 source/artifacts are
unchanged. The two native repairs supplement the V8/ICU candidate; they do not establish
that the complete native stack is fixed or that the consumer builds.

* SQLite CVE-2026-11822/11824: the exact bundled fts5LeafRead function equals the
  vulnerable upstream preimage. The one-line guard changes `pRet->nn<4` to
  `pRet->szLeaf<4`, matching upstream Fossil commit
  `061febcf41ca4872a0f407951e1507209daca7895122b909a7806c60b6e200c4`.
  `libsqlite3-sys.patch` adapts that exact guard to the amalgamation location;
  before/after file hashes are pinned. FTS5 remains enabled.
* XZ CVE-2026-34743: the exact maintained v5.2 patch
  `4343f5e7ceab1d3eee1b5e29bfa2340fb2d4ac54` repairs empty-index preallocation in
  bundled lzma-sys 0.1.20. The patch applies without fuzz; its second hunk has a
  harmless -10-line offset against the packaged 5.2.5 source. The entire resulting
  file is checked against its pinned expected SHA-256. No decoder is removed.

`pins.json` binds the original registry crate checksums, native source preimages
and postimages, exact patches, regression inputs, and the three expected files
of the preceding V8/ICU consumer candidate. The helper copies that consumer to a
**new** tree, extracts the verified crates under `codex-rs/stateport-native-overrides`,
and adds three explicit local `[patch.crates-io]` entries. It changes only those three
Cargo lock nodes from registry to local source; versions, dependencies and
features remain the same. The existing candidate version remains .3, which is
unreleased. This is a source candidate, not an artifact with certified new bytes.

```sh
python3 "$repo/config/codex-runtime/v8-repair/native-backports/prepare_backports.py" \
  --source "$run/codex-source-r3" \
  --inputs "$verified_public_crate_directory" \
  --output "$run/codex-source-r3-native-backports"
```

The input directory must contain exactly named libsqlite3-sys-0.37.0.crate and
lzma-sys-0.1.20.crate and ts-rs-macros-11.1.0.crate files; unrelated cache files are ignored. The manifest gives
immutable registry URLs, sizes and hashes for a coordinator-booked fetch if they
are unavailable locally. No download or compile occurs in this helper. The source
must be the previous `prepare.py consumer` result, not r6/r7. Failed outputs are
retained and cannot be reused. Patched source input hashes and the resulting
Cargo manifest/lock hashes are recorded inside the new override directory.

The regression files are exact upstream inputs, not executed tests:

* `sqlite-upstream-regression.test` is the new fts5corruptA.test from the fixed
  SQLite commit. It requires the upstream Tcl SQLite test harness, FTS5 and
  corruption-testing support. Run it against the patched amalgamation with the
  actual consumer compile flags; expected outcome is controlled corruption
  rejection, not memory corruption.
* `xz-upstream-regression.patch` is upstream commit
  `a3ea8832bec11128597c454f5d14d05ef6010e3f`, which encodes an empty index, decodes
  it, then appends one record. It targets the newer upstream test harness; it is
  deliberately not claimed to apply to the packaged old test file. Port the
  unchanged API sequence into the selected source's harness and use ASan or an
  equivalent memory checker: an ordinary successful exit can miss this overflow.
  The upstream follow-up `f3b5688159c60495f48db3942a36509671dfce89` documents that
  sanitizer requirement. Source/test identity and any harness adaptation must be
  retained with the eventual run.

Source preparation and integrity/refusal checks were exercised on the three real
consumer files plus both complete SHA-verified source crates. This fixture is not
a complete build tree. Locked Cargo resolution, native regressions, Codex
persistence/migrations and final archive/link tests are unrun. The future build
must retain final linker inputs proving these exact local crate overrides were
selected, then account for all remaining native advisories and scan final bytes.
Neither an unproved current caller exclusion nor a version label substitutes for
that proof.

## Optional maintained SQLite 3.53.4 source — 2026-09-10

The ordinary command above retains the existing exact SQLite backport. A separate,
explicit `--maintained-sqlite-archive` input prepares an alternative source-only
candidate from the official `sqlite-amalgamation-3530400.zip`; it is deliberately
not wired into `consumer_context.py` or any default build path.

```sh
python3 "$repo/config/codex-runtime/v8-repair/native-backports/prepare_backports.py" \
  --source "$run/codex-source-r3" \
  --inputs "$verified_public_crate_directory" \
  --maintained-sqlite-archive "$verified/sqlite-amalgamation-3530400.zip" \
  --output "$run/codex-source-r3-maintained-sqlite"
```

`maintained-sqlite.json` pins the official archive, `sqlite3.c`, `sqlite3.h`, and
`sqlite3ext.h`, including SHA-256 and SHA3-256 identities, SQLite 3.53.4's source
ID, its distinct `SQLITE_VERSION_NUMBER` API value `3053004`, and their exact archive root. Before copying the consumer tree, the helper
rejects a missing, wrong-size, wrong-hash, unsafe, encrypted, duplicate, malformed,
or unexpected archive member. It reads the three authenticated members directly
from the ZIP and replaces only `libsqlite3-sys-0.37.0/sqlite3/sqlite3.c`,
`sqlite3.h`, and `sqlite3ext.h` in the new local crate override. It does not mutate
the retained input source or crate archive.

In this opt-in mode only, `libsqlite3-sys.patch` and its historical custom SQLite
regression input are not required or applied. The crate's `build.rs`, Cargo flags,
generated bindings, and every non-SQLite override remain unchanged. In particular,
libsqlite3-sys 0.37.0's generated binding constants still identify its bundled
SQLite 3.51.3 / API number `3051003`, while the replacement source identifies
3.53.4 / `3053004`; the preparation receipt records that mismatch rather than presenting
the constants as updated. The receipt explicitly records maintained SQLite 3.53.4,
the archive/member/source identities, and marks compilation, standard upstream
suites, and release qualification `not_run`.

## Deterministic macro output

The third local override pins ts-rs-macros 11.1.0 and sorts only the generated
dependency calls and inferred generic bounds at the token emission boundary.
Randomized HashSet iteration previously changed generated Rust across processes.
All dependency calls, deduplication and existing where predicates are retained;
no RNG seed, dependency version or public TypeScript feature is changed. Both
modified files have exact preimage/postimage hashes in pins.json.

The R5 focused dependency-emitter probe produced 12 original orders versus one
sorted order with the same ten unique calls. Real registry extraction and patch
application pass. The R6 complete derive probe also compiled and ran real struct/enum dependency
declarations and inferred generic bounds in32.67s. Upstream macro-suite coverage
and independent final CLI byte comparison remain unrun.
Old compiler contexts and both differing CLI artifacts are preserved.

## Maintained XZ selection — 2026-09-10

The consumer recipe now installs matching Alpine5.8.4 XZ runtime, static and
development packages. The development package supplies liblzma.pc; without it,
the existing no-static-feature Rust graph fell back to the bundled5.2.5 source.
PKG_CONFIG_ALL_STATIC remains enabled. The recipe rejects environment overrides
that force bundled compilation or disable/change pkg-config linkage.

A bounded musl binding probe installed the signature-checked5.8.4 APK set,
selected /usr/lib, reported5.8.4, passed an ordinary valid-data roundtrip and
produced an ELF without INTERP/NEEDED. The original runner failed afterward on
an over-specific Cargo-output assertion; separate retained-byte verification
passed. This is neither a full consumer build nor memory/security qualification.
Evidence is maintained-release-20260910 in the slice summary.

XZ5.8.3 is not the replacement target: upstream5.8.4 fixes the newer
GHSA-5qpq-xqfv-j9pg advisory. Existing override files and historical artifacts
remain preserved; the new complete provider must prove actual final archive
selection before claiming the bundled backport is no longer consumed. SQLite
replacement, standard upstream suites and all exact-candidate gates remain open.

The same option is exposed by `consumer_context.py --maintained-sqlite-archive`.
That entrypoint copies the maintained-source identity into its context receipt,
and its inventory binds the actual replaced files. Historical default mode and
all previous artifacts remain available; new maintained-source candidates must
explicitly select the verified archive and retain a new context receipt.
