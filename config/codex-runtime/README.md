# Provider runtime inputs

The npm lock remains the default input for both production consumers. Both
consumer recipes also implement an optional, locked custom OCI input, currently
**disabled with null identities** in `config/provider-runtime-inputs.yaml`.
The source build in this directory is **preparation only**; no reviewed custom
producer has been admitted to a release image. Enabling the input requires
independent reproduction, exact provenance and security qualification first.

The current repaired preparation target is `0.146.0+stateport.3`, described by
`v8-repair/recipe.json`; the `.2` recipe and experiments below are earlier work.
Required native security proof remains paused, and independent reproduction of
the current target is incomplete. Preserve partial builds and read the current
slice evidence before admitting a new build.

A September 10 source assessment of upstream Codex `0.154.0` found that its
immutable Cargo lock still selects the same `libsqlite3-sys 0.37.0` and
`lzma-sys 0.1.20` archive checksums as the pre-backport inputs in
`v8-repair/native-backports/pins.json` (bundled SQLite 3.51.3 and XZ 5.2.5).
Updating Codex alone is therefore not an established resolution of those source
blockers. This source comparison does not establish upstream binary linkage
or replace required security proof.

The upstream Codex 0.146.0 proc-mount classifier recognizes Bubblewrap's former
`/newroot/proc` diagnostic but misses the `/proc` spelling in Bubblewrap 0.12.
`proc-mount-compat.patch` recognizes both exact destinations while retaining the
existing errno family and upstream fallback. It changes neither namespace,
filesystem, seccomp, network nor approval policy. Regression cases accompany the
patch. Bubblewrap remains 0.12; no vulnerable downgrade or sandbox bypass is used.

`prepare-source.py` verifies the source archive, patch and upstream Cargo.lock
against `source-build.json`, applies both patches without fuzz, and assigns the
distinct version `0.146.0+stateport.2`. The release tag's local workspace lock
entries need version normalization from 0.0.0. `dependency-updates.patch` first
applies exact locked security updates for Gitoxide 0.83.0 and Rust OpenSSL
0.10.80, with their required transitive changes; the patched lock hash must
match before version normalization. Normalization must preserve those reviewed
external records and checksums. No build-time dependency update is allowed.
Existing output directories refuse reuse.

The Containerfile builds the full CLI for native musl with pinned Rust and V8
inputs and one Cargo job to bound compiler concurrency. The supported `OPENSSL_NO_VENDOR` setting selects the already pinned
static OpenSSL 3.5.8 instead of building a second vendored library. It then
exports the binary, source preparation receipt, dependency lock and
runtime graph with resolved features, compiler/package observations, upstream
license and notice.
Its output is not a StatePort release image. Invoke image builds through the
workstation governor and give Buildah a separate descendant cgroup, as the main
release-image builder does. Source preparation alone is a cheap local operation:

```sh
python3 config/codex-runtime/prepare-source.py verified-source.tar.gz new-output
```

Before wiring this artifact into either runtime image, compare independent
builds, review its vulnerabilities and provenance, and run the normal CLI through
`scripts/qualification/provider_sandbox_probe.py` inside the confined image. The
installed rehearsal uses that same probe against the exact signed-image-verified
container ID. Credential-free sandbox success does not establish authentication,
provider requests, installed lifecycle, native WSL qualification or human acceptance.

Use the probe's default `--runtime web` for UID/GID65532 and
`--runtime workspace` for UID/GID10001 in the Ubuntu developer image. Both
profiles run the same boundaries with that image's Python interpreter and an
empty provider home. The report includes the observed CLI version and proves
that the parent can create an Internet socket before requiring the sandboxed
child to refuse one; no connection is made. The installed web controller
requires the web identity and the complete boundary report.

The first source-lock assessment found 13 high-severity advisory matches.
Targeted security updates reduce that inventory to two: the selected runtime
graph excludes Quinn, and its Hickory features exclude the DNSSEC prerequisite.
The complete GNU prototype compiles and passes the normal sandbox probe,
including namespace isolation. The recovered complete musl CLI also passes the same sandbox journey in
both retained consuming images. A fresh database scan of that artifact and
conservative full Cargo.lock again finds the two High matches. Its exact normal
CLI graph excludes DNSSEC features and Quinn; the scan remains review-required,
and complete static-native-library coverage is still pending. This is neither
a clean release scan nor an exception. See the current slice evidence
before considering this preparation artifact for release.

Two native-musl attempts produced no binary: one exceeded its deadline and the
second was stopped during sustained memory-reclaim and I/O stalls. A longer
deadline alone did not resolve the compilation cost within 3 GiB. The preparation
recipe now uses release optimization level 1, no debug information, LTO disabled
and 16 code-generation units, while retaining one Cargo job and the same source
and dependency pins. The bounded app-server-protocol experiment compiled with
these settings in 27m21s including dependencies. Full CLI compilation, runtime
performance, sandbox checks and independent rebuilding remain separate gates.
Retain the normal CPU and memory limits for every build.

The full CLI then compiled its major crates but reached the 90-minute deadline
during the final GNU link, with its swap allowance full. The preparation recipe
selects Alpine's pinned LLD21 with one linker thread. Rust's bundled LLD lacks
support for Alpine's compressed debug sections; the packaged linker passed a
real static-executable premise after package-signature verification. Recovery
reuses the retained compiled objects and writes a separate binary. The recovered full CLI linked successfully in398.83s and passed version/static
AMD64 ELF checks. The recovered binary now passes the normal sandbox journey
in retained web and Ubuntu workspace images, including separate namespaces and
filesystem/network refusals. The workspace probe keeps its outside fixture out
of `/tmp`, which the normal workspace-write policy permits. The fresh scan and
its unresolved coverage limits are recorded above. The independent current-target
build was stopped at the owner's request; its partial work is preserved.
No build is running at this checkpoint. Binary and OCI reproduction remain
required. These linker packages are build tools; the output remains a scratch
artifact image. The output includes the observed linker version.

`bubblewrap.Containerfile` prepares the matching static, position-independent
Bubblewrap0.12 companion for images without a suitable system binary. Its
upstream source archive is pinned in `bubblewrap-build.json`; the output includes
the archive, both upstream license files and package observations. The same
normal CLI probe passes with the first static companion prototype in the
retained web image. The repository recipe additionally verifies PIE and downloads
the pinned source directly. Two builds with caching disabled match in both OCI
image and binary digests; rootless Ubuntu namespace/filesystem portability also
passes. Full musl-provider integration and final scanning remain pending. No release image consumes the companion yet.
