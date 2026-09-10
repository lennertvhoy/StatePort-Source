# V8 native repair preparation

This is a preparation-only repair candidate. The corrected native archive and
full `.3` static CLI have now compiled, and the final CLI passed ordinary provider
isolation in rootless namespaces at both runtime UIDs. The canonical current
results and exact external receipts are in
[the slice summary](../../../evidence/one-line-release-001/summary.md).
Independent reproduction, security disposition, consuming-image and native
installed qualification remain open. The provider release pin is unchanged.

The sections below retain the original pilot premises and subsequent findings;
statements that a check was unrun describe that pilot stage, not current status.
Choose each new job's limits from measured evidence and its admitted time window.
The latest CLI compiler needed6GiB high=max after a3GiB OOM; the compiler's resource
requirement is not the installed product's memory requirement.

`Consumer.Containerfile` now retains the stripped artifact, rejects a dynamic
loader or NEEDED entries, and exports the normal runtime feature graph, builder
package list, OpenSSL version and upstream LICENSE/NOTICE. These metadata are
inputs for review, not a complete linked-library SBOM or license audit. The
container recipe still needs its own build qualification; the completed local
consumer used an offline mounted vendor tree and different internal paths. Its
byte identity cannot be assumed for a future Containerfile build.

`recipe.json` pins rusty_v8 152.2.0 (packaged Rust API plus native source) and the
complete upstream V8 15.2.124.1 → 15.2.124.21 patch at
`4323497a6a73839e6d5260f6acd7ec0212cb3321`. All 53 resulting changed files were
compared with that exact upstream commit. Three tests omitted from the crate are
restored from the exact base commit before patching. V8 DEPS stays byte-identical.
The root's 20 submodule identities and all 66 V8 DEPS entries are inventoried in
separate digest-bound manifests; optional platform dependencies are inventory,
not a promise to fetch or compile every platform.

The consumer patch produces a new `0.146.0+stateport.3` source tree. It changes
V8 149.2.0 → 152.2.0, ICU data 0.77.0 → 0.78.0, and the Rust initialization API
`set_common_data_77` → `set_common_data_78`. The old and new V8 crate dependency
and build-dependency tables are identical; temporal_capi was already 0.2.3.
Only V8 and ICU change external Cargo lock identities. Full locked resolution,
Rust typechecking, native ABI correspondence and ICU execution remain unrun.
The consumer must use the archive AND generated bindings from the same repaired
native compilation. Existing r6/r7 archives cannot be reused as repair evidence.

## Inputs and local prerequisites

The two Containerfile images are already retained locally: the GNU workspace
image supplies glibc 2.39, Python 3.12, patch, git, dpkg-deb, and Linux UAPI headers;
the exact Rust Alpine image supplies musl 1.2.5-r23 headers and CRT/static libc.
These are read-only image-layer observations, not a successful builder run.
No host Rust installation, package install, moving image tag, credential or host
container socket is supplied to the builder.

Native compilation uses the DEPS-pinned Chromium Clang 23 and Chromium Rust
payloads. Outer Cargo/Rust is official 1.95.0. Bindgen uses matching LLVM 21.1.8
libclang, libLLVM and resource headers; their Ubuntu packages were checked against
LLVM's signed repository metadata. GNU host tools use the pinned Bullseye sysroot;
target compilation uses the separate musl sysroot. Exact URLs, sizes and SHA-256
values are in the recipe. GN/Ninja use immutable CIPD instance IDs (SHA-256
identities); their stable download endpoints returned GET 200 with the expected
length. Those endpoints reject HEAD with 405.

Complete downloads, including native Cargo dependencies and ICU data, total
633,541,181 bytes before decompression. The inspected public local cache contains
72 of 121 native registry crates (16,890,195 bytes), the 36,569,477-byte V8 crate
and three restored test preimages. The coordinator completed all 138 inputs (633,541,181 bytes) on 2026-09-05 at
22:22:27 UTC; retrieval alone is not native execution proof.
Use only public source caches in `--cache`; every reused file is SHA-256 checked.
Unpacked disk, native peak memory and duration are **unmeasured**. The 3 GiB,
one-CPU container cap (the governor ancestor further limits the whole job to
70% of one CPU), 25-minute native attempt below is a bounded pilot, not a completion
estimate. Compilation may exceed that cap and must fail with retained evidence.

## Coordinator commands

Run sequentially only after booking the existing heavy-operation governor slot.
Each command below must receive its own `scripts/release_guard.py authorize
heavy_operation <receipt> -- <exact command>` receipt, then run through
`~/.kimi-code/governor/heavy-run.sh 3G <exact command>` with
`STATEPORT_RELEASE_ACTION=heavy_operation`, `STATEPORT_RELEASE_GUARD_RECEIPT`,
`STATEPORT_GOVERNOR_MEMORY_HIGH=2560M`, `STATEPORT_GOVERNOR_MEMORY_MAX=3G`,
`STATEPORT_HEAVY_RUNTIME_MAX=30min`, and a unique governor state directory.
The output parent must already exist; each stage output must be new.
Here `$repo` is the reviewed checkout and `$run` is a new, owned external parent.

```sh
python3 "$repo/config/codex-runtime/v8-repair/fetch.py" --output "$run/inputs"
python3 "$repo/config/codex-runtime/v8-repair/booked_pilot.py" builder --output "$run/builder"
python3 "$repo/config/codex-runtime/v8-repair/booked_pilot.py" native --output "$run/native" --inputs "$run/inputs" --vendor-inputs "$run/chromium-vendor-inputs-r1" --image-id-file "$run/builder/image-id"
```

`booked_pilot.py` checks actual finite governor service cgroup controls and places
Podman children inside that service. The native stage uses `--cgroups=no-conmon` with `--cgroup-parent` set to the
exact governed service. The payload is placed directly below that service while
conmon remains within its owned runtime child. The actual PID observer must prove
both descendants before any compilation. This replaces split-mode nesting, which
failed before compilation because the nested payload lacked controller files.
The real same-image admission probe passed the corrected placement and limits. Builder uses its separate unique Buildah cgroup-parent.
Builder context contains only this recipe,
not the checkout or preparation caches. Both build and native run have network
none and pull never. The native container has a read-only root, no capabilities,
no-new-privileges, explicit PID/memory/CPU bounds, and only owned input/work mounts.
The stopped diagnostic container and output tree are retained for review.
Unexpected tool archive layouts or missing dependencies fail; no online fallback
or host-tool substitution is allowed. Governor timeout/OOM may prevent the inner
receipt: preserve the governor receipt, stage command, logs and partial work.

Source-only consumer preparation is independently reviewable and does not compile:

```sh
python3 "$repo/config/codex-runtime/v8-repair/prepare.py" consumer --source "$retained_r6_source" --output "$run/codex-source-r3"
```

The source preparer verifies every changed input and output, refuses existing
output trees and leaves the retained input source untouched. Fetch failures retain
partial bytes. Never reuse a failed output directory for another attempt.

## Expected proof and unresolved limits

A successful pilot emits `native/work/artifacts/` with the native archive, matching
Rust bindings, GN arguments, Cargo lock and source receipt. Its native build
receipt records inputs, environment, duration and hashes; it explicitly remains
unqualified. Builder and native stage logs are separate.

Source validation passed: real complete V8 patch and all 53 postimage digests;
existing-output refusal; corrupted-source refusal before creating output; patch
of the three real consumer files with only two changed external lock nodes; and
host execution refusal. Ruff and diff whitespace checks pass. No native compile,
container prerequisite execution, generated bindings, consumer typecheck or ICU
smoke test has run. Upstream crate metadata reports `dirty: true`; the registry
SHA binds packaged bytes, but git identity alone does not certify that entire
packaged tree. Tool archive layouts and cross-toolchain execution remain pilot
premises. No source-build reproducibility claim is made.

Before adopting the candidate: complete native compile and upstream/relevant
regression tests, exercise real Codex CodeMode API and ICU paths with the resulting
bindings, account for every relevant native advisory (including non-V8 inputs),
scan exact final bytes with a native-inclusive inventory, independently rebuild,
and rerun sandbox and installed runtime qualification. The old vulnerable inputs
remain blocked; this recipe supplies no security exemption or feature reduction.

The native runner additionally captures the actual container ID, init PID and
conmon PID, their `/proc` start times and cgroup memberships, and direct plus
ancestor quota files in `containment.json`. Both processes must be within the
exact booked governor service; a similarly prefixed sibling is refused. The
native entrypoint waits for that measured receipt before input processing or
compilation. Failed/missing observation stops the owned container and retains
`containment-failure.json`. Fixture tests cover inherited limits, an outside
conmon, a sibling-prefix mismatch and unbounded ancestor refusal. Actual Podman
containment remains unrun for this native pilot; declared cgroup configuration
alone is not proof. Builder
RUN process containment is still a separate qualification limitation.

Native preparation now also applies two separately pinned ICU source corrections
(ICU-23256 and ICU-23319) after verifying the unchanged 53 V8 postimages. See
[the ICU correction notes](icu-corrections/README.md) for upstream regression
inputs, licensing and remaining API/data proof. The receipt reports two ICU
postimages separately and distinguishes unchanged dependency pins from changed
native dependency source. Five source/integrity checks pass: complete preparation,
existing-output refusal, corrupted ICU preimage refusal, corrupted patch/regression
or license refusal, and unchanged identities for all 138 external inputs. No
additional payload download or native compilation was performed for these fixes.

The recipe retains original upstream license/notice texts and classifies every
recipe file by exact path in the existing public-export policy. See
[the retained material notice](licenses/README.md). No downloaded source archive,
toolchain payload or binary is included by those rules.

The first real native pilot passed actual init/conmon containment, offline input
verification, source preparation, Rust component installation, native Cargo
resolution/compilation of dependencies and GN generation. Ninja then refused the
crate-excluded `third_party/icu/common/icudtl.dat` before C++ compilation. Source
preparation now restores it from the already-pinned `deno_core_icudata` archive:
its SHA-256 and Git blob identity exactly match the pinned Chromium ICU source.
No feature setting or external download identity changes. The consumer data and
restored embedded data are the same bytes. Four source integrity/refusal checks
pass; this is not an ICU runtime or native-build pass.

The generated target also exposed the missing
`third_party/rust/chromium_crates_io/vendor` source graph. The source crate omits
that directory; native GN expects its exact Chromium versions and generated
headers. Outer Cargo's vendor directory is a separate graph and cannot be blindly
substituted. In particular, native GN declares temporal_capi/temporal_rs 0.2.4
while the outer Cargo lock currently declares 0.2.3. Compatibility and provenance
must be established before a second compile; do not disable Temporal to proceed.


The selected Chromium vendor graph is now restored from 45 exact upstream tree
archives at gitlink `afbc96607d0e659715d803cc099607dd1737fc41`:
3,675,819 compressed bytes, 25,645,531 expanded bytes, 1,742 regular files.
`chromium-vendor.json` records every Git blob/mode, transport SHA-256/size,
package version and license. The original 138 inputs remain unchanged and are
mounted separately from this additional read-only input directory. No source
payload is committed to Git. Retrieve these archives only through a separate
booked `chromium_vendor.py --output <new-directory>` fetch; the native runner now
requires `--vendor-inputs <verified-directory>`. Source-only preparation accepts
the same argument. Existing source/output trees are never updated in place.

Chromium's vendor Cargo lock and checksum stubs are not registry-integrity
proof. Complete pinned upstream tree verification preserves Chromium patches,
generated headers, tests and license files. Of the selected packages, the pinned
patch directory identifies the icu_locale_core numeric-singleton correction
(upstream ICU4X PR8019); it is already present and is not applied twice.

All 83 generated C++ Temporal headers from native Chromium 0.2.4 are byte-identical
to the verified outer temporal_capi 0.2.3 headers. This is a useful header/API
premise, not a passed final link or Temporal behavior test. Native Rust versions
remain their exact Chromium versions; outer Cargo versions are unchanged.
Upstream 0.2.4 contains date/duration behavior corrections, so header identity is
not a claim that the two implementations are equivalent or fully qualified.

`booked_pilot.py native --timeout-seconds N` now forwards an explicit integer
native deadline, default 1500 and permitted range 1–21600 seconds, matching the
inner pilot bound. Invalid values fail before governor lookup or output creation.
Initial planning allowed `N=7200` (120 min) with a separate 125-minute
governor deadline and the same 3 GiB/70% CPU limits. That historical envelope
is not authority for another run or a completion estimate.
The original selected generated Ninja graph contained 4,074 C++ compile edges and 142 Rust
compile edges, plus generation, assembly and linking. No measured C++ throughput
was available at that point. At 70% CPU, 120 minutes provides at most 5,040 CPU-seconds for all work;
there is no evidence that this guarantees completion. Use fresh builder/native
outputs with the complete repaired source and verified offline inputs. The
previous failures and their outputs stay intact. The resumed-cache checks below
apply before considering a continuation under a newly authorized work envelope.


## Checking a stopped resumed run

`verify_cached_work.py` accepts both the original three-mount pilot and the
resumed eight-mount pilot. A resumed command must match its retained admission
and the complete correspondence receipt, exact canonical mount roots, builder,
recipe, and unchanged pilot/runner identities. The earlier verifier identity is
historical; the current verifier reconstructs and compares the source, tool and
vendor trees again. Host admission helpers are imported only on the host so the
original pinned builder can still execute inner reconstruction.

Use new output and receipt paths for each admitted correspondence check. A passed
comparison establishes source/tool correspondence, not generated-object or final
artifact provenance. Before any compilation continuation, inspect the selected
remaining build graph and measured throughput against the actual deadline. A
passed cache check alone does not justify another timed-out compile or qualify
a provider. The official-upstream alternative remains a separate compatibility
experiment until its complete native/security/runtime requirements pass.


## Ordinary upstream compatibility experiment (2026-09-09)

An isolated copy of the unchanged Codex 0.146 initializer passed both an offline
Rust API check and a native musl link/run with V8 150.4.0, its official matching
ptrcomp/sandbox archive and bindings, and ICU data 0.77.0. The compiler was pinned
Rust 1.95.0 in the independently reconstructed tool tree. The run exercised
jitless initialization, idempotent same-mode initialization and conflicting-mode
refusal, with network disabled and measured 3 GiB/70%-CPU containment. It used a
new output tree; no production dependency, recipe or provider default changed.

The original upstream V8 fix `df948e6725883d290998e99343a7ef093f781c13` is an
ancestor of V8 15.0.245.2. The M149 cherry-pick identifier itself is not that
ancestor. This supports investigating the upstream alternative; it does not
establish complete native-library advisory coverage or provenance of every
object in a prebuilt archive. Full CodeMode/CLI consumer compatibility, selected
ICU/SQLite/XZ sources, exact final linkage, reproducibility, packaged isolation
and installed provider execution remain required. The experiment does not
qualify a release or replace unresolved security evidence.

The retained repaired native cache independently matches 41,314 native files,
1,220 tool files and 8,717 vendor files. Its selected remaining closure has
408 C++ outputs plus an archive; the recent 100 compiler outputs had a median
6.996-second duration under the recorded limit. This is a partial throughput
observation, not a total completion estimate; generated objects remain
unqualified and no further native compile was admitted in the one-hour run.
