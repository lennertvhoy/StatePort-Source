# Two ICU source corrections

These patches retain ICU 78.2 API/data identity and the pinned Chromium ICU base
`d578f2e8b7bd5938e21cfb6bf15c079e0aa5b738`. They do not claim a full ICU 78.3
upgrade or security clearance. `recipe.json` pins exact original packaged files,
corrected files, upstream patches and the license notice.

`icu-source.patch` contains only the original upstream C++ source hunks, with
`icu4c/` stripped from paths. Both full upstream patches are preserved unchanged:

- `910bb20d66f1d19140bd045aed88d6402208326a`: ICU-23256 prevents remainder by zero
  after exponentiation overflow in rule-based number formatting. Its C++
  `TestDividedByZero` supplies `7060920374060940374/4:[]` and expects
  `U_NUMBER_ARG_OUTOFBOUNDS_ERROR`. The full patch includes the corresponding
  Java regression and source fix; those Java changes are not applied here.
- `fc010e8b96ca90ee37f9a5bc8f33e0621f4dbe75`: ICU-23319 makes UTF iterator template
  branches total using `if constexpr` and `static_assert`. The full patch retains
  the upstream C++ iterator test changes and Windows compiler-error setting.
  Those test/build files are absent from the packaged crate and are not silently
  invented or reported as executed.

The upstream patches are regression *inputs*, not runnable standalone tests.
Running them requires the corresponding ICU test harness, with each upstream
commit's parent source as the test preimage, or a reviewed port to the candidate
harness. Re-run the upstream rule-based formatter and iterator tests with the
actual compiled ICU; exercise ICU data registration, Unicode/Intl and Codex
CodeMode against the matching generated V8 bindings and musl target. No public API
signature, ICU data format, feature or sandbox option is intentionally changed.
Compile/ABI/data compatibility remains unproven until those checks run.

`LICENSE-ICU` is the exact license from the pinned Chromium ICU base, fetched by
immutable URL recorded in the recipe. Existing source copyright headers and
upstream patch authorship are preserved. Source preparation restores that notice
to `third_party/icu/LICENSE`, which the registry crate omitted. Distribution must
carry applicable ICU and third-party notices; this is not a complete distribution
license audit.

No downloaded payload changes: these small patches and notice are vendored in the
recipe. Existing verified input files remain reusable. The 53-file V8 repair
proof is separate from these two ICU postimages. Old prepared sources, receipts
and binaries remain untouched; native preparation always requires a new output.
