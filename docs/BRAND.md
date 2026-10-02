# StatePort brand usage

StatePort's canonical product mark is the light block-arch mascot and compact
house-check favicon owned by StatePort and committed under
`apps/web/assets/brand/`. The dark detailed SVG remains committed as untouched
provenance, not an active UI asset. The old blue mascot and v2 family remain
recorded as private or rejected provenance only; none are wired into the shell.

## Product tokens

- Infrastructure navy: `#0B132B`
- Orchestration blue: `#2563EB`
- Active-port cyan: `#22D3EE`
- White: `#FFFFFF`
- Supporting slate: `#94A3B8`
- Success, warning, and critical colors are separate semantic tokens.

The canonical CSS token source is
[`apps/web/src/styles/tokens.css`](../apps/web/src/styles/tokens.css),
with the machine-readable summary in the private-internal
`brand/design-tokens.json`.

## Asset boundary

Canonical ownership, hashes, relationships, required sizes, and adoption
provenance are recorded in [`brand/source-manifest.json`](../brand/source-manifest.json).
The exact static web-surface contract is enforced by
[`scripts/test_web_surface.py`](../scripts/test_web_surface.py).

Use the imported local light asset for detailed marks and the favicon for compact
marks. Vite bundles them as same-origin files; do not redraw the mascot in CSS,
filter it, embed remote references, or replace it with inline geometry. Preserve
all committed SVG bytes, including the inactive dark provenance asset, and use
the favicon path recorded in the manifest.

## Shell sizing

- Compact marks at 16px, 20px, 24px, and 32px use only the canonical favicon.
- Detailed marks at 40px and above use only the canonical light mascot.
- Expanded sidebar and mobile drawer lockups use a 40px detailed mascot in the
  existing header control.
- Compact rail uses a 24px favicon centered and clipped inside its existing
  40px control. No 33px-39px mark size is supported.
- The lockup remains non-wrapping at 320px, 390px, and 125% font scale.

## Accessibility

The mascot is decorative beside the visible `StatePort` wordmark. A standalone
mark receives an accessible name and `role="img"`; theme changes do not replace
the active light detailed asset. Brand color is not used as the only status
signal. Focus uses a visible semantic ring, and
reduced-motion and forced-colors fallbacks are included in the stylesheet.
