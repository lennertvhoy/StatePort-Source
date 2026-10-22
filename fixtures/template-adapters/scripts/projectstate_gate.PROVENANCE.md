# Provenance: `projectstate_gate.py` (vendored copy)

This directory holds a **compatibility fixture**: an immutable vendored copy of
one upstream file, used as the deterministic evaluator (ADR-0007) of the
ProjectState template adapter. It is classified under
[`docs/TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md`](../../../../docs/TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md)
as "compatibility fixture or snapshot", and this record carries the fields that
policy requires.

| Field | Value |
|---|---|
| Original source | `https://github.com/lennertvhoy/ProjectState_Template.git`, `scripts/projectstate_gate.py` |
| Exact source revision | tag `v6.4.0` → commit `237f1d04603f68b40a78e353c2a6a4a8f043f79b` (tree `1d0b16b24c74dc53fd28a2ecc104234b648509b5`) |
| Upstream blob id | `181141423931b00e0fc4178023b68270f991be39` |
| Content digest of this copy | `sha256:d0db4d913ff282c942b23fd796264422107418d7338911b324e4d0676f200861` (recorded as `GATE_SHA256` in `template_actions.py`) |
| Upstream release | `6.4.0` (recorded as `GATE_RELEASE` in `template_actions.py`) |
| Why vendored instead of resolved temporarily | The evaluator must run on the staged copy of an instance **inside the product's own sandbox**, with no network and no access to the owner's checkout of the template. Resolving the upstream repository at run time would put a network fetch and an unpinned checkout on that path. The gate is therefore pinned to one immutable digest, and the copy is byte-identical to that revision. |
| Format and reader under test | The ProjectState v6 core (`STATE.yaml`, `PROJECT.md`, `evidence/<slice>/summary.md`); the reader is `projectstate_gate.py` itself, invoked by `template_actions.py check` with `--root` on the staged copy. |
| Redistribution | Permitted by the upstream "ProjectState Free Use License – Teaching Rights Reserved" (Copyright (c) 2026 lennertvhoy), which grants use, copy, modification, publication and distribution provided the notice is retained. The verbatim notice is kept beside the copy as `projectstate_gate.LICENSE`. The same licence reserves teaching use; that restriction travels with the notice and is the owner's call to accept for this vendored copy. |
| Update policy | Immutable. A new upstream release does **not** rewrite this file in place: it produces a new copy with a new digest, a new `GATE_RELEASE`/`GATE_SHA256` pair and a new provenance record, and the two coexist until the adapter is switched over. |
| Removal criteria | When the ProjectState template is no longer an installed template, or when the upstream licence stops permitting redistribution, this copy and its `template_actions.py` binding are removed together. The public template contract (`docs/TEMPLATE_CONTRACT.md`) and the ADR-0007 evaluator binding are updated in the same change. |
| Owner for review | The StatePort owner decides the release; the machine-checked part of this record is the digest equality asserted by `scripts/test_agent_file_change_proposals.py::test_pinned_gate_hash_is_recorded`. |

The copy is loaded through `importlib` from a path next to
`template_actions.py`; it never executes repository-supplied text, and the
instance's own (editable) `scripts/projectstate_gate.py` is never what judges
an instance.
