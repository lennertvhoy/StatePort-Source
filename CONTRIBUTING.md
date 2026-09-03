# Contributing to StatePort

StatePort is not publicly released, and **external contribution intake is
currently closed**. No contributor-agreement signing or verification route is
active. Please do not open a pull request, send a patch, or submit code until
the project owner publishes that route.

This boundary prevents the repository from accepting work without a truthful
rights and review process. An issue, patch, or pull request does not create a
right to merge, redistribute, or dual-license the submitted work.

## Good starter scopes once intake opens

Prefer one small outcome that can be reviewed and reverted independently:

- correct a broken link or unclear alpha limitation;
- improve a Linux local-workflow diagnostic or error message;
- add a focused regression test for a reproducible defect;
- clarify a StateSpec schema example without changing its contract; or
- improve a public-safe synthetic fixture using invented data only.

Avoid broad refactors as a first contribution. Changes to execution authority,
permissions, security/privacy gates, canonical-source policy, licensing,
governance, release automation, infrastructure, or real learner data require
maintainer agreement on an explicit scope before implementation.

## Standards

- Submit only work you have authority to contribute.
- Never include credentials, private conversations, learner material, user
  instances, private paths, or unclassified third-party material.
- Preserve third-party notices and record the source and licence of external
  material.
- Keep the change narrow and add regression coverage for a defect.
- Preserve public Stateware, State-Centric Engineering, StateSpec, StudyState,
  and ClassState terminology; legacy identifiers remain only where the
  [terminology policy](config/terminology-policy.yaml) permits them.
- Do not weaken ownership, security, privacy, approval, state-integrity, or
  evidence gates to make a test pass.
- Describe implemented, locally validated, remote-CI-validated, released, and
  human-accepted states separately.

## Proposed workflow after intake opens

1. Use the published non-security issue route to agree the user outcome,
   boundary, and acceptance evidence. Never report a vulnerability publicly.
2. Complete the written contributor licence agreement through the published
   route. A DCO sign-off is not a substitute; see [CLA.md](CLA.md).
3. Start from the documented base in a fresh branch or isolated worktree.
4. Make the smallest coherent change, including tests and documentation.
5. Run focused checks plus the repository gate and state all limitations.
6. Open a pull request. Maintainer review is required, and release authority
   remains with the project owner under [GOVERNANCE.md](GOVERNANCE.md).

## Local setup and validation

The current developer baseline is Linux with Python 3.10 or newer. Start with
the [StudyState local quickstart](docs/LOCAL_ALPHA_QUICKSTART.md) and the
[architecture overview](docs/ARCHITECTURE_OVERVIEW.md). At minimum, run:

```bash
python3 scripts/validate_repo.py
git diff --check
bash scripts/gitleaks_scan.sh
```

Then run the focused test documented for the component you changed. Frontend,
packaging, browser, and release checks have additional dependencies and do not
become required merely because a documentation-only change exists. A local
pass is not remote CI, release, production, independent-review, or human
acceptance evidence.

## Conduct, security, and support

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). The
current disclosure gap is recorded in [SECURITY.md](SECURITY.md); do not put a
security report into a public channel while no private route is active. The
current bug and support boundary is in [SUPPORT.md](SUPPORT.md).
