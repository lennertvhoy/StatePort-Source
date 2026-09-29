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

### Build the production frontend before the Python suite

Parts of the Python suite boot the application and require the built production
bundle. Without it they fail closed with
`ValueError: StatePort production web build is missing` rather than skipping,
because the product refuses to serve a mislabelled artifact when
`apps/web/dist/index.html` is absent. A fresh clone has no `apps/web/dist` and
no `apps/web/node_modules`, so build it once before running the suite:

```bash
cd apps/web
npm ci --no-audit --no-fund
npm run build
cd ../..
```

CI runs `npm run build` in the "Build production frontend" step, which is why a
remote run and a local run otherwise disagree. Note that CI installs with
`npm ci --ignore-scripts` while the command above was measured with
`--no-audit --no-fund`; if one form fails for you, try the other, and prefer
whichever leaves you with a bundle that passes `npm run check:bundle`.

This is a build prerequisite for the test suite only. A locally built bundle is
a prepared-machine artifact and is **not** evidence of an installed, qualified,
or human-accepted product; the release journey and its evidence requirements are
unchanged by anything on this page.

### Give pytest a short scratch directory

Tests that bind a Unix socket put that socket's path inside the scratch
directory, and `sockaddr_un.sun_path` is limited to about **108 characters** on
Linux. A nested `--basetemp` can push it past that, and the failure is not
obviously a path problem:

```
OSError: AF_UNIX path too long
ExecutionHostTransportError: socket-refused: cannot connect to
  .../test_.../daemon/execution-control/control.sock: AF_UNIX path too long
```

Measured on this repository: that socket path was 111 characters and the test
failed; the identical test at the identical commit passed with a 12-character
`--basetemp`. 57 test files reference `AF_UNIX` or `.sock`, so this is not one
test's quirk.

Pass an explicit short scratch root rather than accepting the default:

```bash
python3 -m pytest -q --basetemp=/tmp/sp
```

pytest's own default names directories after the test, so a default
`/tmp/pytest-of-<user>/pytest-<n>/<long-test-name>/…` is already long before any
socket subpath is added. This is an environment concern, not a repository
requirement, and it is not a product defect.

## Conduct, security, and support

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). The
current disclosure gap is recorded in [SECURITY.md](SECURITY.md); do not put a
security report into a public channel while no private route is active. The
current bug and support boundary is in [SUPPORT.md](SUPPORT.md).
