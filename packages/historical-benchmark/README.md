# Historical candidate benchmark foundation

This package is a small, local-only foundation for comparing historical
candidate commits in a Git repository. It resolves commits and trees with
local Git commands, gives each run a complete configuration identity, and
executes a deterministic fake runner that copies a declared candidate file to
an artifact path.

The objective score contains only:

- local validator pass rate;
- repeated-run determinism rate; and
- expected-artifact presence rate.

Artifact file count and byte size are reported as measurements. No model,
network, host subscription, token, cost, latency, or subjective quality
metric is collected. The fake runner and temporary Git repositories are test
fixtures, not production execution or benchmark evidence.
