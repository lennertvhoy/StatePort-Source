# Public snapshot audit

`scripts/public_snapshot_audit.py` performs a local, read-only, fail-closed
audit of an already materialized public candidate. It does not export,
publish, push, or certify the candidate. The earlier release-reconciliation
exporter has now been ported as an active local primitive, but its old blocked
policy was not revived.

## Materialize an exact local candidate

`scripts/materialize_public_snapshot.py` composes the exact-path exporter,
Sensitive Data Gateway, one-commit Git materialization, complete external
rights inventory, and this independent audit. Candidate and evidence paths
must be new and outside the private source repository. The private detector
file is an operator input and must also remain outside the repository.

```bash
python3 scripts/materialize_public_snapshot.py \
  --source /path/to/private/source \
  --commit <exact-full-head> \
  --policy config/public-export-allowlist.v1.yaml \
  --private-detectors /path/to/private-detectors.json \
  --candidate /path/to/new-public-candidate \
  --evidence /path/to/new-private-evidence
```

The tracked policy grants public inclusion only by exact file path, defaults
all future paths to blocking, keeps operating state and unverified assets
private, and records binary or detector-triggering exclusions. Passing output
is local internal redistribution evidence—not legal certification, public
release, publication approval, or human acceptance.

Run it with a candidate Git root and an external descriptor:

```bash
python3 scripts/public_snapshot_audit.py \
  --candidate /path/to/candidate \
  --metadata /path/to/private-audit-inputs/audit-input.json
```

The descriptor is external so an exact candidate commit can be recorded
without asking a tracked file to contain its own Git object ID:

```json
{
  "formatVersion": "stateport.public-snapshot-audit-input/v1",
  "git": {
    "expectedBranch": "public-main",
    "expectedHead": "0000000000000000000000000000000000000000"
  },
  "rightsInventory": {
    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "path": "rights-inventory.yaml"
  }
}
```

The rights path is normalized and resolved relative to the descriptor. The
inventory uses `stateport.rights-inventory/v1`. It must cover every candidate
file exactly; every included entry must be redistributable, explicitly
licensed and provenanced, approved for inclusion, and internally or
independently reviewed. The descriptor and inventory must stay outside the
candidate tree.

The audit rejects unsafe filesystem entries, Git identity or cleanliness
mismatches, remotes and unexpected refs, high-risk credential structures,
secret-like literal assignments and paths, local-user paths, known private canary markers,
internal-only StatePort artifacts, unreadable binary/non-UTF-8 content, and
incomplete or unsafe rights inputs. Current content scanning is deliberately
text-only and bounded; binary assets and oversized candidates block instead
of being treated as safe. A later reviewed media-specific scanner may narrow
that limitation.

Output is deterministic JSON on stdout. Findings contain stable codes and
counts, never matched content or candidate paths. Exit status is `0` only for
a passed audit and `2` for a blocked candidate.
