# Persistent StudyState local alpha

Use a fresh clone or isolated worktree; inspect `git worktree list` before
testing. This Linux-first, local-single-user alpha needs Python 3.10 or newer;
it needs no provider, cloud resource, root access, or Compose. Read the
[`LOCAL_ALPHA_LIMITATIONS.md`](LOCAL_ALPHA_LIMITATIONS.md) boundary before
using it.

When the pinned candidate commit is not advertised by its credential-free
remote, prepare an owner-private carrier from a trusted local mirror. The
command copies only the exact Git object graph into `source.bundle`, writes a
digest-bound `receipt.json`, and verifies the recovered tree, manifest, and
StatePort source digest. Keep the resulting directory private; it is an input
to local source resolution, never a public release artifact.

```bash
install -d -m 700 "$HOME/.local/share/stateport-private"
python3 scripts/source_recovery_bundle.py prepare \
  --repository /absolute/path/to/trusted/StudyState-mirror \
  --profile "$PWD/sources/profiles/studydd-local-alpha.yaml" \
  --output-root "$HOME/.local/share/stateport-private/studydd-candidate"
python3 scripts/source_recovery_bundle.py verify \
  --profile "$PWD/sources/profiles/studydd-local-alpha.yaml" \
  --bundle-root "$HOME/.local/share/stateport-private/studydd-candidate"
```

```bash
./stateport setup \
  --source-mirror "$HOME/.local/share/stateport-private/studydd-candidate/source.bundle" \
  init
./stateport instance create \
  --source-profile builtin:studydd-local-alpha \
  --allow-development-candidate \
  --destination "$HOME/StatePort/StudyState-AI103" \
  --instance-id studydd-ai103 --name "AI-103 Study" \
  --owner-name "Local Owner" --target-id ai-103
./stateport service start --open
./stateport instance synthetic-run studydd-ai103
./stateport instance backup studydd-ai103
./stateport service stop
./stateport service start --open
```

The instance repository is canonical. Catalog, source cache, runtime files,
dashboard summaries, and run history are disposable management metadata.
The development-candidate flag is explicit consent bound to the exact plan,
approval, immutable source, and created directory identity. Execution and
proposal apply recheck the same receipt. Replacing a forgotten instance path
does not transfer consent; a governed restore discloses any exact receipt
transfer in its plan and terminal receipt. None of this makes the source
production-installable.
Private-state migration from an existing local StudyState instance is planned and
applied separately through the typed `instance import-state-*` commands.

For a public-safe retained demo, use `./stateport demo studydd-local-alpha
--workspace "$HOME/StatePortDemo" --keep`; it refuses an existing workspace
and uses the same governed creation path.

Known limits: synthetic execution is not tutor quality, a narrow opt-in local
Codex provider path exists while other live providers and host adapters are
deferred, browser mutation is limited, encryption and hosted multi-user
operation are not claimed, and remote CI/human acceptance are separate states.
