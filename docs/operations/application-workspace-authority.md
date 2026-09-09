# Application workspace authority

Application workspace requests are prepared in the application UI and approved
by an OS operator through the installed `stateport-execution-host-provision`
helper. Preparing or downloading a request creates no grant. The execution daemon
continues to enforce its private grant store for every operation.

## Installed policy and source review

The installed, signed topology selects the policy. Existing installations keep
their empty-workspace policies. The additive
`stateport.reviewed-source-workspace-terminal/v1` policy requires an explicit
signed selection and a new v3 issuer context/publication. Changing an environment
variable in a browser or reusing an older context does not activate this policy.
The repository's default release topology does not select it.

This policy uses the same fixed isolated workload template, terminal operations,
and resource budgets as the existing terminal policy. A v2 authority request
adds an exact source review:

- the installed application's catalog identity and local Git commit;
- the complete tracked regular-file inventory, executable bits and SHA-256 hashes;
- the deterministic source archive digest, byte count and context digest;
- the descriptor digest and a bounded raw Git commit witness.

The review covers committed files only, including managed metadata when it is
tracked in the local commit. Ignored and other untracked files are not copied. Dirty tracked source, symlinks, submodules, hardlinks,
unsafe permissions and paths, or unsupported size bounds refuse preparation or
issuance. The local managed-copy commit can differ from the upstream import
commit; this review does not assert a new upstream signature verification.

The request digest binds all these facts, the installed profile and context,
application identity, and expiry. Review the downloaded request before supplying
that exact digest to the installed helper:

```sh
sudo /usr/local/libexec/stateport-execution-host-provision issue-workspace \
  --request-digest sha256:THE_REVIEWED_REQUEST_DIGEST < workspace-request.json
```

Use the actual digest shown in the prepared request. The helper authenticates
the invoking operator and independently locates the installed catalog and source.
It never accepts an arbitrary source path from the request. It checks the source
through directory-relative, no-follow file descriptors, reconstructs the Git tree
from actual file bytes, checks the commit witness and deterministic archive, and
repeats the checks during publication. It runs no Git commands or repository code
as root. Source changes before activation leave new authority paused.

## Result and limits

The resulting grant binds one exact workload specification and source revision.
The public binding and issuance receipt are evidence of issuance; the daemon's
current private grant remains authoritative. An existing application's binding
cannot be renewed or replaced through this fresh-authority procedure.

Source preparation, issuance, container creation, and terminal connection are
separate actions. Creation revalidates the approved source before transferring it
to the isolated workspace volume. Container removal preserves that volume; an
explicit recovery reattaches it. The application source is not the writable
container volume.

This contract is source implementation work. Its focused and integration proof
is recorded in `evidence/one-line-release-001/summary.md`. It does not establish
publication, clean installation, native WSL2 qualification, or human acceptance.
