# Local operator identity

`setup init` creates a stable local operator identity in a mode-restricted
configuration file. It is not stored in the catalog or browser storage. The
dashboard receives a short local session cookie, and the approvals view
returns `No approval requests` when authenticated and empty. Missing or unsafe
identity metadata fails closed.
