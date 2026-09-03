# Lock-proven contribution bundles

This isolated package validates `stateport.contribution-bundle/v2` bundles.
It requires an exact instance lock, locked source and baseline identities,
explicit selected paths, positive template ownership and provenance, digests,
and a read-only clean synthetic reproduction. Instance-owned, generated,
unknown, private, and secret-like content fails closed. The validator has no
upstream or instance application operation.
