# Sensitive Data Gateway

This package implements the public-safe, headless foundation of
`BL-SENSITIVE-DATA-GATEWAY-001`.

It provides typed findings and receipts, deterministic local detection,
stable redaction aliases, a fail-closed final provider boundary, an output
boundary, and a mock secret store/broker for fictional tests. Matched values
and redaction maps are deliberately absent from returned contracts and
receipts.

The mock store is not a production credential store. OS keyring integration,
the browser journey, real providers/connectors, and human acceptance remain
outside this slice.
