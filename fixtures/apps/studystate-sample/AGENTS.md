# StudyState Sample agent contract

This is a fictional public-safe StudyState application fixture. Treat
`state/LEARNING.yaml` as durable application state. Read actions from
`actions.yaml`, propose mutations before applying them, and never infer or add
credentials, private learner data, or external permissions.

The package requests no network access. A host must declare any capability
degradation and StatePort remains the authority for validation, approval, and
receipts.
