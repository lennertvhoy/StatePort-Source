# tool-gateway

> Mediates access to external tools for StatePort runners.

## Purpose

The tool gateway controls which tools a runner may invoke and under what conditions:

- Web search
- File operations
- GitHub
- Calendar/mail (future)
- Model providers
- Code execution
- External message sending

Every tool call records:

- tool name
- risk level
- quota impact
- approval requirement
- audit event

## Status

This package currently contains only a skeleton. Implementation starts in MVP 3.
