# NIS2 / CyberFundamentals Alignment

> NIS2-aware design notes and CyberFundamentals-aligned control mapping.

**This is not a certification claim.** StatePort is designed to be NIS2-aware and CyberFundamentals-aligned. Actual compliance must be verified by the customer through appropriate risk management, legal review, and audit.

## NIS2 context

Belgium transposed the EU NIS2 Directive into national law, which entered into force on 18 October 2024. The Centre for Cybersecurity Belgium (CCB) is the national cybersecurity authority. The implementing Royal Decree provides sectoral and organisational obligations.

StatePort does not determine whether a customer is an essential or important entity under NIS2. The customer must make that assessment.

## CyberFundamentals framework

The Belgian CyberFundamentals framework is a step-by-step approach described by CCB to protect data, reduce common cyberattack risk, and improve cyber resilience. It maps to NIST CSF, ISO 27001/27002, IEC 62443, and CIS Controls.

StatePort's design aligns with CyberFundamentals themes where applicable.

## Control mapping

| CyberFundamentals theme | StatePort design control |
|-------------------------|--------------------------|
| Risk management | Template risk levels; instance-scoped actions; quota controls |
| Access control | Per-instance permissions; L5 admin actions; managed identity on Azure |
| Incident handling | Structured audit logs; incident response stub in [`SECURITY.md`](SECURITY.md) |
| Backup and recovery | File-based instances; git-backed state; Azure Storage versioning |
| Logging and monitoring | Audit events; Azure Monitor/Log Analytics placeholders |
| Vulnerability management | Dependency pinning; minimal container images; update runbooks |
| Supplier/subprocessor management | Subprocessor list placeholder; DPA checklist in [`GDPR.md`](GDPR.md) |
| Network security | Private networking placeholders; Azure Container Apps network controls |
| Data protection | Encryption at rest/transit planned (not claimed in the local alpha); EU region preference; data minimisation |
| Identity management | Managed identity; Entra ID placeholder for admin dashboard |

## NIS2-aware design notes

- **Supply chain:** templates and dependencies are versioned and validated.
- **Incident reporting:** audit logs provide the evidence base for customer incident reporting.
- **Business continuity:** state is portable and recoverable from files.
- **Encryption:** prefer encryption in transit and at rest; use Key Vault for secrets.
- **Least privilege:** runner and adapter permissions are scoped to need.

## What we do not claim

- Not NIS2 compliant.
- Not CyberFundamentals certified.
- Not a substitute for customer risk management.
- Not a legal opinion.

## Customer obligations

Customers using StatePort for NIS2-relevant activities remain responsible for:

- Their own risk assessment
- Applying appropriate technical and organisational measures
- Incident reporting to competent authorities where required
- Maintaining records and evidence
- Reviewing and signing appropriate DPAs and subprocessor lists
