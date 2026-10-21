# 0001: How do we back up the production database?

Status: decided on 2026-03-17. Review on 2026-09-17.

## Context

The product stores its customer data in one PostgreSQL database of about 8 GB on a single virtual machine. Today the only
copy is the provider's disk snapshot of that same machine, which has never been restored and is lost with the account.
The team of five has no dedicated operations person, so whatever we choose must be easy to run and easy to explain.
The business accepts losing up to one day of data after a disaster, and wants service back within a working day.

## Options considered

1. **Provider disk snapshots only (status quo).** No work and no extra cost. The snapshots live in the same account as
   the machine, restoring one means replacing the whole machine, and nobody has tried it.
2. **Nightly logical dump, encrypted and copied to a second provider.** A scheduled `pg_dump` is encrypted and uploaded
   to object storage at another provider. Easy to understand and to restore on any machine. The recovery point is up to
   24 hours. Storage cost is a few euros a month at the current size.
3. **Continuous archiving with point-in-time recovery.** Write-ahead logs are shipped continuously, so recovery can be to
   within seconds. It needs a backup tool, monitoring of the archive and more operating knowledge than the team has.

## Decision

Option 2: a nightly encrypted dump kept at a second provider, with a restore test every quarter.

## Rationale

It removes the single point of failure (one account) at little cost, and the team can run it without learning a new
tool. A 24-hour recovery point matches what the business accepted. Option 3 is better on paper but is more machinery than
the risk justifies today, and an untested restore is not a backup at all, so the quarterly restore test matters as
much as the dump.

## Consequences

- After a disaster up to one day of data can be lost; this is accepted for now.
- Someone owns a quarterly calendar item to restore the latest dump onto a scratch machine and run the smoke tests.
- The encryption key is stored separately from the backups; losing it makes every backup unreadable.
- Revisit when the database passes 100 GB, when customers need a tighter recovery point, or at the review date.
