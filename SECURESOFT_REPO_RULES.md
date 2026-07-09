# SecureSoft Repo Rules

This repository is a SecureSoft TrustTunnel fork. Treat it as production-sensitive infrastructure code.

## Workflow

1. Check `git status --short --branch` before edits and before commits.
2. Preserve upstream/fork history.
3. Keep LK and SecureSoft client compatibility first.
4. Build and test locally before pushing.

## Safety

- Do not remove credential fields or node bootstrap fields without a migration plan.
- Do not deploy mutable `latest` images to production.
- Keep rollback artifacts available while old nodes are still serving users.
