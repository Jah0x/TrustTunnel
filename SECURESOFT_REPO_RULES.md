# SecureSoft Repo Rules

This repository is a SecureSoft TrustTunnel fork. Treat it as production-sensitive infrastructure code.

## AI Office Control

All non-trivial writes are routed through
`Securesoftdev/securesoft-ai-office`. Before implementation,
`engineering_director` must produce a task packet naming one runtime module,
allowed and forbidden paths, compatibility targets, acceptance criteria,
required checks, reviewers and rollout impact.

- Use one writable agent in one isolated branch/worktree.
- Reviewers remain independent and read-only.
- Open a draft PR with test, security, LK/client compatibility, rollout and
  rollback evidence.
- Normal implementation agents do not merge, publish images or deploy.
- Runtime, credential, networking and production changes require the protected
  release workflow and the authority defined by AI Office.
- These local protocol and release rules remain authoritative and may be
  stricter than the shared office contract.

## Workflow

1. Check `git status --short --branch` before edits and before commits.
2. Preserve upstream/fork history.
3. Keep LK and SecureSoft client compatibility first.
4. Build and test locally before pushing.
5. Record docs and compatibility impact before handoff.
6. Scan the exact diff for credentials, keys and production config values.

## Safety

- Do not remove credential fields or node bootstrap fields without a migration plan.
- Do not deploy mutable `latest` images to production.
- Keep rollback artifacts available while old nodes are still serving users.

## Current customer baseline

- TrustTunnel is the active customer protocol.
- LK allocates two routes per active subscription.
- Windows/Android consume both through bootstrap.
- iOS consumes the same routes through an LK-generated Clash Mi subscription.
- Happ/Xray is legacy and must not become a new allocation dependency.
