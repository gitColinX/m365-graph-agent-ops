# Docs

| Document | What it covers |
|---|---|
| [`adr-0001-agent-admin-access.md`](adr-0001-agent-admin-access.md) | Microsoft MCP Server for Enterprise vs Lokka vs certificate app-only for agent admin access, the consent matrix, and what I decided |
| [`scopes-and-roles.md`](scopes-and-roles.md) | Why per-task `-Scopes` on a shared client is not least privilege, the profile matrix, token lifetime, roles |
| [`lessons.md`](lessons.md) | Errors I hit, their cause and the fix, plus one gap the rewrite closes |
| [`../auth/README.md`](../auth/README.md) | Why device code, why detached, why no refresh token, and "why not `-ClientTimeout`?" |

## Case studies

| Case | Date | One line |
|---|---|---|
| [`intune-cleanup-rule-forensics.md`](case-studies/intune-cleanup-rule-forensics.md) | 2026-09-18 | Two laptops gone from Intune; a year of audit events with no matching admin removal shows, by elimination, that the inactivity cleanup rule removed them |
| [`detection-rule-false-failures.md`](case-studies/detection-rule-false-failures.md) | 2026-09-11 | 667 of 707 failed installs were an auto-updating agent outrunning its product-code detection rule; fixed through Graph, then un-fixed by a portal save, then fixed again |
| [`approle-delete-blast-radius.md`](case-studies/approle-delete-blast-radius.md) | 2026-09-25 | My delete removed a group's app grant instead of one user's; caught by the next step and restored in about two minutes |
| [`b2b-external-sharing-diagnosis.md`](case-studies/b2b-external-sharing-diagnosis.md) | 2026-09-21 | Sign-in logs and the cross-tenant policy prove a B2B failure is the partner's sharing setting |
