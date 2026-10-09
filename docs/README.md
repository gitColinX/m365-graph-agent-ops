# Docs

| Document | What it covers |
|---|---|
| [`WRITEUP.md`](WRITEUP.md) | The full write-up: the sign-in problem, the guardrails, problems I hit and all the results |
| [`adr-0001-agent-admin-access.md`](adr-0001-agent-admin-access.md) | Microsoft MCP Server for Enterprise vs Lokka vs certificate app-only for agent admin access, the consent matrix, and what I decided |
| [`scopes-and-roles.md`](scopes-and-roles.md) | Why per-task `-Scopes` on a shared client is not least privilege, the profile matrix, token lifetime, roles |
| [`lessons.md`](lessons.md) | Errors I hit, their cause and the fix, plus one gap the rewrite closes |
| [`../auth/README.md`](../auth/README.md) | How the device code sign-in works, why it keeps no refresh token, and why not `-ClientTimeout` |

## Case studies

| Case | Date | One line |
|---|---|---|
| [`intune-cleanup-rule-forensics.md`](case-studies/intune-cleanup-rule-forensics.md) | 2026-09-18 | Two laptops gone from Intune; a year of audit events with no matching admin removal shows, by elimination, that the inactivity cleanup rule removed them |
| [`detection-rule-false-failures.md`](case-studies/detection-rule-false-failures.md) | 2026-09-11 | 667 of 707 failed installs were an auto-updating agent outrunning its product-code detection rule; fixed through Graph, then un-fixed by a portal save, then fixed again |
| [`approle-delete-blast-radius.md`](case-studies/approle-delete-blast-radius.md) | 2026-09-25 | My delete removed a group's app grant instead of one user's; caught by the next step and restored in about two minutes |
| [`b2b-external-sharing-diagnosis.md`](case-studies/b2b-external-sharing-diagnosis.md) | 2026-09-21 | Sign-in logs and the cross-tenant policy prove a B2B failure is the partner's sharing setting |

## Status of each piece

Each row says what the piece does, how far the original got at work, and
what this rewrite added on top. Everything in the last column is tested
offline only.

| Piece | What it does | The original at work | Added in this rewrite (tested offline only) |
|---|---|---|---|
| [`auth/Start-DeviceLogin.ps1`](../auth/Start-DeviceLogin.ps1), [`auth/DeviceCodeAuth.psm1`](../auth/DeviceCodeAuth.psm1) | Detached launcher, RFC 8628 grant, DPAPI access-token cache, token hand-off to the SDK and Exchange | [built, ran on real tickets]: detached sign-in, raw grant polled until sign-in, DPAPI access-token cache with file-age expiry, `-AccessToken` hand-off | `slow_down` adds 5 s (the original treated it like pending); `offline_access` refused (the original requested it); tenant required (the original hard-coded it); one cache per profile; the token's not-after time returned to callers |
| [`auth/Test-WamSignIn.ps1`](../auth/Test-WamSignIn.ps1) | Reports why WAM and interactive sign-in fail in the agent's process | [built, ran on real tickets]: a 15-line probe I ran while diagnosing sign-in | This wider diagnostic as a whole; run once in an agent session while writing this repo |
| [`tools/Invoke-GraphRead.ps1`](../tools/Invoke-GraphRead.ps1) | Read-only Graph runner: paging, one JSON per query | [built, ran on real tickets]: GET with `@odata.nextLink` paging, one file per query | 429 and `Retry-After` handling (the original had none); the off-Graph host guard; a tested result marker |
| [`tools/Export-RemediationRunStates.ps1`](../tools/Export-RemediationRunStates.ps1) | Every Intune Remediations package with run data to its own CSV, script output included | [built, ran on real tickets], run in my own console | `index.json`; safe file names |
| [`tools/Get-IntuneDeviceHistory.ps1`](../tools/Get-IntuneDeviceHistory.ps1) | Where did this device go? Concludes by elimination | [built, ran on real tickets] | The Undetermined answers: audit window too short, device not yet eligible, or an evidence query that failed, returned 403 or hit its page cap |
| [`tools/Set-IntuneWin32AppField.ps1`](../tools/Set-IntuneWin32AppField.ps1) | Resolve, dry run, one field per PATCH, read-back, collateral check | [built, ran on real tickets]: resolve, one field per PATCH with read-back, assignments checked afterwards | Read-back compared field by field so server defaults do not count as a mismatch; collateral compare across every watched field; a second switch for command-line fields |
| [`tools/Start-QueueWorker.ps1`](../tools/Start-QueueWorker.ps1) | One Graph and one Exchange sign-in serving a queue of approved steps | [built, ran on real tickets] | Session limit tied to the tokens' not-after time; idle limit; step hashes; step output written as it is printed |
| [`tools/New-AgentReadOnlyApp.ps1`](../tools/New-AgentReadOnlyApp.ps1) | Read-only (not least-privilege) app registration for the agent: certificate, no secret, no self-consent | [designed, runbook written]: the original created the app and its service principal; I wrote the consent request; the plan routed consent to the Global Admin | A smaller app-only set; content-reading app-only permissions refused; TPM-backed key; 3-month certificate; assignment required; public client flows off; certificate removed if the app POST fails. `-Apply` has never run in this form |
| [`tools/Remove-UserAppRoleAssignment.ps1`](../tools/Remove-UserAppRoleAssignment.ps1) | Deletes a direct user grant; refuses group grants; pages membership | [in progress]: written after the incident | All of it |
| [`recipes/`](../recipes/README.md) | Onboarding gates, B2B invite, Autopilot export, dynamic device group, sharing audit | per recipe, see its README | URL-encoded filter values |
| [`adr-0001-agent-admin-access.md`](adr-0001-agent-admin-access.md) | Microsoft MCP Server for Enterprise vs Lokka vs certificate app-only | [designed, runbook written] | Revised October 2026; the corrections are marked in it |
