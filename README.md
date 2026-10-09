# Microsoft 365 admin from Claude Code, with me holding the sign-in

How I ran Microsoft Graph, Entra ID, Intune and Exchange Online administration
from Claude Code at my employer, a hybrid Microsoft 365 tenant of about 1,100
devices, in 2026. The agent never saw a password or an MFA prompt. Its
sign-ins were delegated device code sign-ins that I completed in my own
browser, under my own MFA and Conditional Access, and the rule for every
write was the same: read it back.

This repo is a fresh rewrite, generalized from what I ran at work: the
narrative, the sign-in code, the tools, the guardrails, the outcomes, and
four case studies, including the one where my own write went wider than I
meant it to. The code is new and generic, tested offline against synthetic
fixtures. Employer, people, ticket numbers and tenant identifiers are
removed. The case studies are what happened, with identifying details
generalized.

```
              me, in my own browser: sign-in, MFA, Conditional Access
                                   ^
                                   | user code, relayed by the agent within seconds
                                   |
Claude Code --> auth/Start-DeviceLogin.ps1 --(detached child)--> login.microsoftonline.com
                                   |                               RFC 8628 device authorization grant
                                   v
                 access token only, DPAPI-encrypted, 50 minutes, no refresh token
                                   |
       tools/*.ps1, recipes/*.ps1, tools/Start-QueueWorker.ps1 (one sign-in, many steps)
                                   |
         Graph REST (read-only unless -Apply)  |  Connect-MgGraph -AccessToken  |  Connect-ExchangeOnline -AccessToken
```

| | |
|---|---|
| **Sign-in** | [`auth/`](auth/) and the reasoning in [`auth/README.md`](auth/README.md) |
| **Tools** | [`tools/`](tools/): read-only Graph runner, Intune forensics, Remediations export, Win32 app PATCH, agent app registration, queue worker, safe app role delete |
| **Recipes** | [`recipes/`](recipes/README.md): onboarding gates, B2B invite, Autopilot export, dynamic device group, sharing audit |
| **Decisions** | [`docs/adr-0001-agent-admin-access.md`](docs/adr-0001-agent-admin-access.md), [`docs/scopes-and-roles.md`](docs/scopes-and-roles.md), [`docs/lessons.md`](docs/lessons.md) |
| **Case studies** | [`docs/case-studies/`](docs/case-studies/) |
| **Tests** | `pwsh -NoProfile -File tests/Run-Tests.ps1`: 65 offline tests. Unit tests, plus the Graph REST tools run end to end against a fake Graph. No tenant; network calls are blocked in the modules. What the tests do not cover is listed under [What is in the repo](#what-is-in-the-repo). |
| **Requirements** | PowerShell 7.2 or later on Windows. Windows PowerShell 5.1 will not run these scripts: they use `-SkipHttpErrorCheck`, `ConvertFrom-Json -Depth`, `$IsWindows` and three-argument `Join-Path`, and the token cache uses Windows DPAPI. Microsoft.Graph.Authentication 2.x, where `Connect-MgGraph -AccessToken` takes a SecureString. An ExchangeOnlineManagement 3.x release that has `Connect-ExchangeOnline -AccessToken`. PnP.PowerShell, if you use it, in its own session: its identity libraries can conflict with the Graph SDK's in one process. |
| **Stack** | PowerShell 7, Microsoft Graph REST v1.0 and beta, Microsoft Graph PowerShell SDK, ExchangeOnlineManagement V3, Claude Code on Windows 11 |

## The problem

The admin work was spread across Entra ID, Intune, Exchange Online and
SharePoint, and the evidence for a ticket usually lived in two or three of
them. I was already using Claude Code to write PowerShell. The question was
whether it could run the Graph and Exchange work itself: under my own
identity, with every call attributable to me, without ever holding a
password, and without a model writing to production unchecked.

The first attempts did not work. Inside Claude Code, PowerShell runs as a
non-interactive child process. The Windows sign-in broker (WAM) had no parent
window to draw its prompt in, and the SDK's interactive browser sign-in
failed the same way. There was a browser right there on the desktop; the
process context was the problem. One September ticket needed three sign-ins
before I could check one user's groups, their Intune device and their app
assignments. That was the night I decided to fix sign-in properly.

## How it works

### Sign-in

1. The agent runs `auth/Start-DeviceLogin.ps1 -TenantId <tenant> -AuthProfile <profile>`.
2. That script starts a **detached** PowerShell process which calls the
   Entra ID device authorization endpoint directly and writes the user code
   to a file. The launcher sees the file and returns within seconds with
   `USER_CODE=... URL=https://microsoft.com/devicelogin`. Run detached, my
   first launcher (the SDK's device code sign-in) got the code to me in
   about 3 seconds; the raw-flow child here makes a single POST before it
   writes the code.
3. The agent shows me the code. I open the URL in my own browser and sign
   in with my admin account: password, MFA, Conditional Access, all in a
   place the agent cannot see.
4. The detached process keeps polling the token endpoint for the full
   15-minute life of the code, honoring `authorization_pending` and
   `slow_down`, then caches **only the access token**, DPAPI-encrypted for my
   Windows user, for 50 minutes. It never asks for `offline_access`, so no
   refresh token is issued.
5. Every tool after that, in any process, picks the cached token up and
   either calls Graph REST directly or hands it to `Connect-MgGraph
   -AccessToken` and `Connect-ExchangeOnline -AccessToken`.

The client ids are Microsoft's own public clients (Microsoft Graph Command
Line Tools and Exchange Online PowerShell). The full reasoning, including
"why not just use `-ClientTimeout`?", is in [`auth/README.md`](auth/README.md).

### Guardrails, and where each one came from

Most of these exist because of a specific moment where I saw the default
would eventually hurt someone.

1. **The human holds the sign-in.** The agent relays a code. It never sees
   a password, never satisfies MFA, never holds a refresh token. It does get
   a short-lived access token, and anything running as me can read the
   DPAPI cache, so the real controls are the token's lifetime and what the
   token can do.
2. **Name the tenant on every call.** No default tenant, and `common` is
   refused. A hard-coded tenant id once sent one of my queries to the wrong
   tenant: the app I was investigating lived in a different tenant than the
   one in the script.
3. **Writes are off by default, in code.** The REST module refuses POST,
   PATCH, PUT and DELETE until a tool passes `-Apply`, so every write needs
   a visible `-Apply` in a command I approve before it runs. That stops
   accidental writes. It is not a security boundary: anything running as me
   can switch it. The actual controls are my approval of production writes
   before they run (guardrail 11), plus the token's scopes and my roles.
4. **Never send the token anywhere but graph.microsoft.com.** An absolute
   URI or `@odata.nextLink` on any other host is refused. Tenant data can
   carry text aimed at the model; it does not get to redirect a bearer token.
5. **Resolve to exactly one.** Names are matched to objects first. Zero or
   two matches stop the run and print the candidate ids.
6. **Dry run, then apply.** Every write tool prints its plan and stops.
   `-Apply` is a separate, deliberate run.
7. **One field per PATCH, and read each one back.** When Graph rejected one
   field for me, the other six still landed and were verified.
8. **Check for collateral.** After a write, compare what was not supposed to
   change. My original runs checked the app's assignments afterwards; the
   rewrite compares every watched field as well. The habit came from an
   Intune portal Save that silently undid a Graph change.
9. **Never delete a grant you do not own.** `GET /users/{id}/appRoleAssignments`
   also returns grants made to the user's groups. Deleting one of those
   removes the app for the whole group. The helper refuses unless
   `principalType` is `User`. I learned this one the hard way.
10. **Page everything.** A single page of `$top=999` is not "all members".
    One of my own verification checks was wrong for exactly that reason.
11. **I approve production writes before they run.** In later sessions,
    routine reads often ran under Claude Code's auto mode, whose classifier
    approves them; the contract still required my approval for production
    writes. The queue worker follows the same rule. It runs whatever lands
    in the queue, as me, so a step that writes is approved when the agent
    writes its file, before the step exists. Keep writes into the queue
    folder out of any auto-approval.

### What is in the repo

Status labels describe the original tooling at work. Every file here is a
fresh rewrite, generalized from what I ran at work, with generic names,
tested offline against synthetic fixtures; none of it has been run against a
live tenant in this form. The last column says what the rewrite added on
top of what I actually ran, so the labels do not stretch to cover it.

Not covered by the tests, so not proven in this form: `New-AgentReadOnlyApp.ps1
-Apply`; the success path of the detached launcher (tested only with network
calls blocked); `Connect-AgentGraph` and `Connect-AgentExchange`, which do the
token hand-off; the two SDK recipes (B2B invite, dynamic group); and the
Exchange audit search. Those are checked for syntax only.

| Piece | What it does | The original at work | Added in this rewrite (tested offline only) |
|---|---|---|---|
| [`auth/Start-DeviceLogin.ps1`](auth/Start-DeviceLogin.ps1), [`auth/DeviceCodeAuth.psm1`](auth/DeviceCodeAuth.psm1) | Detached launcher, RFC 8628 grant, DPAPI access-token cache, token hand-off to the SDK and Exchange | [built, ran on real tickets]: detached sign-in, raw grant polled until sign-in, DPAPI access-token cache with file-age expiry, `-AccessToken` hand-off | `slow_down` adds 5 s (the original treated it like pending); `offline_access` refused (the original requested it); tenant required (the original hard-coded it); one cache per profile; the token's not-after time returned to callers |
| [`auth/Test-WamSignIn.ps1`](auth/Test-WamSignIn.ps1) | Reports why WAM and interactive sign-in fail in the agent's process | [built, ran on real tickets]: a 15-line probe I ran while diagnosing sign-in | This wider diagnostic as a whole; run once in an agent session while writing this repo |
| [`tools/Invoke-GraphRead.ps1`](tools/Invoke-GraphRead.ps1) | Read-only Graph runner: paging, one JSON per query | [built, ran on real tickets]: GET with `@odata.nextLink` paging, one file per query | 429 and `Retry-After` handling (the original had none); the off-Graph host guard; a tested result marker |
| [`tools/Export-RemediationRunStates.ps1`](tools/Export-RemediationRunStates.ps1) | Every Intune Remediations package with run data to its own CSV, script output included | [built, ran on real tickets], run in my own console | `index.json`; safe file names |
| [`tools/Get-IntuneDeviceHistory.ps1`](tools/Get-IntuneDeviceHistory.ps1) | Where did this device go? Concludes by elimination | [built, ran on real tickets] | The Undetermined answers: audit window too short, device not yet eligible, or an evidence query that failed, returned 403 or hit its page cap |
| [`tools/Set-IntuneWin32AppField.ps1`](tools/Set-IntuneWin32AppField.ps1) | Resolve, dry run, one field per PATCH, read-back, collateral check | [built, ran on real tickets]: resolve, one field per PATCH with read-back, assignments checked afterwards | Read-back compared field by field so server defaults do not count as a mismatch; collateral compare across every watched field; a second switch for command-line fields |
| [`tools/Start-QueueWorker.ps1`](tools/Start-QueueWorker.ps1) | One Graph and one Exchange sign-in serving a queue of approved steps | [built, ran on real tickets] | Session limit tied to the tokens' not-after time; idle limit; step hashes; step output written as it is printed |
| [`tools/New-AgentReadOnlyApp.ps1`](tools/New-AgentReadOnlyApp.ps1) | Read-only (not least-privilege) app registration for the agent: certificate, no secret, no self-consent | [designed, runbook written]: the original created the app and its service principal; I wrote the consent request; the plan routed consent to the Global Admin | A smaller app-only set; content-reading app-only permissions refused; TPM-backed key; 3-month certificate; assignment required; public client flows off; certificate removed if the app POST fails. `-Apply` has never run in this form |
| [`tools/Remove-UserAppRoleAssignment.ps1`](tools/Remove-UserAppRoleAssignment.ps1) | Deletes a direct user grant; refuses group grants; pages membership | [in progress]: written after the incident | All of it |
| [`recipes/`](recipes/README.md) | Onboarding gates, B2B invite, Autopilot export, dynamic device group, sharing audit | per recipe, see its README | URL-encoded filter values |
| [`docs/adr-0001-agent-admin-access.md`](docs/adr-0001-agent-admin-access.md) | Microsoft MCP Server for Enterprise vs Lokka vs certificate app-only | [designed, runbook written] | Revised October 2026; the corrections are marked in it |

## What broke, and what I learned

- **WAM had nowhere to draw.** Silent reuse of the SDK's token cache failed
  from the agent with "window handle must be configured". The interactive
  browser credential failed too. Device code is the flow that needs no
  window in the process that asks for it.
- **The code was invisible until it no longer mattered.** Run in the
  foreground, `Connect-MgGraph -UseDeviceCode` prints the code, but the
  agent only sees output when the command returns, which is after sign-in or
  after timeout. Running it detached with output going to a file put the
  code in front of me in about 3 seconds.
- **The SDK gave up before I did.** The SDK's default client timeout is
  about 120 seconds, much shorter than the 15-minute life of the code. Two
  of four sign-in attempts one afternoon hit that timeout before I had
  entered the code. I moved to calling the device authorization endpoints
  directly and handing the token to the SDK. I later learned
  `Connect-MgGraph` has `-ClientTimeout`. The hand-written flow was still
  worth keeping: the code shows up in a file within seconds, the token is
  reused across separate processes, and one sign-in serves a whole queue.
- **I kept refresh tokens I never used.** My first launcher used the SDK's
  persistent token cache, which keeps a refresh token on disk. The raw-flow
  scripts that replaced it asked for `offline_access` and then threw the
  refresh token away. I needed neither. This version keeps neither: it
  refuses `offline_access` outright and caches only the access token.
- **Status written to the pipeline corrupts a return value.** In
  PowerShell, a logging line inside a function that returns a token becomes
  part of the return value, and the token becomes an array. The original
  worker carries a comment warning about exactly this. Status now goes to
  the host or a file, never the pipeline.
- **My result file lied.** An early runner wrote its success marker with a
  variable that did not exist in that scope, so every run ended with a
  failure message while the query files were fine. The reporting path is
  code too; it gets tested now.
- **The portal overwrote Graph.** I changed a Win32 app's detection rule
  through Graph. Three minutes later I uploaded a logo in an Intune blade I
  had opened before the change. The portal re-sent every field it had
  loaded and silently put the old rule back. I re-applied it one field at a
  time with read-back.
- **Graph rejected one field and accepted the rest.** A long notes value
  came back BadRequest. Because each field was its own PATCH, nothing else
  was lost; the notes went in through the portal.
- **The default MFA method cannot go first.** Deleting the Authenticator
  method failed while it was the default; it succeeded after the phone
  method was removed.
- **Not every endpoint takes a UPN as the key.** Some calls answered
  "Get By Key only supports UserId". Resolve the object id first, always.
- **403 is an answer.** The older Intune cleanup settings endpoint returned
  403 for my role while the cleanup rules endpoint worked. Delegated
  `Sites.Read.All` returned 403 on another user's OneDrive. The tools record
  403 as "not visible to this account" and keep going, and a conclusion
  that depended on that query comes out as Undetermined.
- **5,000 rows is a wall, not a result.** A per-user audit log pull came back
  with exactly 5,000 rows. `ReturnLargeSet` only helps if every call reuses
  one `SessionId` and you keep calling.

## What it produced

"Run from" says who typed the commands: the agent in Claude Code (with me
completing the sign-in and approving production writes before they ran), or
me in my own console.

| Job | Date | Run from | Result |
|---|---|---|---|
| **Intune device forensics** | 2026-09-18 | Agent | Showed by elimination that two laptops' Intune records were removed by the 90-day inactivity cleanup rule, not by an admin: no matching delete in a year of Intune audit events (about 5,600 checked), Entra and Autopilot objects still present. The lesson: issue wipe or retire on the last day instead of waiting for the hardware. [Case study](docs/case-studies/intune-cleanup-rule-forensics.md). |
| **Win32 detection false failures** | 2026-09-11 | Agent | A remote-support agent showed 707 of 764 devices Failed. 667 of those were false: the agent had auto-updated past the MSI product code the detection rule looked for. Proved it with discovered-apps data through Graph, switched detection to a file rule through Graph, and handed over a 40-device list of real failures. [Case study](docs/case-studies/detection-rule-false-failures.md). |
| **Bulk app metadata** | 2026-09-25 | Agent | Set the owner on 13 Intune apps resolved from a 118-app snapshot: 13 of 13 verified by read-back, assignments unchanged on all 13. |
| **Remediations export** | 2026-08-24 | My console | Every Remediations package with run data exported to its own CSV with per-device script output: 16 files in about 10 seconds, instead of one admin center screen at a time. |
| **B2B access diagnosis** | 2026-09-21 | Agent | A senior leader could not open a partner company's SharePoint file. Sign-in logs showed five successful sign-ins to the partner tenant; our cross-tenant settings allowed the collaboration, and our Conditional Access was not the blocker. The block was the partner's external sharing setting. [Case study](docs/case-studies/b2b-external-sharing-diagnosis.md). |
| **Offboarding gap closure** | 2026-09-25 | Agent, through the queue worker | Nine queued steps on one Graph and one Exchange sign-in: discovery, a mailbox recheck, MFA method teardown, a device object delete, session revocation, and final verification. One step removed a group's app grant by mistake; I caught it and restored it about two minutes later. [Case study](docs/case-studies/approle-delete-blast-radius.md). |
| **Exchange at scale** | 2026-09-15 | Agent | A read-only FullAccess sweep across 1,278 mailboxes for an offboarding audit, on device code sign-ins. |
| **Volume** | May to Sep 2026 | My console | My interactive admin console history shows 319 `Connect-MgGraph` commands, 197 raw `Invoke-MgGraphRequest` calls and 182 `Connect-ExchangeOnline` commands (commands entered; output was not kept). The agent's own shell does not write to that history. |

## Lessons that transfer

1. **Let the human hold the sign-in.** Device code lets an agent work under
   a person's real identity, MFA and Conditional Access, and the audit log
   shows the person. Offboarding the person offboards the agent.
2. **Short tokens beat clever caches.** An access token that dies in under
   an hour, and no refresh token, limits what a mistake or a compromised
   process can do later.
3. **Least privilege is the token, not the request.** With a shared
   first-party client, asking for fewer scopes does not shrink what the
   token carries. The real ceilings are your directory roles, or a dedicated
   app registration. See [`docs/scopes-and-roles.md`](docs/scopes-and-roles.md).
4. **Separate read from write in code.** Read-only by default at the
   transport, writes only behind a switch, one field at a time. That stops
   accidents; approving production writes before they run is the control.
5. **A write is a claim until you read it back.** And reading back the
   field you changed is not enough; check what you did not mean to change.
6. **Know what an object really is before you delete it.** A row in the
   user's list is not necessarily the user's.
7. **Page, always.** Every collection endpoint, every time.
8. **Write the quirks down the day you hit them.** Each one in
   [`docs/lessons.md`](docs/lessons.md) looked like a dead end once.

## How this was built

I built the original tooling at work with Claude Code as my primary tool
and verified the results in the tenant. I approved production writes before
they ran. In later sessions, routine reads often ran under Claude Code's
auto mode, whose classifier approves them; the contract still required my
approval for production writes. When my Claude Code usage ran out, I
pointed Codex, signed in to the company's ChatGPT workspace, at the same
folders and the same agent-neutral `AGENTS.md`; the controls live in the
scripts, so they hold no matter which agent is driving. The timeline: Codex
from mid-August (the desktop app, for OCR) and the Codex CLI from 2026-08-21.

This is a fresh rewrite, generalized from what I ran at work, written with
Claude Code. I directed the work and checked the results against my own
records. The code here is tested offline against synthetic fixtures (65
tests passing on 2026-10-09) and has not been run against a live tenant in
this form. Colleagues show up by role where they contributed: the colleague
who first suggested why the remote-support agent's installs were failing,
and the Global Admin, to whom my plan routed consent for the agent's app.

## About

Colin Lundholm, IT Support Engineer, working across systems administration,
endpoint, identity and cloud · [GitHub profile](https://github.com/gitColinX)
· [LinkedIn](https://www.linkedin.com/in/cdlundholm)

Corrections welcome by issue or pull request. MIT licensed.
