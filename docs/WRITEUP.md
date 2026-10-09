# Full write-up

This is the long version of the [README](../README.md).

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
assignments. After that I decided to fix sign-in properly.

## How it works

### Sign-in

1. The agent runs `auth/Start-DeviceLogin.ps1 -TenantId <tenant> -AuthProfile <profile>`.
2. That script starts a detached PowerShell process which calls the
   Entra ID device authorization endpoint directly and writes the user code
   to a file. The launcher sees the file and returns within seconds with
   `USER_CODE=... URL=https://microsoft.com/devicelogin`.
3. The agent shows me the code. I open the URL in my own browser and sign
   in with my admin account: password, MFA, Conditional Access, all in a
   place the agent cannot see.
4. The detached process keeps polling the token endpoint for the full
   15-minute life of the code, honoring `authorization_pending` and
   `slow_down`, then caches only the access token, DPAPI-encrypted for my
   Windows user, for 50 minutes. It never asks for `offline_access`, so no
   refresh token is issued.
5. Every tool after that, in any process, picks the cached token up and
   either calls Graph REST directly or hands it to `Connect-MgGraph
   -AccessToken` and `Connect-ExchangeOnline -AccessToken`.

The client ids are Microsoft's own public clients (Microsoft Graph Command
Line Tools and Exchange Online PowerShell). The full reasoning, including
"why not just use `-ClientTimeout`?", is in [`auth/README.md`](../auth/README.md).

### Guardrails

Most of these came from a mistake I made or nearly made.

1. I hold the sign-in. The agent relays a code. It never sees my password
   or my MFA prompt, and it never holds a refresh token. It does get a
   short-lived access token, and anything running as me can read the DPAPI
   cache, so the real controls are the token's lifetime and what the token
   can do.
2. Name the tenant on every call. No default tenant, and `common` is
   refused. A hard-coded tenant id once sent one of my queries to the wrong
   tenant: the app I was investigating lived in a different tenant than the
   one in the script.
3. Writes are off by default, in code. The REST module refuses POST, PATCH,
   PUT and DELETE until a tool passes `-Apply`, so every write needs a
   visible `-Apply` in a command I approve before it runs. That stops
   accidental writes. **It is not a security boundary:** anything running as
   me can switch it. The actual controls are my approval of production
   writes before they run (guardrail 11), plus the token's scopes and my
   roles.
4. Never send the token anywhere but graph.microsoft.com. An absolute URI
   or `@odata.nextLink` on any other host is refused. That stops text
   planted in tenant data from sending my token somewhere else.
5. Resolve to exactly one. Names are matched to objects first. Zero or two
   matches stop the run and print the candidate ids.
6. Dry run, then apply. Every write tool prints its plan and stops.
   `-Apply` is a separate, deliberate run.
7. One field per PATCH, and read each one back. When Graph rejected one
   field for me, the other six still landed and were verified.
8. Check for collateral. After a write, compare what was not supposed to
   change. My original runs checked the app's assignments afterwards; the
   rewrite compares every watched field as well. The habit came from an
   Intune portal Save that silently undid a Graph change.
9. Never delete a grant you do not own. `GET /users/{id}/appRoleAssignments`
   also returns grants made to the user's groups. Deleting one of those
   removes the app for the whole group. The helper refuses unless
   `principalType` is `User`.
10. Page everything. A single page of `$top=999` can stop short of all
    members. One of my own verification checks was wrong for that reason.
11. I approve production writes before they run. In later sessions,
    routine reads often ran under Claude Code's auto mode, whose classifier
    approves them; the contract still required my approval for production
    writes. The queue worker follows the same rule. It runs whatever lands
    in the queue, as me, so a step that writes is approved when the agent
    writes its file, before the step exists. Keep writes into the queue
    folder out of any auto-approval.

### What is in the repo

Most of the tools here ran on real tickets at work. Two did not: the
read-only app script got as far as creating the app and routing consent to
the Global Admin, and the app role delete helper was still in progress. The
full status table, with what the rewrite added to each piece, is in
[docs/README.md](README.md#status-of-each-piece).

Not covered by the tests, so not proven in this form: `New-AgentReadOnlyApp.ps1
-Apply`; the success path of the detached launcher (tested only with network
calls blocked); `Connect-AgentGraph` and `Connect-AgentExchange`, which do the
token hand-off; the two SDK recipes (B2B invite, dynamic group); and the
Exchange audit search. Those are checked for syntax only.

## Problems I hit

- WAM sign-in failed in the agent's process. Silent reuse of the SDK's
  token cache failed from the agent with "window handle must be configured".
  The interactive browser credential failed too. Device code is the flow
  that needs no window in the process that asks for it.
- The device code did not show until the command returned. Run in the
  foreground, `Connect-MgGraph -UseDeviceCode` prints the code, but the
  agent only sees output when the command returns, which is after sign-in or
  after timeout. Running it detached with output going to a file put the
  code in front of me within seconds.
- The SDK timed out before the code expired. The SDK's default client
  timeout is about 120 seconds, much shorter than the 15-minute life of the
  code. Two of four sign-in attempts one afternoon hit that timeout before I
  had entered the code. I moved to calling the device authorization
  endpoints directly and handing the token to the SDK. I later learned
  `Connect-MgGraph` has `-ClientTimeout`. The hand-written flow was still
  worth keeping: the code shows up in a file within seconds, the token is
  reused across separate processes, and one sign-in serves a whole queue.
- I kept refresh tokens I never used. My first launcher used the SDK's
  persistent token cache, which keeps a refresh token on disk. The raw-flow
  scripts that replaced it asked for `offline_access` and then threw the
  refresh token away. I needed neither. This version refuses
  `offline_access` outright and caches only the access token.
- Status written to the pipeline corrupts a return value. In PowerShell, a
  logging line inside a function that returns a token becomes part of the
  return value, and the token becomes an array. The original worker carries
  a comment warning about exactly this. Status now goes to the host or a
  file, never the pipeline.
- The success marker was wrong. An early runner wrote its success marker
  with a variable that did not exist in that scope, so every run ended with
  a failure message while the query files were fine. The tests now check
  the success marker too.
- An Intune portal save undid a Graph change. I changed a Win32 app's
  detection rule through Graph. Three minutes later I uploaded a logo in an
  Intune blade I had opened before the change. The portal re-sent every
  field it had loaded and silently put the old rule back. I re-applied it
  one field at a time with read-back.
- Graph rejected one field and accepted the rest. A long notes value came
  back BadRequest. Because each field was its own PATCH, nothing else was
  lost; the notes went in through the portal.
- The default MFA method cannot go first. Deleting the Authenticator method
  failed while it was the default; it succeeded after the phone method was
  removed.
- Not every endpoint takes a UPN as the key. Some calls answered "Get By
  Key only supports UserId". Resolve the object id first, always.
- Some queries returned 403. The older Intune cleanup settings endpoint
  returned 403 for my role while the cleanup rules endpoint worked.
  Delegated `Sites.Read.All` returned 403 on another user's OneDrive. The
  tools record 403 as "not visible to this account" and keep going, and a
  conclusion that depended on that query comes out as Undetermined.
- An audit log pull stopped at 5,000 rows. A per-user audit log pull came
  back with exactly 5,000 rows. `ReturnLargeSet` only helps if every call
  reuses one `SessionId` and you keep calling.

## Results at work

"Run from" says who typed the commands: the agent in Claude Code (with me
completing the sign-in and approving production writes before they ran), or
me in my own console.

| Job | Date | Run from | Result |
|---|---|---|---|
| Intune device forensics | 2026-09-18 | Agent | Showed by elimination that two laptops' Intune records were removed by the 90-day inactivity cleanup rule, not by an admin: no matching delete in a year of Intune audit events (about 5,600 checked), Entra and Autopilot objects still present. The lesson: issue wipe or retire on the last day instead of waiting for the hardware. [Case study](case-studies/intune-cleanup-rule-forensics.md). |
| Win32 detection false failures | 2026-09-11 | Agent | A remote-support agent showed 707 of 764 devices Failed. 667 of those were false: the agent had auto-updated past the MSI product code the detection rule looked for. Proved it with discovered-apps data through Graph, switched detection to a file rule through Graph, and handed over a 40-device list of real failures. [Case study](case-studies/detection-rule-false-failures.md). |
| Bulk app metadata | 2026-09-25 | Agent | Set the owner on 13 Intune apps resolved from a 118-app snapshot: 13 of 13 verified by read-back, assignments unchanged on all 13. |
| Remediations export | 2026-08-24 | My console | Every Remediations package with run data exported to its own CSV with per-device script output: 16 files in about 10 seconds, instead of one admin center screen at a time. |
| B2B access diagnosis | 2026-09-21 | Agent | A senior leader could not open a partner company's SharePoint file. Sign-in logs showed five successful sign-ins to the partner tenant; our cross-tenant settings allowed the collaboration, and our Conditional Access was not the blocker. The block was the partner's external sharing setting. [Case study](case-studies/b2b-external-sharing-diagnosis.md). |
| Offboarding gap closure | 2026-09-25 | Agent, through the queue worker | Nine queued steps on one Graph and one Exchange sign-in: discovery, a mailbox recheck, MFA method teardown, a device object delete, session revocation, and final verification. One step removed a group's app grant by mistake; I caught it and restored it about two minutes later. [Case study](case-studies/approle-delete-blast-radius.md). |
| Exchange at scale | 2026-09-15 | Agent | A read-only FullAccess sweep across 1,278 mailboxes for an offboarding audit, on device code sign-ins. |
| Volume | May to Sep 2026 | My console | My interactive admin console history shows 319 `Connect-MgGraph` commands, 197 raw `Invoke-MgGraphRequest` calls and 182 `Connect-ExchangeOnline` commands (commands entered; output was not kept). The agent's own shell does not write to that history. |

## Lessons

1. Let a person hold the sign-in. Device code lets an agent work under a
   person's real identity, MFA and Conditional Access, and the audit log
   shows the person. Offboarding the person offboards the agent.
2. Keep tokens short-lived. An access token that dies in under an hour, and
   no refresh token, limits what a mistake or a compromised process can do
   later.
3. Use roles or a dedicated app to limit what the agent can do. With a
   shared first-party client, asking for fewer scopes does not shrink what
   the token carries. See [`docs/scopes-and-roles.md`](scopes-and-roles.md).
4. Separate read from write in code. Read-only by default at the transport,
   writes only behind a switch, one field at a time. That stops accidents;
   approving production writes before they run is the control.
5. Read back every write. Then check the fields you did not mean to change.
6. Know what an object really is before you delete it. A user's
   appRoleAssignments list also includes grants made to their groups.
7. Always page, on every collection endpoint.
8. Write the quirks down the day you hit them. Mine are in
   [`docs/lessons.md`](lessons.md).

## How this was built

I built the original tooling at work with Claude Code as my primary tool
and verified the results in the tenant. I approved production writes before
they ran. When my Claude Code usage ran out, I pointed Codex, signed in to
the company's ChatGPT workspace, at the same folders and the same
agent-neutral `AGENTS.md`; the controls are in the scripts, so they applied
to Codex the same way. The timeline: Codex from mid-August (the desktop app,
for OCR) and the Codex CLI from 2026-08-21.

This is a fresh rewrite, generalized from what I ran at work, written with
Claude Code. I directed the work and checked the results against my own
records. The code here is tested offline against synthetic fixtures (65
tests passing on 2026-10-09) and has not been run against a live tenant in
this form. Employer, people, ticket numbers and tenant identifiers are
removed; the case studies are what happened, with identifying details
generalized. Colleagues show up by role where they contributed: the
colleague who first suggested why the remote-support agent's installs were
failing, and the Global Admin, to whom my plan routed consent for the
agent's app.

## Requirements

- PowerShell 7.2 or later on Windows (5.1 won't run these)
- Microsoft.Graph.Authentication 2.x
- ExchangeOnlineManagement 3.x with `Connect-ExchangeOnline -AccessToken`
- PnP.PowerShell, if used, in its own session

## About

Colin Lundholm, IT Support Engineer. [GitHub](https://github.com/gitColinX) | [LinkedIn](https://www.linkedin.com/in/cdlundholm)

Corrections welcome by issue or pull request. [MIT license](../LICENSE)
