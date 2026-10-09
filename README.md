# M365 Graph Agent Ops

This is a rewrite of the PowerShell tools I used at work to run Entra ID, Intune and Exchange Online tasks from Claude Code through Microsoft Graph, in a hybrid tenant of about 1,100 devices. Claude never saw my password. It started a device code sign-in, I finished it in my browser with my MFA, and every call after that showed up in the audit log as me. I approved each production write before it ran and read it back afterward.

## Results at work

- Intune showed 707 of 764 devices failing to install our remote-support tool. 667 were false failures: the tool had auto-updated past the MSI product code the detection rule looked for. I switched detection to a file rule through Graph and handed over the 40 real failures.
- Two laptops were gone from Intune. I went through a year of audit events (about 5,600), found no matching delete, and showed the 90-day inactivity cleanup rule had removed them.
- I ran a nine-step offboarding with one sign-in each for Graph and Exchange. One step removed a whole group's access to an app by mistake. I caught it, restored it in about two minutes, and started a delete helper that refuses group grants.
- I checked FullAccess permissions on 1,278 mailboxes, read-only, for an offboarding audit.

## What's in here

- [auth/](auth/) - the device code sign-in. It caches a short-lived access token and never a refresh token.
- [lib/](lib/AgentGraph.psm1) - the Graph REST module. It refuses writes unless a tool passes `-Apply`.
- [tools/](tools/) - Graph reads, Intune device history, a Remediations export, Win32 app field edits, a queue worker for approved steps, and the app role delete helper.
- [recipes/](recipes/README.md) - short scripts for onboarding checks, guest invites, Autopilot export and audits.

## Try it

```powershell
pwsh -NoProfile -File tests/Run-Tests.ps1
```

65 offline tests, including the Graph REST tools end to end against a mock Graph, so no tenant is needed. The rewrite hasn't been run against a live tenant. Needs PowerShell 7.2 or later on Windows.

## More detail

- [Full write-up](docs/WRITEUP.md) - the sign-in problem, the guardrails, problems I hit and all the results
- [Case studies](docs/README.md#case-studies) - four jobs written up in detail
- [Other docs](docs/README.md) - sign-in notes, the access decision, scopes and roles, and errors I hit

## About

Colin Lundholm, IT Support Engineer. [GitHub](https://github.com/gitColinX) | [LinkedIn](https://www.linkedin.com/in/cdlundholm)

[MIT license](LICENSE)
