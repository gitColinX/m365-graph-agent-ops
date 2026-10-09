# Sign-in for an agent that must never hold a password

Everything in this repo signs in through the files in this folder. This page
is the why.

## The constraint

Claude Code runs PowerShell as a non-interactive child process and shows me
the output only when the command returns. That breaks the usual sign-ins:

| Method | What happened from the agent's shell |
|---|---|
| `Connect-MgGraph` (WAM, the default on Windows) | Silent reuse of the cached token failed with "window handle must be configured". The broker needs a parent window; the agent's process has none. |
| Interactive browser credential | Failed the same way. A browser was on the desktop; the process asking for it could not open one. |
| `Connect-MgGraph -UseDeviceCode` in the foreground | Works, but the code is printed by a command that has not returned yet, so the agent cannot show it to me until sign-in is over or has timed out. |
| `Connect-MgGraph -UseDeviceCode` in a detached process | The code reached me in about 3 seconds. Then the SDK's default client timeout (about 120 seconds) ended two of my sign-ins before I had entered the code. |
| Raw device authorization grant (this folder) | Code in a file within seconds, full 15-minute window, token reused across processes. This became the standard. |

`auth/Test-WamSignIn.ps1` prints the facts that decide this for any process:
interactive flag, console window handle, redirected streams, session id,
elevation, SDK version. It changes nothing unless you pass
`-TryGraphConnect`, which attempts a real sign-in in a child process. Run
from inside a Claude Code session while I was writing this repo (without
`-TryGraphConnect`), it reported (trimmed):

```
stdinRedirected : True
consoleWindow   : none
elevated        : False
hints           : This process has no interactive window to parent a WAM or browser prompt.
                  Use device code: auth/Start-DeviceLogin.ps1.
```

Device code was my standard for agent work, not the only method I ever used.
In my own console, the normal WAM sign-in works fine.

## The flow

```
agent                       Start-DeviceLogin.ps1             detached child                      Entra ID
  | run, -AuthProfile X  -->  |                                  |                                    |
  |                           | start child (hidden) ----------> | POST /{tenant}/oauth2/v2.0/devicecode
  |                           |                                  | <---------- user_code, device_code, interval, expires_in
  |                           | <-- usercode.txt (seconds) ----- |                                    |
  | <-- USER_CODE=... URL=... |                                  | POST /token every `interval` s     |
  |  (returns)                                                   |   authorization_pending: keep going |
  |                                                              |   slow_down: interval += 5 s         |
me: open URL, enter code, password, MFA, Conditional Access ---------------------------------------->  |
  |                                                              | <---------- access_token (no refresh token)
  |                                                              | DPAPI cache, status.txt "OK"       |
  | tools/*.ps1 -CacheOnly  --> read cache --> Graph REST / Connect-MgGraph -AccessToken / Connect-ExchangeOnline -AccessToken
```

`Get-AgentAccessToken -CacheOnly` never starts a sign-in. Tools fail fast
with "run Start-DeviceLogin.ps1" instead, so sign-in only ever happens where
the agent can see and relay the code.

## Decisions, and why

**Public first-party clients.** Graph uses Microsoft Graph Command Line Tools
(`14d82eec-204b-4c2f-b7e8-296a70dab67e`, the Graph PowerShell SDK's own
client). Exchange uses Exchange Online PowerShell
(`fb78d390-0c51-40cd-8e17-fdbfab77341b`) with scope
`https://outlook.office365.com/.default`, and that token goes to
`Connect-ExchangeOnline -AccessToken -UserPrincipalName`. Both ids are
public and documented; they are not secrets. The catch with a shared client
is in [`../docs/scopes-and-roles.md`](../docs/scopes-and-roles.md).

**Named profiles, not ad hoc scopes.** Tools ask for `GraphRead`,
`IntuneRead`, `IntuneAppWrite` and so on, and each profile has its own
cache file. Separate caches keep each profile's purpose explicit. They are
not a write barrier: with the shared client, every Graph token can write
whatever was ever consented to that client, so in read tools the guard is
the read-only REST layer, and the real ceiling is my roles or a dedicated
app. Profiles are listed in `DeviceCodeAuth.psm1`.

**No `offline_access`.** The Microsoft identity platform returns a refresh
token only when `offline_access` is requested. My first launcher used the
SDK's persistent cache, which keeps a refresh token on disk. The raw-flow
scripts that replaced it asked for `offline_access` and then discarded the
refresh token. I needed neither. This version refuses any scope list that
contains `offline_access` (including inside a space-separated string), and
drops a refresh token if one ever comes back.

**Cache only the access token, encrypted with DPAPI.**
`ConvertFrom-SecureString` without a key uses DPAPI for the current Windows
user. That protects the file from other users on the machine. It does not
protect it from anything running as me, and the agent runs as me. So the
cache is short-lived by design.

**Expire by file age.** Microsoft says clients should treat access tokens as
opaque, so I do not parse the token to read its expiry. The cache file is
discarded after 50 minutes (default access tokens live 60 to 90 minutes),
or at `expires_in` minus 5 minutes if the token endpoint said less.
`Get-AgentAccessToken` returns that not-after time with the token, counted
from when the token was issued, so a long-running caller such as the queue
worker knows how much life a cached token really has left.

**The device code never touches disk.** `device_code` plus the public client
id is enough to redeem the token once I finish signing in. It stays in the
child process's memory as a SecureString. Only the user code is written to a
file, and that file is deleted when sign-in completes.

**Name the tenant.** `common`, `organizations` and `consumers` are refused.
A GUID or a verified domain is required on every call.

## Why not just `-ClientTimeout`?

`Connect-MgGraph` has a `-ClientTimeout` parameter. I learned that after I
had written this. I kept the raw flow because it solves three problems, and
the timeout was only one of them:

1. The code is visible within seconds, from a file, while the sign-in is
   still pending.
2. The token is reused by separate processes for its lifetime. Silent
   reuse of the SDK's own cache is exactly what WAM broke in the agent's
   shell.
3. One sign-in serves a queue of scripts (`tools/Start-QueueWorker.ps1`)
   and any number of later tool runs.

## Device code and Conditional Access

Device code is a known phishing technique: an attacker starts a flow and
talks someone into entering the code. Tenants can block the device code flow
with a Conditional Access authentication flows policy, and many should. If
yours does, this approach needs a narrow exception (named admin accounts,
from compliant devices or known locations) agreed with whoever owns
Conditional Access. Two habits that matter either way:

- Only enter a code you started yourself, seconds ago.
- Read the app name on the sign-in prompt before approving. Here it should
  be Microsoft Graph Command Line Tools or Exchange Online PowerShell.

## Files

| File | Role |
|---|---|
| `DeviceCodeAuth.psm1` | RFC 8628 functions, profiles, DPAPI cache, `Connect-AgentGraph`, `Connect-AgentExchange` |
| `Start-DeviceLogin.ps1` | What the agent runs. Returns the user code in seconds. |
| `Invoke-DeviceCodeSignIn.ps1` | The detached child. Writes `status.txt` with OK or FAIL, and how many scopes the token carried versus how many were requested. |
| `Test-WamSignIn.ps1` | Diagnostic for the process context. Read-only unless `-TryGraphConnect`. |
