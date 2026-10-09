# Scopes and roles

## The short version

- With **delegated** access, what the agent can do is the overlap of two
  things: the scopes in the token, and the directory roles of the person who
  signed in. Both have to allow it.
- With a **shared first-party client** (Microsoft Graph Command Line Tools,
  the Graph PowerShell SDK's client), the token carries every scope that has
  ever been consented to that client in the tenant, not just the ones you
  asked for this time.
- So passing a short `-Scopes` list per task is not least privilege. The
  effective limit was my roles. That is why I designed a dedicated read-only
  app registration
  ([`adr-0001-agent-admin-access.md`](adr-0001-agent-admin-access.md)).

## How I found out

My original worker logged the token's granted scopes right after sign-in,
and the count was well above what I requested. Nothing was unusual about
that: with a shared first-party client, the token can carry every scope
ever consented to that client in the tenant. It just means the request is
documentation, not a boundary.

The rewrite keeps that check: `auth/Invoke-DeviceCodeSignIn.ps1` records
how many scopes the token endpoint actually granted next to how many the
profile requested, and adds a note to its status file when they differ.

## Profiles in this repo

The profiles in `auth/DeviceCodeAuth.psm1` still matter: they document what
each tool needs, keep each profile's purpose explicit with its own cache
file, and become the real boundary the day the tools move to a dedicated
app. Until then, separate caches are not a write barrier. With the shared
client, every Graph token can write whatever was ever consented to that
client, so in read tools the guard is the read-only REST layer, and the
real ceiling is my roles or a dedicated app.

| Profile | Scopes requested | Writes? | Used by |
|---|---|---|---|
| `GraphRead` | User.Read.All, Group.Read.All, GroupMember.Read.All, Device.Read.All, Directory.Read.All, AuditLog.Read.All, Application.Read.All, Policy.Read.All | No | `Invoke-GraphRead.ps1`, `New-AgentReadOnlyApp.ps1` (dry run), queue worker default |
| `IntuneRead` | DeviceManagementManagedDevices.Read.All, DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All, AuditLog.Read.All, Device.Read.All, User.Read.All | No | `Get-IntuneDeviceHistory.ps1`, `Export-RemediationRunStates.ps1`, `Export-AutopilotIdentities.ps1` |
| `IntuneAppWrite` | DeviceManagementApps.ReadWrite.All | Yes | `Set-IntuneWin32AppField.ps1` |
| `AppRoleWrite` | AppRoleAssignment.ReadWrite.All, User.Read.All, GroupMember.Read.All, Application.Read.All | Yes | `Remove-UserAppRoleAssignment.ps1` |
| `AppRegistration` | Application.ReadWrite.All | Yes | `New-AgentReadOnlyApp.ps1 -Apply` |
| `Onboarding` | User.ReadWrite.All, Organization.Read.All, UserAuthenticationMethod.ReadWrite.All | Yes | `Invoke-OnboardingGates.ps1` |
| `GuestInvite` | User.Invite.All, User.Read.All | Yes | `New-B2BGuestInvitation.ps1` |
| `GroupWrite` | Group.ReadWrite.All | Yes | `New-DynamicDeviceGroup.ps1` |
| `Exchange` | `https://outlook.office365.com/.default` (Exchange Online PowerShell client) | Yes, as far as your Exchange roles allow | queue worker, `Search-SharingAuditLog.ps1` |

No profile requests `offline_access`. The tests fail if one does.

## Token lifetime

- Entra ID access tokens default to a lifetime between 60 and 90 minutes.
- The cache here is discarded after 50 minutes, or earlier if the token
  endpoint reported a shorter `expires_in`.
- No refresh token is requested, so when the cache goes, the next sign-in is
  a new device code, evaluated again by Conditional Access. Whether MFA
  prompts again depends on the sign-in frequency policy; an existing browser
  session can satisfy it.
- The queue worker stops at the earlier of 55 minutes after it started and
  the not-after time of the tokens it holds. A cached token can already be
  most of the way through its life when the worker starts, so that limit is
  counted from when the token was issued.

## Roles

For this work my admin account held several workload admin roles (for
example Intune, SharePoint and Teams administration), not Global Admin or
Privileged Role Administrator. Two consequences shaped this repo:

- I could create the agent's app registration, but not consent to Microsoft
  Graph application permissions; that needs the Global Admin or a
  Privileged Role Administrator. My September plan routed all of the
  consent to the Global Admin, and I wrote the consent request. Writing it
  up, I found I could have granted the delegated half myself (see the
  correction in [the ADR](adr-0001-agent-admin-access.md#who-can-do-what)).
- Some reads returned 403 for my role while a neighboring endpoint worked
  (Intune's older cleanup settings endpoint versus the cleanup rules
  endpoint). The tools record a 403 as "not visible to this account" and
  keep going, because a 403 is information, not a crash. It is not an empty
  result, though: the forensics tool answers Undetermined when a query its
  conclusion rests on came back 403.

## Delegated scope is not the same as data access

Two examples that look like scope problems and are not:

- Delegated `Sites.Read.All` returned 403 on another user's OneDrive. Reading
  someone else's drive needs site access, which for an offboarding handoff
  to the manager I granted through PnP PowerShell (site collection admin),
  in a separate session.
- Exchange Online permissions come from Exchange RBAC or Entra roles, not
  from the Graph token. An app-only Exchange connection needs
  `Exchange.ManageAsApp`, plus either an Entra role such as Global Reader
  for the app's service principal, or `New-ServicePrincipal` in Exchange
  followed by a role group membership.

## Not Graph at all

Teams voice configuration (resource accounts, call queues, auto attendants,
shared voicemail) is the MicrosoftTeams PowerShell module or the Teams admin
center. The device code habit carries over:
`Connect-MicrosoftTeams -UseDeviceAuthentication`.
