# ADR 0001: How an AI agent gets admin-grade access to Microsoft 365

- **Date:** 2026-09-17
- **Revised:** October 2026, while writing this repo. Three corrections to the September plan are marked "Correction" below: who could consent, the Exchange steps, and the app-only trade-off.
- **Status:** Accepted in part. The app registration and its service principal were created. My plan routed consent to the Global Admin, and I wrote the consent request. The MCP options were not set up. Day-to-day work stayed on delegated device code sign-in.
- **Deciders:** me, with the Global Admin for anything that needs consent

## Context

By September I was running Graph and Exchange Online work from Claude Code
through delegated device code sign-ins (see [`../auth/README.md`](../auth/README.md)).
It worked, but every new task meant another code, and the token came from a
shared first-party client that could carry more consented scopes than any
task needed (see [`scopes-and-roles.md`](scopes-and-roles.md)).

Three ways to give the agent standing, scoped access were on the table. I
compared them on what the agent could do, how it authenticates, where
secrets would live, and what an attacker gets if the agent is tricked by
text in tenant data.

## Options

### A. Microsoft MCP Server for Enterprise

Microsoft's own remote MCP server for Microsoft Graph, in public preview when
I looked.

- Read only: tools to suggest Graph queries, run GET requests and list entity
  properties.
- Runs as the signed-in user, so it can never exceed that user's roles.
  Calls show up in Microsoft Graph activity logs under the server's own app.
- Scope at the time: Entra identity and directory data. No Intune, no
  Exchange, no Teams administration.
- Setup needs a tenant admin: provision the server's service principal and
  grant a client app its scopes.
- **Verdict:** the safest option and Microsoft-supported. It solved only
  directory reads, but cost nothing, so: enable it as a bonus.

### B. Lokka (open-source MCP server for Microsoft Graph and Azure)

A local stdio MCP server by Merill Fernando, run with `npx`.

- One tool that passes any Graph or Azure Resource Manager path with GET,
  POST, PUT, PATCH or DELETE. Covers Intune, Teams and SharePoint surfaces
  that Graph exposes. Not Exchange PowerShell cmdlets.
- Auth modes: interactive with its default app, interactive with your own
  app, client secret, certificate, or a supplied token.
- Risks I wrote down:
  1. **No read-only switch.** Whatever the Entra app is allowed to do, the
     model can do. Mitigation: grant the app read-only permissions only.
  2. **A client secret would sit in plain text** in the MCP client
     configuration. Mitigation: never use secret mode.
  3. **`npx -y` runs whatever version is latest** on every launch.
     Mitigation: pin an exact version and review before bumping.
  4. **Prompt injection through tenant data.** Display names, descriptions
     and mail bodies returned by Graph can carry instructions aimed at the
     model. Read-only scoping caps the damage at disclosure.
- **Verdict:** the option that removes the daily friction, Intune included.
  Acceptable in interactive mode, against my own read-only app, with a
  pinned version.

### C. Certificate app-only for the PowerShell modules

The same app registration gets application permissions and a certificate,
for unattended `Connect-MgGraph -ClientId -TenantId -CertificateThumbprint`,
`Connect-ExchangeOnline -AppId -CertificateThumbprint -Organization`, and
the equivalents in the Teams and PnP modules.

- App-only ignores my roles: the app's own permissions are the ceiling. So
  they must be read-only.
- Exchange needs more than an API permission: `Exchange.ManageAsApp`, plus
  an Exchange admin running `New-ServicePrincipal` to register the app's
  service principal inside Exchange and adding it to a role group such as
  View-Only Organization Management. (Assigning an Entra role such as
  Global Reader to the app is the other documented route.) **Correction:**
  my September plan listed only the role group step; `New-ServicePrincipal`
  has to come first.
- The private key is generated non-exportable in my user certificate store.
  If the machine is lost, remove the key credential from the app.
- **Correction, the trade-off I did not write down in September:**
  non-exportable only means the key cannot be copied out. Any process
  running as me, the agent included, can still use it to sign in as the
  app: unattended, with no MFA, and outside Conditional Access unless the
  tenant licenses Conditional Access for workload identities. That is the
  opposite of the rest of this repo, where I hold the sign-in. Read-only
  application permissions are tenant-wide reads, and some of them read
  content: `Sites.Read.All` reaches every SharePoint and OneDrive file,
  `UserAuthenticationMethod.Read.All` every user's registered methods. So
  "read-only" is not "least privilege", and the app-only half needs its own
  limits:
  - App-only permissions only for what a named job needs. The script's
    default application set leaves out `Sites.Read.All` and
    `UserAuthenticationMethod.Read.All`, and refuses content-reading
    permissions (mail, files, sites, chats, calendars, authentication
    methods, BitLocker keys, LAPS passwords) unless asked explicitly.
  - A TPM-backed key, so it is bound to one machine, and a short
    certificate lifetime (3 months by default).
  - `appRoleAssignmentRequired` on the service principal, and no public
    client flows on an app that holds application permissions.
  - An alert on sign-ins by this service principal, and someone who reviews
    them.
- **Verdict:** the only option that makes Exchange reads silent for the
  agent, at the cost above.

## Decision

One app registration, read-only, two credential types:

- **Delegated** read-only Graph permissions plus a `http://localhost`
  public-client redirect, for an MCP client in interactive mode (option B).
  Delegated access is the intersection of the app's permissions and my
  roles. Public client flows (device code, username and password) stay off.
- **Application** read-only Graph permissions plus `Exchange.ManageAsApp`,
  with a certificate, for unattended PowerShell (option C), limited as
  described under option C.
- Option A enabled alongside, since it costs nothing.
- **Writes stay where they are:** delegated device code sign-in, a human
  approving each production write before it runs, read-back after every
  change. If the agent ever needs to write unattended, that is a second app
  with a deliberately small write set, not a scope bump on this one.

The permission lists are the defaults in
[`../tools/New-AgentReadOnlyApp.ps1`](../tools/New-AgentReadOnlyApp.ps1):
19 Microsoft Graph permissions delegated, and 17 of them as application
permissions. My September plan asked for all 19 both ways; the rewrite
drops `Sites.Read.All` and `UserAuthenticationMethod.Read.All` from the
app-only set. The script refuses any permission whose name is not a `.Read`
or `.ReadBasic` variant.

## Who can do what

| Step | Who |
|---|---|
| Create the app registration, upload the certificate, create the service principal | Any user allowed to register applications, or an Application Developer, Application Administrator or Cloud Application Administrator. I could do this. |
| Grant tenant-wide consent for **delegated** permissions, including Microsoft Graph | Cloud Application Administrator or Application Administrator. |
| Grant consent for **application** permissions on APIs other than Microsoft Graph (for example `Exchange.ManageAsApp`) | Cloud Application Administrator or Application Administrator. |
| Grant consent for **Microsoft Graph application permissions** | Privileged Role Administrator or Global Administrator only. |
| Register the service principal in Exchange and add it to a role group | An Exchange administrator. |
| Provision the Enterprise MCP server for the tenant | A tenant admin with rights to create service principals and grant permissions. |

**Correction:** My September plan routed all consent to the Global Admin
because I thought my role could not grant Graph permissions. Writing it up,
I found I could have granted the delegated half. I would still route it to
a second person: granting your own automation its own permissions should
have someone else on it. I wrote the consent request: the consent link,
what the app is and is not, and the Exchange step.

Related point worth knowing: Cloud Application Administrator can also add
credentials to applications and then act as them. That role deserves the
same care as the permissions it can grant.

## Consequences

- The app and its service principal existed; nothing could use them until
  consent. The day-to-day tooling stayed on device code sign-in, which is
  what this repo's tools use.
- When the work moves to the app, every `tools/Get-*` style read can run
  without a code, and Exchange reads become possible for the agent at all.
- The certificate is tied to one machine and one user profile. Rotation and
  revocation are manual, so they belong in the runbook.
- Once consented, the app-only half works without me: anything running as me
  can use the key. The limits under option C are what keep that acceptable,
  and the service principal's sign-in log is where misuse would show.
- The prompt-injection risk does not go away with read-only scopes; it
  shrinks to disclosure. Treat everything Graph returns as data, never as
  instructions.

## Sources I used

- Microsoft Learn: granting tenant-wide admin consent (role requirements),
  app-only authentication for Exchange Online PowerShell, Microsoft MCP
  Server for Enterprise overview.
- The Lokka repository and documentation (authentication modes,
  configuration).
- `claude mcp add --help` for the client-side flags.
