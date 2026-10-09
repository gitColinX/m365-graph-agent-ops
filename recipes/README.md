# Recipes

Short, single-purpose scripts for jobs I did more than once. Same rules as
the tools: name the tenant, use a cached token from
`auth/Start-DeviceLogin.ps1`, dry run by default, `-Apply` for writes, read
back after every write.

Status labels describe the original work. The scripts here are fresh
rewrites, generalized from what I ran at work. The onboarding gates and the
Autopilot export run in the offline tests against a fake Graph; the B2B invite, the dynamic group and the
sharing audit search need the Graph SDK or an Exchange session, so they are
checked for syntax only. Filter values are URL-encoded, so a guest UPN with
`#EXT#` works in a `$filter`.

| Recipe | What it does | Profile | Status |
|---|---|---|---|
| [`Invoke-OnboardingGates.ps1`](Invoke-OnboardingGates.ps1) | New-hire gates: directory sync has propagated, usageLocation set, a free seat in `subscribedSkus`, `assignLicense` with explicit `addLicenses` and `removeLicenses` and a `licenseDetails` read-back, optional MFA phone pre-registration, optional Exchange mailbox gate | `Onboarding` (+ `Exchange` session for the mailbox gate) | [built, ran on real tickets] a few onboardings, each run in my own console |
| [`New-B2BGuestInvitation.ps1`](New-B2BGuestInvitation.ps1) | Duplicate check, `New-MgInvitation` through the SDK, read-back of `userType` and `externalUserState`; never prints the redeem URL | `GuestInvite` | [built, ran on real tickets] |
| [`Export-AutopilotIdentities.ps1`](Export-AutopilotIdentities.ps1) | All Autopilot identities to CSV; flags identities that point at an Intune record that no longer exists | `IntuneRead` | [built, ran on real tickets] |
| [`New-DynamicDeviceGroup.ps1`](New-DynamicDeviceGroup.ps1) | `New-MgGroup -MembershipRule` for a device group (example: every Windows 10 build), name collision check, rule read-back, optional member count polling | `GroupWrite` | [built, ran on real tickets] once, for a Windows 10 refresh scope; my shell history has the command, not its output |
| [`Search-SharingAuditLog.ps1`](Search-SharingAuditLog.ps1) | SharePoint and OneDrive sharing events from the unified audit log, flattened from `AuditData` | existing Exchange Online session | sharing searches [built, ran on real tickets]; the `SessionId` and `ReturnLargeSet` paging loop [in progress] |

## Notes that cost me time

- **License before mailbox.** The mailbox appears only after an Exchange
  service plan is assigned and provisioned. The license gate prints any
  service plan that is not provisioned yet, so a missing mailbox has an
  explanation.
- **usageLocation first.** License assignment fails without it.
- **REST or cmdlet for licenses.** I standardized on
  `POST /users/{id}/assignLicense` because it needs only the Graph token and
  makes the add and remove sets explicit. `Set-MgUserLicense` does the same
  job when its module (`Microsoft.Graph.Users.Actions`) is loaded. I used
  both.
- **Group-based licensing** is the more scalable pattern. These recipes do
  direct assignment because that is what the tenant used.
- **Phone methods need an authentication admin role** on top of the
  `UserAuthenticationMethod.ReadWrite.All` scope.
- **Dynamic groups need Entra ID P1**, take a while to evaluate, and a rule
  cannot mix `user.` and `device.` properties.
- **Search-UnifiedAuditLog:** 100 rows by default, 5,000 per call at most,
  up to 50,000 with `-SessionCommand ReturnLargeSet` only when every call
  reuses one `-SessionId`. For bulk or scheduled pulls, use the Office 365
  Management Activity API.
- **Test values:** use fictitious phone numbers (+1 555 0100 to 0199) and
  `example.com` addresses.
