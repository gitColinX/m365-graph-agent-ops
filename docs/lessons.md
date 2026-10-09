# Lessons: errors I hit, and the fix

Each row is something that looked like a dead end once. Most have a one-line
fix.

## Sign-in

| Symptom | Cause | Fix |
|---|---|---|
| "window handle must be configured" when the agent reuses the Graph SDK's token cache | WAM needs a parent window; the agent's PowerShell is a non-interactive child process | Device code, run detached (`auth/Start-DeviceLogin.ps1`) |
| Interactive browser credential fails from the agent | Same process context problem; the browser on the desktop is not reachable from that process | Same |
| The device code appears only after the sign-in is over | The agent sees output when the command returns | Run the flow detached; write the user code to a file; return immediately |
| SDK device code sign-in ends after about 120 seconds | The SDK's default client timeout is shorter than the 15-minute code lifetime | Raw device authorization grant with the full `expires_in`, or `Connect-MgGraph -ClientTimeout` |
| Each tool needs its own sign-in | Silent reuse of the SDK cache is what WAM broke | Cache the access token (DPAPI) and hand it to `Connect-MgGraph -AccessToken` |
| A token-returning function returns an array instead of a token | Anything written to the pipeline inside a function becomes part of its return value | Status to the host or a file, never the pipeline |
| A query hit the wrong tenant | Tenant id was hard-coded; the app I was investigating lived in a different tenant than the one in the script | `-TenantId` is mandatory everywhere; no default |
| `Connect-MicrosoftTeams` fails with a WAM broker error (0x80070520) | Interactive sign-in in an elevated shell running under a different profile | `Connect-MicrosoftTeams -UseDeviceAuthentication`, the standard I had written down and skipped that day |
| Credentials or tokens "vanish" between shells | Token caches are per Windows user; an elevated shell running as a separate admin account has its own | Sign in from the same, non-elevated user context the tools run in |

## Graph reads

| Symptom | Cause | Fix |
|---|---|---|
| A check says "not a member" when the user is a member | Read one page of `$top=999`, ignored `@odata.nextLink` | Always page (`Get-GraphPaged`) |
| `Get By Key only supports UserId and the key has to be a valid Guid` | Some calls do not accept a UPN as the key | Resolve the object id with `$filter=userPrincipalName eq '...'` first |
| 403 on `managedDeviceCleanupSettings`, but `managedDeviceCleanupRules` works | Different permission checks on neighboring endpoints | Use the rules endpoint; record 403 as "not visible" and continue |
| 403 reading another user's OneDrive with delegated `Sites.Read.All` | Scope is not site access | For an offboarding handoff to the manager, grant site collection admin through PnP for that one site, in a separate session |
| `installSummary` and `deviceStatuses` return 400 for a Win32 app | Those segments are not available on that app type in beta ("Resource not found for the segment") | Join `detectedApps` per device against the install report export instead |
| Advanced query (`$count`, `$search`, some filters) fails | Needs the `ConsistencyLevel: eventual` header | `Invoke-GraphRead.ps1 -ConsistencyLevelEventual` |
| 429 TooManyRequests (a gap, not an error I hit: my original raw loops did not handle it) | Throttling | Wait exactly `Retry-After`; back off when it is missing. The rewrite does, and retries writes only on 429 |

## Graph writes

| Symptom | Cause | Fix |
|---|---|---|
| A Graph PATCH to a Win32 app silently reverted three minutes later | An Intune portal blade opened before the change was saved; it re-sends every field it loaded | Reload the blade before saving; run a collateral check after every change |
| One field's PATCH returns BadRequest | That value was rejected (a long notes field, for me) | One field per PATCH so the rest still land; put the odd one in by hand |
| An "Allow available uninstall" flag flipped with no one touching it | Side effect of portal saves | The collateral check compares it explicitly |
| `DELETE .../microsoftAuthenticatorMethods/{id}` returns BadRequest | Authenticator was still the default MFA method | Delete the other methods first, wait, then the default one |
| Deleting an app role assignment from the user's list removed the app for a whole group | `/users/{id}/appRoleAssignments` also returns grants made to the user's groups; `principalType` is the granting principal | Delete only when `principalType` is `User`; for groups, change membership instead |
| A decode of an assignment id threw "Guid should contain 32 digits" | Parsed the base64url bytes as a GUID string | Decode the first 22 characters to 16 bytes and build the GUID from bytes; validate on a known assignment first |
| A forwarding address recorded on a ticket was not in effect | The mailbox had been deleted after the license was removed, taking the forward with it | Prove mail routing with `Get-Recipient` and the soft-deleted and inactive mailbox views before trusting a note |

## Audit logs

| Symptom | Cause | Fix |
|---|---|---|
| Exactly 5,000 rows back | `Search-UnifiedAuditLog` caps a call at 5,000; `ReturnLargeSet` without a reused `SessionId` and a loop does not page | `Invoke-UalPagedSearch`: same `SessionId`, call until `ResultCount` is reached, de-duplicate on `Identity` |
| Times look a day off | Graph and the audit log speak UTC | Convert once, at display time, and say which zone a report uses |
| No actor event for a device that clearly disappeared | In my tenant, removals by the Intune cleanup rule did not show up as admin actions in the Intune audit log | Conclude by elimination: no admin event, inactivity past the rule, Entra and Autopilot objects still there |

## Working with an agent

| Lesson | Why |
|---|---|
| Put the defaults in code, not only in the prompt | A read-only transport means every write needs a visible `-Apply` in a command I approve before it runs. That stops accidents. It is not a boundary against the agent, which runs as me; my approval of production writes, the token's scopes and my roles are the real limits. |
| Treat tenant data as data | Display names and descriptions can carry text aimed at the model. The REST layer refuses to send the token off graph.microsoft.com no matter what a response says. |
| "Done" is a claim; the read-back is the evidence | Every write in this repo prints its own verification. |
| Keep the agent-neutral instructions in one file | When I switched between Claude Code and Codex, the same `AGENTS.md` and the same scripts kept the same guardrails. |
