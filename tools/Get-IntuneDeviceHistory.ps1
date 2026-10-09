#Requires -Version 7.2
<#
.SYNOPSIS
  Read-only forensics for "where did this device go in Intune?" Collects every surviving trace of a device and
  concludes by elimination.

.DESCRIPTION
  For each serial number, device name and (optionally) the primary user, it collects:
    - Intune managedDevices (current)
    - Entra device objects and their registered owners
    - Windows Autopilot device identities (and whether they still point at a managed device that is gone)
    - Intune device cleanup rules (managedDeviceCleanupRules; the older settings endpoint may return 403)
    - Intune audit events since -Since, matched locally on serial, name, user and device ids
    - Entra directory audits for the device objects, plus 'Delete device' events in the window
  Then Resolve-DeviceRemovalVerdict decides: StillEnrolled, AdminAction, CleanupRuleByElimination or
  Undetermined. "By elimination" means: no admin Delete, Retire or Wipe event matches the device, the device was
  inactive longer than the cleanup rule allows, and the Entra and Autopilot objects survived. The script says
  Undetermined rather than guess when the audit window does not cover the date the rule would have fired, and
  when any query the conclusion rests on (managed devices, Entra devices, Autopilot, cleanup rules, audit
  events) failed, returned 403 or hit its page cap. An empty result only counts as evidence if the query
  that produced it succeeded.

  Output: <OutDir>\intune-history-<stamp>.json and summary.md. Contains device names and UPNs; .gitignore
  excludes the output folder.

.EXAMPLE
  pwsh -File tools/Get-IntuneDeviceHistory.ps1 -TenantId contoso.onmicrosoft.com -SerialNumber 'SN0001' `
    -DeviceName 'LT-SN0001' -UserPrincipalName 'adele.vance@contoso.onmicrosoft.com' -Since '2025-10-01'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [string[]] $SerialNumber = @(),
  [string[]] $DeviceName = @(),
  [string] $UserPrincipalName,
  [datetime] $Since = (Get-Date).AddDays(-365),
  [string] $OutDir
)
$ErrorActionPreference = 'Stop'
if (-not $SerialNumber -and -not $DeviceName -and -not $UserPrincipalName) {
  throw 'Give at least one of -SerialNumber, -DeviceName or -UserPrincipalName.'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "intune-history-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile IntuneRead -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken

function Get-QuotedOData([string] $s) { ConvertTo-ODataLiteral $s }
$stepLog = [System.Collections.Generic.List[object]]::new()
function Invoke-Step([string] $Name, [string] $Uri, [int] $MaxPages = 50) {
  try {
    $items = @(Get-GraphPaged -Uri $Uri -MaxPages $MaxPages)
    $stepLog.Add([pscustomobject]@{ step = $Name; uri = $Uri; status = 200; count = $items.Count })
    return , $items
  } catch {
    $code = Get-GraphErrorStatus $_
    $note = if ($code -eq 403) { 'not visible to this account' } else { $_.Exception.Message }
    $stepLog.Add([pscustomobject]@{ step = $Name; uri = $Uri; status = $code; count = 0; note = $note })
    return , @()
  }
}

$sinceIso = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# 1. Intune managed devices (current)
$managed = @()
foreach ($s in $SerialNumber) { $managed += Invoke-Step 'managedDevices.serial' "beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$(Get-QuotedOData $s)'" }
foreach ($n in $DeviceName) { $managed += Invoke-Step 'managedDevices.name' "beta/deviceManagement/managedDevices?`$filter=deviceName eq '$(Get-QuotedOData $n)'" }
if ($UserPrincipalName) { $managed += Invoke-Step 'managedDevices.user' "beta/deviceManagement/managedDevices?`$filter=userPrincipalName eq '$(Get-QuotedOData $UserPrincipalName)'" }
$managed = @($managed | Sort-Object id -Unique)

# 2. Entra device objects and owners
$entra = @()
foreach ($n in $DeviceName) {
  $entra += Invoke-Step 'entraDevices.name' "beta/devices?`$filter=displayName eq '$(Get-QuotedOData $n)'&`$select=id,deviceId,displayName,trustType,isManaged,isCompliant,accountEnabled,registrationDateTime,approximateLastSignInDateTime,enrollmentType,managementType,profileType,operatingSystemVersion"
}
$entra = @($entra | Sort-Object id -Unique)
$owners = foreach ($d in $entra) {
  # Invoke-Step returns its array as one object; assign it before piping so the items enumerate.
  $ownerObjects = Invoke-Step 'entraDevices.owners' "beta/devices/$($d.id)/registeredOwners?`$select=id,userPrincipalName"
  [pscustomobject]@{
    device = $d.displayName
    owners = @($ownerObjects | ForEach-Object { Get-PropValue $_ 'userPrincipalName' })
  }
}

# 3. Autopilot identities
$autopilot = @()
foreach ($s in $SerialNumber) { $autopilot += Invoke-Step 'autopilot.serial' "beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$(Get-QuotedOData $s)')" }
$autopilot = @($autopilot | Sort-Object id -Unique)

# 4. Cleanup rules (the rules endpoint can work when the older settings endpoint returns 403 for your role)
$rules = Invoke-Step 'cleanupRules' 'beta/deviceManagement/managedDeviceCleanupRules'
$legacySettings = Invoke-Step 'cleanupSettings' 'beta/deviceManagement/managedDeviceCleanupSettings'

# 5. Intune audit events in the window, matched locally
$events = Invoke-Step 'auditEvents' "beta/deviceManagement/auditEvents?`$filter=activityDateTime ge $sinceIso" -MaxPages 500
$terms = @($SerialNumber + $DeviceName + @($UserPrincipalName) +
  @($autopilot | ForEach-Object { Get-PropValue $_ 'managedDeviceId' }) +
  @($entra | ForEach-Object { Get-PropValue $_ 'deviceId' }) +
  @($managed | ForEach-Object { Get-PropValue $_ 'id' })) |
  Where-Object { $_ -and $_ -ne '00000000-0000-0000-0000-000000000000' } | Sort-Object -Unique
$pattern = ($terms | ForEach-Object { [regex]::Escape([string]$_) }) -join '|'
$matching = @(if ($pattern) { $events | Where-Object { ($_ | ConvertTo-Json -Depth 10 -Compress) -match $pattern } })
$isRemoval = { param($e) ("$(Get-PropValue $e 'activityType') $(Get-PropValue $e 'displayName')") -match 'Delete|Retire|Wipe' }
$matchingRemovals = @($matching | Where-Object { & $isRemoval $_ })
$allRemovalsInWindow = @($events | Where-Object { & $isRemoval $_ }).Count

# 6. Entra directory audits for the surviving device objects, plus device deletes in the window
$dirAudits = @()
foreach ($d in $entra) { $dirAudits += Invoke-Step 'directoryAudits.device' "v1.0/auditLogs/directoryAudits?`$filter=targetResources/any(t:t/id eq '$($d.id)')" }
$dirAudits += Invoke-Step 'directoryAudits.deleteDevice' "v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Delete device' and activityDateTime ge $sinceIso"
$dirAudits = @($dirAudits | Sort-Object id -Unique)
$dirMatches = @(if ($pattern) { $dirAudits | Where-Object { ($_ | ConvertTo-Json -Depth 10 -Compress) -match $pattern } })

# 7. Verdict. The steps the conclusion rests on must have succeeded; the older cleanup settings endpoint, the
#    owner lookups and the directory audits are reported but do not decide the verdict.
$critical = '^(managedDevices\.|entraDevices\.name$|autopilot\.|cleanupRules$|auditEvents$)'
$failedSteps = @($stepLog | Where-Object { $_.status -ne 200 -and $_.step -match $critical } |
    ForEach-Object { "$($_.step) (HTTP $($_.status))" } | Sort-Object -Unique)
$verdict = Resolve-DeviceRemovalVerdict -Evidence @{
  Now                        = [datetimeoffset]::UtcNow
  AuditWindowStart           = [datetimeoffset]$Since.ToUniversalTime()
  ManagedDevices             = $managed
  EntraDevices               = $entra
  AutopilotIdentities        = $autopilot
  CleanupRules               = $rules
  MatchingAdminRemovalEvents = $matchingRemovals
  FailedSteps                = $failedSteps
}

$result = [ordered]@{
  generatedUtc               = (Get-Date).ToUniversalTime().ToString('o')
  query                      = [ordered]@{ serialNumber = $SerialNumber; deviceName = $DeviceName; user = $UserPrincipalName; since = $sinceIso }
  verdict                    = $verdict
  intuneManagedDevices       = @($managed | Select-Object id, deviceName, serialNumber, userPrincipalName, enrolledDateTime, lastSyncDateTime, managementState, complianceState, azureADDeviceId)
  entraDevices               = $entra
  entraDeviceOwners          = @($owners)
  autopilot                  = @($autopilot | Select-Object id, serialNumber, model, groupTag, enrollmentState, lastContactedDateTime, deploymentProfileAssignmentStatus, managedDeviceId, azureActiveDirectoryDeviceId)
  cleanupRules               = $rules
  cleanupSettings            = $legacySettings
  intuneAuditEventsInWindow  = $events.Count
  intuneRemovalEventsInWindow = $allRemovalsInWindow
  intuneAuditMatches         = @($matching | Select-Object activityDateTime, displayName, activityType, activityResult, @{ n = 'actor'; e = { Get-PropValue (Get-PropValue $_ 'actor') 'userPrincipalName' } })
  directoryAuditMatches      = @($dirMatches | Select-Object activityDateTime, activityDisplayName, result, @{ n = 'initiatedBy'; e = { $ib = Get-PropValue $_ 'initiatedBy'; $u = Get-PropValue $ib 'user'; $a = Get-PropValue $ib 'app'; if ($u) { Get-PropValue $u 'userPrincipalName' } else { Get-PropValue $a 'displayName' } } })
  steps                      = $stepLog.ToArray()
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$json = Join-Path $OutDir "intune-history-$stamp.json"
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $json -Encoding utf8

$md = @(
  '# Intune device history'
  ''
  "Generated $($result.generatedUtc). Audit window from $sinceIso."
  ''
  "**Verdict: $($verdict.Verdict)**"
  ''
  $verdict.Summary
  ''
  '| Evidence | Count |'
  '|---|---|'
  "| Intune managed devices now | $($managed.Count) |"
  "| Entra device objects | $($entra.Count) |"
  "| Autopilot identities | $($autopilot.Count) |"
  "| Intune audit events in window | $($events.Count) |"
  "| Delete, Retire or Wipe events in window (any device) | $allRemovalsInWindow |"
  "| ... matching this device | $($matchingRemovals.Count) |"
  "| Directory audit matches | $($dirMatches.Count) |"
  ''
) + @($verdict.Notes | ForEach-Object { "- $_" }) + @(
  ''
  'Steps that failed or were not visible to this account:'
) + @($stepLog | Where-Object { $_.status -ne 200 } | ForEach-Object { "- $($_.step): HTTP $($_.status) $(Get-PropValue $_ 'note')" })
$md -join "`n" | Set-Content -LiteralPath (Join-Path $OutDir 'summary.md') -Encoding utf8

Write-Output "VERDICT=$($verdict.Verdict)"
Write-Output $verdict.Summary
Write-Output "OUT_DIR=$OutDir"
