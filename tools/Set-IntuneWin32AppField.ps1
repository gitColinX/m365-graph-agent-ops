#Requires -Version 7.2
<#
.SYNOPSIS
  Changes metadata or detection on one Intune app through Graph, the careful way: dry run by default, resolve to
  exactly one app, one field per PATCH, read back every field, then check nothing else moved.

.DESCRIPTION
  1. Resolve. -AppName must match exactly one mobileApp display name (case-insensitive). Zero or several
     matches stop the run with the candidate ids. -AppId skips the lookup.
  2. Snapshot. The full app object and its assignments are written to before.json. That file is the rollback.
  3. Plan. Each requested field is compared with its current value; unchanged fields are skipped.
     Without -Apply the script stops here. The REST layer is read-only in that case, so nothing can be written.
  4. Apply. One PATCH per field, each with the app's own @odata.type. One rejected field (Graph returned
     BadRequest on a long notes value for me) does not sink the rest. Each PATCH is followed by a GET, and
     the field is compared field by field with what was sent (Get-ReadBackMismatch): key order and
     server-added defaults do not count as a mismatch. Intune does add defaults: a file detection rule comes
     back with operator and detectionValue filled in.
  5. Collateral check. The app is read again and compared with before.json on every field that was not meant
     to change, and on its assignments. Any difference is reported and the exit code says so. One expected
     side effect is not counted: Intune keeps a second copy of detection and requirement rules in 'rules',
     so a detectionRules change rewrites the ruleType 'detection' entries there. Only the other entries
     are compared.

  Portal warning: an Intune portal blade that was opened before this change still holds the old object.
  Saving anything in it (even just a logo) re-sends every field it loaded and silently reverts the Graph
  change. It happened to me three minutes after a detection rule PATCH. Reload the blade before saving there.

  Allowed fields: owner, publisher, developer, description, notes, informationUrl, privacyInformationUrl,
  installCommandLine, uninstallCommandLine, detectionRules. The last three are Win32 only.
  installCommandLine and uninstallCommandLine also need -AllowCommandLineChange: on a Required app they decide
  what runs as SYSTEM on every targeted device, so the plan prints the full old and new command and the
  apply stops without that second switch.

.EXAMPLE
  pwsh -File tools/Set-IntuneWin32AppField.ps1 -TenantId contoso.onmicrosoft.com -AppName '7-Zip' -Field owner -Value 'Endpoint team'
.EXAMPLE
  # detection rule change from a JSON file: { "detectionRules": [ { "@odata.type": "#microsoft.graph.win32LobAppFileSystemDetection", ... } ] }
  pwsh -File tools/Set-IntuneWin32AppField.ps1 -TenantId contoso.onmicrosoft.com -AppName 'Remote Support Agent' -ChangesJson .\changes.json -Apply
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [string] $AppName,
  [string] $AppId,
  [ValidateSet('owner', 'publisher', 'developer', 'description', 'notes', 'informationUrl', 'privacyInformationUrl', 'installCommandLine', 'uninstallCommandLine', 'detectionRules')]
  [string] $Field,
  [string] $Value,
  [string] $ChangesJson,
  [switch] $Apply,
  [switch] $AllowCommandLineChange,
  [string] $OutDir
)
$ErrorActionPreference = 'Stop'
$allowed = @('owner', 'publisher', 'developer', 'description', 'notes', 'informationUrl', 'privacyInformationUrl', 'installCommandLine', 'uninstallCommandLine', 'detectionRules')
$win32Only = @('installCommandLine', 'uninstallCommandLine', 'detectionRules')
$commandLineFields = @('installCommandLine', 'uninstallCommandLine')
# Fields Intune mirrors into the 'rules' collection, and the ruleType they appear under there.
$mirroredRuleType = @{ detectionRules = 'detection'; requirementRules = 'requirement' }
if ([bool]$AppName -eq [bool]$AppId) { throw 'Give exactly one of -AppName or -AppId.' }
if ([bool]$Field -eq [bool]$ChangesJson) { throw 'Give either -Field with -Value, or -ChangesJson.' }

$changes = [ordered]@{}
if ($Field) {
  $changes[$Field] = if ($Field -eq 'detectionRules') { @($Value | ConvertFrom-Json -Depth 20) } else { $Value }
} else {
  $j = Get-Content -LiteralPath $ChangesJson -Raw | ConvertFrom-Json -Depth 20
  foreach ($p in $j.PSObject.Properties) {
    if ($allowed -notcontains $p.Name) { throw "Field '$($p.Name)' is not in the allowed list: $($allowed -join ', ')." }
    $changes[$p.Name] = $p.Value
  }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "app-field-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile IntuneAppWrite -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken -AllowWrites:$Apply
$base = 'beta/deviceAppManagement/mobileApps'

# 1. Resolve
if ($AppName) {
  $all = @(Get-GraphPaged -Uri "$($base)?`$top=100")
  $r = Resolve-ExactlyOne -Items $all -Property 'displayName' -Value $AppName
  Write-Output "INVENTORY $($all.Count) apps"
  if ($r.Status -ne 'Resolved') {
    Write-Output "RESOLVE $($r.Status): '$AppName' matched $($r.Matches) app(s) [$($r.Ids -join ', ')]. Nothing changed."
    exit 2
  }
  $AppId = $r.Item.id
}

# 2. Snapshot
$before = Invoke-GraphRest -Uri "$base/$AppId"
$odataType = [string](Get-PropValue $before '@odata.type')
$bad = @($changes.Keys | Where-Object { $win32Only -contains $_ }) | Where-Object { $odataType -ne '#microsoft.graph.win32LobApp' }
if ($bad) { throw "Field(s) $($bad -join ', ') apply to Win32 apps only; this app is $odataType." }
$assignBefore = @(Get-GraphPaged -Uri "$base/$AppId/assignments")
[pscustomobject]@{ app = $before; assignments = $assignBefore } | ConvertTo-Json -Depth 20 |
  Set-Content -LiteralPath (Join-Path $OutDir 'before.json') -Encoding utf8
Write-Output "APP '$(Get-PropValue $before 'displayName')' id=$AppId type=$odataType assignments=$($assignBefore.Count)"

# 3. Plan
function Format-Short($v) {
  $s = if ($v -is [string]) { $v } else { $v | ConvertTo-Json -Depth 10 -Compress }
  if ($null -eq $s) { $s = '' }
  if ($s.Length -gt 120) { $s.Substring(0, 117) + '...' } else { $s }
}
$plan = foreach ($f in $changes.Keys) {
  $cur = if ($before.PSObject.Properties[$f]) { $before.PSObject.Properties[$f].Value } else { $null }
  # Same comparison as the read-back, so a re-run after a successful apply plans no change.
  $same = -not (Get-ReadBackMismatch -Desired $changes[$f] -Actual $cur -Path $f)
  [pscustomobject]@{ field = $f; action = $(if ($same) { 'unchanged' } else { 'change' }); current = (Format-Short $cur); desired = (Format-Short $changes[$f]); result = '' }
}
$plan = @($plan)
foreach ($p in $plan) { Write-Output ("PLAN {0,-22} {1,-9} '{2}' -> '{3}'" -f $p.field, $p.action, $p.current, $p.desired) }
$todo = @($plan | Where-Object action -eq 'change')
$cmdChanges = @($todo | Where-Object { $commandLineFields -contains $_.field })
foreach ($p in $cmdChanges) {
  # Never truncated: this is the command that will run as SYSTEM on every targeted device.
  Write-Output "PLAN $($p.field) FULL CURRENT: $([string](Get-PropValue $before $p.field))"
  Write-Output "PLAN $($p.field) FULL NEW:     $([string]$changes[$p.field])"
}
if (-not $Apply) {
  if ($cmdChanges.Count) { Write-Output 'NOTE command-line changes also need -AllowCommandLineChange when you apply.' }
  Write-Output "DRY RUN. Nothing was written. Re-run with -Apply to make $($todo.Count) change(s). Rollback file: $(Join-Path $OutDir 'before.json')"
  exit 0
}
if ($cmdChanges.Count -and -not $AllowCommandLineChange) {
  Write-Output "STOP $(($cmdChanges | ForEach-Object field) -join ', ') would change what runs on every targeted device. Re-run with -Apply -AllowCommandLineChange after reading the full commands above. Nothing was written."
  exit 6
}

# 4. Apply: one field per PATCH, read back each, compared field by field
foreach ($p in $todo) {
  $body = [ordered]@{ '@odata.type' = $odataType }
  $body[$p.field] = $changes[$p.field]
  try {
    Invoke-GraphRest -Method PATCH -Uri "$base/$AppId" -Body $body | Out-Null
    Start-Sleep -Milliseconds 500
    $back = Invoke-GraphRest -Uri "$base/$AppId"
    $backValue = if ($back.PSObject.Properties[$p.field]) { $back.PSObject.Properties[$p.field].Value } else { $null }
    $mismatch = Get-ReadBackMismatch -Desired $changes[$p.field] -Actual $backValue -Path $p.field
    $p.result = if (-not $mismatch) { 'OK verified' } else { "MISMATCH on read-back: $mismatch" }
  } catch {
    $p.result = "ERROR HTTP $(Get-GraphErrorStatus $_): $($_.Exception.Message)"
  }
  Write-Output ("PATCH {0,-22} {1}" -f $p.field, $p.result)
}

# 5. Collateral check
$after = Invoke-GraphRest -Uri "$base/$AppId"
$assignAfter = @(Get-GraphPaged -Uri "$base/$AppId/assignments")
$watch = @('displayName', 'displayVersion', 'publisher', 'developer', 'owner', 'description', 'notes', 'informationUrl',
  'privacyInformationUrl', 'installCommandLine', 'uninstallCommandLine', 'detectionRules', 'requirementRules', 'rules',
  'returnCodes', 'installExperience', 'allowAvailableUninstall', 'isFeatured', 'applicableArchitectures') |
  Where-Object { -not $changes.Contains($_) }
$expectedRuleTypes = @($changes.Keys | Where-Object { $mirroredRuleType.ContainsKey($_) } | ForEach-Object { $mirroredRuleType[$_] })
if ($expectedRuleTypes.Count) {
  # Compare only the 'rules' entries this change was not expected to touch.
  $watch = @($watch | Where-Object { $_ -ne 'rules' })
  $otherRules = { param($app) [pscustomobject]@{ rules = @(@(Get-PropValue $app 'rules') | Where-Object { $_ -and ([string](Get-PropValue $_ 'ruleType')) -notin $expectedRuleTypes }) } }
  $ruleLabel = "rules (entries other than $($expectedRuleTypes -join ', '))"
  $ruleDiffs = @(Compare-Snapshot -Before (& $otherRules $before) -After (& $otherRules $after) -Property 'rules' | ForEach-Object { $_.Property = $ruleLabel; $_ })
  Write-Output "NOTE Intune mirrors $($expectedRuleTypes -join ', ') rules into 'rules'; those entries are expected to change and are not counted as collateral."
} else {
  $ruleDiffs = @()
}
$diffs = @(Compare-Snapshot -Before $before -After $after -Property $watch) + $ruleDiffs
$norm = { param($list) @($list | ForEach-Object {
      $t = Get-PropValue $_ 'target'
      '{0}|{1}|{2}|{3}' -f (Get-PropValue $_ 'intent'), (Get-PropValue $t '@odata.type'), (Get-PropValue $t 'groupId'), (Get-PropValue $t 'deviceAndAppManagementAssignmentFilterId')
    } | Sort-Object) -join ';' }
$assignSame = ((& $norm $assignBefore) -eq (& $norm $assignAfter))
[pscustomobject]@{ app = $after; assignments = $assignAfter } | ConvertTo-Json -Depth 20 |
  Set-Content -LiteralPath (Join-Path $OutDir 'after.json') -Encoding utf8
[pscustomobject]@{ plan = $plan; collateralDiffs = $diffs; assignmentsUnchanged = $assignSame } | ConvertTo-Json -Depth 10 |
  Set-Content -LiteralPath (Join-Path $OutDir 'result.json') -Encoding utf8

Write-Output "COLLATERAL fields changed that were not requested: $($diffs.Count)"
foreach ($d in $diffs) { Write-Output "  $($d.Property): $(Format-Short $d.Before) -> $(Format-Short $d.After)" }
Write-Output "COLLATERAL assignments unchanged: $assignSame ($($assignBefore.Count) before, $($assignAfter.Count) after)"
Write-Output 'REMINDER: reload any Intune portal blade for this app before saving there, or it will re-send the old values.'
Write-Output "OUT_DIR=$OutDir"
if (@($todo | Where-Object { $_.result -notlike 'OK*' }).Count -gt 0) { exit 4 }
if ($diffs.Count -gt 0 -or -not $assignSame) { exit 5 }
exit 0
