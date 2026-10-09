#Requires -Version 7.2
<#
.SYNOPSIS
  Exports per-device results for every Intune Remediations script package that has run data: one CSV per
  package. Packages with no run data are listed and skipped. Read-only.

.DESCRIPTION
  1. GET beta/deviceManagement/deviceHealthScripts, following @odata.nextLink.
  2. For each package, GET beta/deviceManagement/deviceHealthScripts/{id}/deviceRunStates?$expand=managedDevice,
     following @odata.nextLink.
  3. Write RemediationExport_<package>_<date>.csv with device name, primary user, detection and remediation
     state, last update time, and the detection output and error text the script wrote.

  The admin center shows these per package, one screen at a time. This pulls all of them at once so the
  script output (which is where a well-written remediation explains itself) can be read side by side.

  The CSVs contain device names and user principal names. They go to an output folder that .gitignore excludes.

.EXAMPLE
  pwsh -File tools/Export-RemediationRunStates.ps1 -TenantId contoso.onmicrosoft.com
.EXAMPLE
  pwsh -File tools/Export-RemediationRunStates.ps1 -TenantId contoso.onmicrosoft.com -NameLike '*Agent*'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [string] $NameLike = '*',
  [string] $OutDir
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')

if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "remediation-export-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile IntuneRead -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken

$stamp = Get-Date -Format 'yyyy-MM-dd'
$scripts = @(Get-GraphPaged -Uri 'beta/deviceManagement/deviceHealthScripts?$select=id,displayName,publisher,version,lastModifiedDateTime') |
  Where-Object { $_.displayName -like $NameLike }
Write-Output "Found $($scripts.Count) remediation package(s) matching '$NameLike'"

# Collect the index in a list: anything a foreach emits would be captured, and the progress lines would vanish.
$index = [System.Collections.Generic.List[object]]::new()
foreach ($s in $scripts) {
  $uri = "beta/deviceManagement/deviceHealthScripts/$($s.id)/deviceRunStates?`$expand=managedDevice"
  $rows = foreach ($r in @(Get-GraphPaged -Uri $uri)) {
    $md = Get-PropValue $r 'managedDevice'
    [pscustomobject]@{
      DeviceName        = Get-PropValue $md 'deviceName'
      UserPrincipalName = Get-PropValue $md 'userPrincipalName'
      DetectionState    = Get-PropValue $r 'detectionState'
      RemediationState  = Get-PropValue $r 'remediationState'
      LastStateUpdate   = Get-PropValue $r 'lastStateUpdateDateTime'
      DetectionOutput   = Get-PropValue $r 'preRemediationDetectionScriptOutput'
      DetectionError    = Get-PropValue $r 'preRemediationDetectionScriptError'
      PostDetectOutput  = Get-PropValue $r 'postRemediationDetectionScriptOutput'
      RemediationError  = Get-PropValue $r 'remediationScriptError'
    }
  }
  $rows = @($rows)
  $file = $null
  if ($rows.Count -gt 0) {
    $file = Join-Path $OutDir ("RemediationExport_{0}_{1}.csv" -f (ConvertTo-SafeFileName $s.displayName), $stamp)
    $rows | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding utf8
    Write-Output ('{0}: {1} rows' -f $s.displayName, $rows.Count)
  } else {
    Write-Output ('{0}: no run data, skipped' -f $s.displayName)
  }
  $index.Add([pscustomobject]@{
    package          = $s.displayName
    id               = $s.id
    rows             = $rows.Count
    detectionFail    = @($rows | Where-Object DetectionState -eq 'fail').Count
    remediationFixed = @($rows | Where-Object RemediationState -eq 'success').Count
    file             = $file
  })
}
ConvertTo-Json -InputObject $index.ToArray() -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir 'index.json') -Encoding utf8
Write-Output "OUT_DIR=$OutDir"
