#Requires -Version 7.2
<#
.SYNOPSIS
  Exports every Windows Autopilot device identity to CSV, with the fields that matter when a device goes
  missing. Read-only.

.DESCRIPTION
  GET beta/deviceManagement/windowsAutopilotDeviceIdentities, following @odata.nextLink.
  Columns: serial, model, manufacturer, group tag, enrollment state, last contacted, profile assignment status,
  the Intune managedDeviceId the identity points at, and the Entra device id.

  The useful join: an identity whose managedDeviceId no longer exists in Intune has lost its Intune record
  (deleted by an admin or by a cleanup rule) while Autopilot still knows the hardware. -CheckManagedDevice
  pulls the managed device ids once and flags those rows.

.EXAMPLE
  pwsh -File recipes/Export-AutopilotIdentities.ps1 -TenantId contoso.onmicrosoft.com -CheckManagedDevice
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [switch] $CheckManagedDevice,
  [string] $OutDir
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "autopilot-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile IntuneRead -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken

$ids = @(Get-GraphPaged -Uri 'beta/deviceManagement/windowsAutopilotDeviceIdentities' -MaxPages 500)
$managed = $null
if ($CheckManagedDevice) {
  $managed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($m in @(Get-GraphPaged -Uri 'v1.0/deviceManagement/managedDevices?$select=id' -MaxPages 500)) { [void]$managed.Add([string]$m.id) }
}
$empty = '00000000-0000-0000-0000-000000000000'
$rows = foreach ($i in $ids) {
  $mid = [string](Get-PropValue $i 'managedDeviceId')
  [pscustomobject]@{
    SerialNumber                      = Get-PropValue $i 'serialNumber'
    Model                             = Get-PropValue $i 'model'
    Manufacturer                      = Get-PropValue $i 'manufacturer'
    GroupTag                          = Get-PropValue $i 'groupTag'
    EnrollmentState                   = Get-PropValue $i 'enrollmentState'
    LastContacted                     = Get-PropValue $i 'lastContactedDateTime'
    DeploymentProfileAssignmentStatus = Get-PropValue $i 'deploymentProfileAssignmentStatus'
    ManagedDeviceId                   = $mid
    EntraDeviceId                     = Get-PropValue $i 'azureActiveDirectoryDeviceId'
    ManagedDeviceMissing              = $(if ($null -ne $managed -and $mid -and $mid -ne $empty) { -not $managed.Contains($mid) } else { $null })
  }
}
$file = Join-Path $OutDir "autopilot-identities-$(Get-Date -Format yyyy-MM-dd).csv"
@($rows) | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding utf8
Write-Output "Exported $(@($rows).Count) Autopilot identities to $file"
if ($CheckManagedDevice) { Write-Output "Identities pointing at a managed device that no longer exists: $(@($rows | Where-Object ManagedDeviceMissing).Count)" }
