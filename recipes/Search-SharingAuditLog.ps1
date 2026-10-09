#Requires -Version 7.2
<#
.SYNOPSIS
  Who shared what, with whom: SharePoint and OneDrive sharing events from the unified audit log, paged properly.
  Read-only. Needs an Exchange Online session already connected in this process.

.DESCRIPTION
  Search-UnifiedAuditLog returns 100 records by default and at most 5,000 per call. -SessionCommand
  ReturnLargeSet raises the ceiling to 50,000, but only if every call reuses the same -SessionId and you keep
  calling until the set is exhausted. One call with ReturnLargeSet and no loop still stops at 5,000. I hit
  exactly that wall on a per-user pull, then wrote a SessionId paging loop; its rewrite is Invoke-UalPagedSearch
  in lib/AgentGraph.psm1.
  For bulk or recurring pulls, the Office 365 Management Activity API is the better tool.

  For each record type, the AuditData JSON is flattened into: time, actor, operation, site, file, target user
  or group, target type, sharing event data and client IP. -SiteUrl filters locally on the object URL.

  Connect first, for example:
    $t = Get-AgentAccessToken -TenantId <tenant> -AuthProfile Exchange -CacheOnly
    Connect-AgentExchange -AccessToken $t.AccessToken -UserPrincipalName <admin upn>
  or run this as a step in tools/Start-QueueWorker.ps1 with -ExchangeUserPrincipalName.

.EXAMPLE
  pwsh -File recipes/Search-SharingAuditLog.ps1 -StartDate (Get-Date).AddDays(-14) -SiteUrl 'https://contoso.sharepoint.com/sites/Finance'
#>
[CmdletBinding()]
param(
  [datetime] $StartDate = (Get-Date).AddDays(-7),
  [datetime] $EndDate = (Get-Date),
  [string[]] $UserIds,
  [string] $SiteUrl,
  [ValidateSet('SharePointSharingOperation', 'SharePointFileOperation', 'SharePoint')][string[]] $RecordType = @('SharePointSharingOperation'),
  [string[]] $Operations,
  [ValidateRange(1, 50000)][int] $MaxRecords = 50000,
  [string] $OutDir
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
  throw 'No Exchange Online session in this process. Connect with Connect-AgentExchange (auth/DeviceCodeAuth.psm1) first.'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "ual-sharing-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$all = [System.Collections.Generic.List[object]]::new()
foreach ($rt in $RecordType) {
  $filters = @{ StartDate = $StartDate; EndDate = $EndDate; RecordType = $rt }
  if ($UserIds) { $filters.UserIds = $UserIds }
  if ($Operations) { $filters.Operations = $Operations }
  $res = Invoke-UalPagedSearch -MaxRecords $MaxRecords -SearchBlock {
    param($sid)
    Search-UnifiedAuditLog @filters -SessionId $sid -SessionCommand ReturnLargeSet -ResultSize 5000
  }.GetNewClosure()
  Write-Output "$rt : $($res.Records.Count) records (service reported $($res.ResultCount))"
  foreach ($r in $res.Records) { $all.Add($r) }
}

$rows = foreach ($r in $all) {
  $d = $r.AuditData | ConvertFrom-Json -Depth 20
  [pscustomobject]@{
    CreationTimeUtc       = Get-PropValue $d 'CreationTime'
    Actor                 = Get-PropValue $d 'UserId'
    Operation             = Get-PropValue $d 'Operation'
    SiteUrl               = Get-PropValue $d 'SiteUrl'
    ObjectId              = Get-PropValue $d 'ObjectId'
    SourceFileName        = Get-PropValue $d 'SourceFileName'
    TargetUserOrGroupName = Get-PropValue $d 'TargetUserOrGroupName'
    TargetUserOrGroupType = Get-PropValue $d 'TargetUserOrGroupType'
    EventData             = Get-PropValue $d 'EventData'
    ClientIP              = Get-PropValue $d 'ClientIP'
    RecordType            = $r.RecordType
  }
}
$rows = @($rows)
if ($SiteUrl) { $rows = @($rows | Where-Object { $_.ObjectId -like "$SiteUrl*" -or $_.SiteUrl -like "$SiteUrl*" }) }
$rows = @($rows | Sort-Object CreationTimeUtc)
$file = Join-Path $OutDir 'sharing-events.csv'
$rows | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding utf8
Write-Output "Wrote $($rows.Count) events to $file"
$rows | Group-Object Operation | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize | Out-String | Write-Output
$rows | Where-Object TargetUserOrGroupType | Group-Object TargetUserOrGroupType | Select-Object Count, Name | Format-Table -AutoSize | Out-String | Write-Output
