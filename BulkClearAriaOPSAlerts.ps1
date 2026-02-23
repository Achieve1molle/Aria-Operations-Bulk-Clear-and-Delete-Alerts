<#
.SYNOPSIS
  Cancels ALL active alerts and deletes ALL canceled alerts in VMware Aria Operations 8.x.

.DESCRIPTION
  - Always bypasses TLS certificate validation (self-signed / untrusted root).
  - PowerShell 7+: uses Invoke-RestMethod -SkipCertificateCheck.
  - Windows PowerShell 5.1: uses ServerCertificateValidationCallback.
  - Flow:
      1) POST   /suite-api/api/auth/token/acquire         (get OpsToken)
      2) GET    /suite-api/api/alerts?page=&pageSize=     (list alerts, paged)
      3) POST   /suite-api/api/alerts?action=cancel       (bulk cancel active alerts)
      4) DELETE /suite-api/api/alerts/bulk                (bulk delete canceled alerts)

.NOTES
  API references:
    - Token: POST /suite-api/api/auth/token/acquire [1](https://community.broadcom.com/vmware-cloud-foundation/discussion/how-to-clear-operation-manger-alerts)[2](https://github.com/vmware-labs/hci-benchmark-appliance/blob/main/HCIBench_User_Guide.pdf)
    - List alerts: GET /suite-api/api/alerts [3](https://cliffcahill.com/2018/12/12/deploying-and-configuring-hci-bench/)
    - Bulk cancel: POST /suite-api/api/alerts?action=cancel 
    - Bulk delete canceled: DELETE /suite-api/api/alerts/bulk [4](https://knowledge.broadcom.com/external/article/389225/how-to-obtain-an-authentication-token-fo.html)
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$AriaOpsFqdnOrIp,

  # Prefer PSCredential so you don't put passwords in command history
  [Parameter(Mandatory=$false)]
  [pscredential]$Credential,

  # If you use AD/LDAP/vIDM auth sources, set this to the Authentication Source name in Aria Ops
  [Parameter(Mandatory=$false)]
  [string]$AuthSource = "LOCAL",

  [Parameter(Mandatory=$false)]
  [int]$PageSize = 1000,

  [Parameter(Mandatory=$false)]
  [int]$CancelBatchSize = 500
)

# -------------------------------
# Always bypass TLS validation
# -------------------------------
$ErrorActionPreference = 'Stop'

# Ensure modern TLS
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if ($PSVersionTable.PSVersion.Major -lt 7) {
  # Windows PowerShell 5.1 (ServicePointManager path)
  try {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public static class TrustAllCerts {
  public static bool Validate(object sender, X509Certificate cert, X509Chain chain, System.Net.Security.SslPolicyErrors errors) { return true; }
}
"@ -ErrorAction Stop
  } catch {}
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($sender,$cert,$chain,$errors) return $true }
}

# Common Invoke-RestMethod options; PS7 supports -SkipCertificateCheck directly
$irmCommon = @{
  ErrorAction = 'Stop'
}
if ($PSVersionTable.PSVersion.Major -ge 7) {
  $irmCommon.SkipCertificateCheck = $true
}

# -------------------------------
# Credential prompt (if not provided)
# -------------------------------
if (-not $Credential) {
  $Credential = Get-Credential -Message "Enter Aria Operations credentials"
}

$base = "https://$AriaOpsFqdnOrIp"

# -------------------------------
# Helper: Invoke REST with consistent options
# -------------------------------
function Invoke-AriaRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('GET','POST','DELETE','PUT','PATCH')]
    [string]$Method,

    [Parameter(Mandatory=$true)]
    [string]$Uri,

    [hashtable]$Headers,

    [string]$ContentType,

    [object]$Body
  )

  $params = @{
    Method = $Method
    Uri    = $Uri
  }

  if ($Headers)     { $params.Headers     = $Headers }
  if ($ContentType) { $params.ContentType = $ContentType }
  if ($null -ne $Body) { $params.Body = $Body }

  return Invoke-RestMethod @params @irmCommon
}

# -------------------------------
# 1) Acquire OpsToken
# -------------------------------
$tokenUri = "$base/suite-api/api/auth/token/acquire"
$tokenBodyObj = @{
  username   = $Credential.UserName
  password   = $Credential.GetNetworkCredential().Password
  authSource = $AuthSource
}
$tokenBodyJson = $tokenBodyObj | ConvertTo-Json

Write-Host "Acquiring token from $tokenUri ..."
$tokenResp = Invoke-AriaRest -Method POST -Uri $tokenUri -ContentType "application/json" -Body $tokenBodyJson
$opsToken  = $tokenResp.token

if (-not $opsToken) {
  throw "Failed to acquire OpsToken (no token returned)."
}

# Per docs, "OpsToken <token>" is the current header format (legacy vRealizeOpsToken is also supported). [2](https://github.com/vmware-labs/hci-benchmark-appliance/blob/main/HCIBench_User_Guide.pdf)[6](https://cliffcahill.com/2018/12/12/hci-bench-parameter-file/)
$headers = @{
  "Accept"        = "application/json"
  "Content-Type"  = "application/json"
  "Authorization" = "OpsToken $opsToken"
}

# -------------------------------
# 2) Get ALL alerts (paged)
# -------------------------------
function Get-AllAlerts {
  param(
    [hashtable]$Headers,
    [string]$Base,
    [int]$PageSize
  )

  $all = New-Object System.Collections.Generic.List[object]
  $page = 0
  $total = $null

  while ($true) {
    $uri = "$Base/suite-api/api/alerts?page=$page&pageSize=$PageSize"
    Write-Host "Fetching alerts page=$page pageSize=$PageSize ..."
    $resp = Invoke-AriaRest -Method GET -Uri $uri -Headers $Headers

    if ($resp.alerts) {
      foreach ($a in $resp.alerts) { $all.Add($a) }
    }

    if ($null -eq $total -and $resp.pageInfo -and $resp.pageInfo.totalCount -ne $null) {
      $total = [int]$resp.pageInfo.totalCount
      Write-Host "Total alerts reported by API: $total"
    }

    $page++

    # Stop conditions:
    # - If API provides totalCount, stop when we have them all.
    # - Otherwise stop when a page returns no alerts.
    if ($null -ne $total) {
      if ($all.Count -ge $total) { break }
    } else {
      if (-not $resp.alerts -or $resp.alerts.Count -eq 0) { break }
    }

    # Safety: avoid infinite loops if server behaves unexpectedly
    if ($page -gt 2000) { throw "Aborting: exceeded 2000 pages while fetching alerts." }
  }

  return $all
}

$alerts = Get-AllAlerts -Headers $headers -Base $base -PageSize $PageSize

# Filter ACTIVE alerts; response includes "status" and "alertId" fields. [3](https://cliffcahill.com/2018/12/12/deploying-and-configuring-hci-bench/)
$activeIds = @()
foreach ($a in $alerts) {
  $status = "$($a.status)"
  if ($status -and $status.Trim().ToUpper() -eq "ACTIVE") {
    if ($a.alertId) { $activeIds += $a.alertId }
    elseif ($a.id)  { $activeIds += $a.id }  # fallback
  }
}

Write-Host "Found ACTIVE alerts: $($activeIds.Count)"

# -------------------------------
# 3) Bulk CANCEL active alerts (chunked)
# -------------------------------
function Invoke-InBatches {
  param(
    [string[]]$Items,
    [int]$BatchSize,
    [scriptblock]$Action
  )

  if (-not $Items -or $Items.Count -eq 0) { return }

  for ($i = 0; $i -lt $Items.Count; $i += $BatchSize) {
    $end = [Math]::Min($i + $BatchSize - 1, $Items.Count - 1)
    $batch = $Items[$i..$end]
    & $Action $batch ([int]($i / $BatchSize) + 1)
  }
}

$cancelUri = "$base/suite-api/api/alerts?action=cancel"  # modify alerts supports cancel action 

if ($activeIds.Count -gt 0) {
  Invoke-InBatches -Items $activeIds -BatchSize $CancelBatchSize -Action {
    param($batch, $batchNum)

    $body = @{ uuids = $batch } | ConvertTo-Json -Depth 5
    Write-Host "Canceling batch #$batchNum (count=$($batch.Count)) ..."
    Invoke-AriaRest -Method POST -Uri $cancelUri -Headers $headers -ContentType "application/json" -Body $body | Out-Null
  }
  Write-Host "Cancel requests submitted."
} else {
  Write-Host "No ACTIVE alerts to cancel."
}

# -------------------------------
# 4) Bulk DELETE all CANCELED alerts
# -------------------------------
# KB shows DELETE /api/alerts/bulk with an alert-query filtering on CANCELLED. [4](https://knowledge.broadcom.com/external/article/389225/how-to-obtain-an-authentication-token-fo.html)
$deleteUri = "$base/suite-api/api/alerts/bulk"

function Try-BulkDeleteCanceled {
  param([string]$StatusValue)

  $deleteBody = @{
    "alert-query" = @{
      alertStatus = @{
        alertStatus = $StatusValue
      }
    }
  } | ConvertTo-Json -Depth 10

  Write-Host "Deleting canceled alerts where alertStatus='$StatusValue' ..."
  Invoke-AriaRest -Method DELETE -Uri $deleteUri -Headers $headers -ContentType "application/json" -Body $deleteBody | Out-Null
}

try {
  # Try the KB-documented value first
  Try-BulkDeleteCanceled -StatusValue "CANCELLED"
  Write-Host "Bulk delete completed (CANCELLED)."
} catch {
  # Some environments may accept CANCELED (one-L) depending on implementation; retry once.
  Write-Warning "Bulk delete using 'CANCELLED' failed: $($_.Exception.Message)"
  Write-Warning "Retrying with 'CANCELED' ..."
  Try-BulkDeleteCanceled -StatusValue "CANCELED"
  Write-Host "Bulk delete completed (CANCELED)."
}

Write-Host "Done."