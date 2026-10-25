param(
    [string]$FastLog,
    [string]$OutputCsv
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($FastLog)) {
    $FastLog = Join-Path $projectRoot "logs\fast.log"
}
if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    $OutputCsv = Join-Path $projectRoot "alert_summary.csv"
}

if (-not (Test-Path -LiteralPath $FastLog)) {
    throw "fast.log not found: $FastLog"
}

$alerts = foreach ($line in Get-Content -LiteralPath $FastLog) {
    if ($line.Contains("NIDS TEST - ICMP traffic detected")) {
        $parts = $line -split '\s+'
        [PSCustomObject]@{
            Timestamp   = $parts[0]
            SID         = "1000001"
            Message     = "NIDS TEST - ICMP traffic detected"
            Protocol    = "ICMP"
            Source      = "See RawAlert"
            Destination = "See RawAlert"
            RawAlert    = $line
        }
    }
}

if (-not $alerts) {
    Write-Warning "No matching custom ICMP alerts found in $FastLog"
    exit 0
}

$alerts | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "Exported $(@($alerts).Count) matching alerts to: $OutputCsv"
