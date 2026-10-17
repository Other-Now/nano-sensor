# Leak check for the long-running process: N back-to-back scan cycles (each one
# a full inventory, CVE match, SQL Server transaction and pipe round-trip),
# sampling the agent's own memory and handle counts through `nsctl status`
# after every cycle.
#
#   powershell -File tools\mem_soak.ps1 [-Scans 300]
#
# A leak shows up as private bytes or handles that keep climbing after the
# first few cycles; a healthy process plateaus once its caches are warm.
# Writes build\memsoak\samples.csv and prints a summary.
param(
    [int] $Scans = 300,
    [string] $Config = 'RelWithDebInfo',
    [string] $Connection = 'Driver={ODBC Driver 18 for SQL Server};Server=.\SQLEXPRESS;Database=nanosensor;Trusted_Connection=yes;Encrypt=no'
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "build\bin\$Config"
$out = Join-Path $root 'build\memsoak'
New-Item -ItemType Directory -Force $out | Out-Null
$pipe = '\\.\pipe\ns-memsoak'

$agentArgs = @('run', '--db', "`"$Connection`"", '--interval', '1', '--pipe', $pipe,
    '--index', "$root\data\cve_index.tsv", '--aliases', "$root\data\cpe_aliases.tsv",
    '--log-file', "$out\agent.log", '--state-dir', "$out")
$agent = Start-Process -FilePath "$bin\nano-sensor.exe" -ArgumentList $agentArgs -PassThru -WindowStyle Hidden

$rows = @()
$last = -1
$deadline = (Get-Date).AddMinutes(30)
while ($last -lt $Scans -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 250
    $json = & "$bin\nsctl.exe" status --pipe $pipe 2>$null
    if ($LASTEXITCODE -ne 0) { continue }
    $s = $json | ConvertFrom-Json
    if ($s.scans_completed -eq $last) { continue }
    $last = $s.scans_completed
    $rows += [pscustomobject]@{
        scan = $s.scans_completed; private_bytes = $s.process.private_bytes
        working_set = $s.process.working_set; handles = $s.process.handles
        threads = $s.process.threads; db_ok = $s.last_scan.ok
    }
}
Stop-Process -Id $agent.Id -Force
$rows | Export-Csv -NoTypeInformation "$out\samples.csv"

$warm = $rows | Where-Object { $_.scan -ge 10 }
$first = $warm | Select-Object -First 1
$end = $rows | Select-Object -Last 1
$maxPriv = ($warm | Measure-Object private_bytes -Maximum).Maximum
$maxH = ($warm | Measure-Object handles -Maximum).Maximum
$failed = ($rows | Where-Object { -not $_.db_ok }).Count
"scans sampled           : $($rows.Count) (last scan #$($end.scan))"
"db writes failed        : $failed"
"private bytes @scan 10  : {0:N0}" -f $first.private_bytes
"private bytes @end      : {0:N0}" -f $end.private_bytes
"private bytes max (10+) : {0:N0}" -f $maxPriv
"growth 10 -> end        : {0:N0} bytes ({1:N2} KB/scan)" -f ($end.private_bytes - $first.private_bytes), (($end.private_bytes - $first.private_bytes) / 1KB / [math]::Max(1, $end.scan - $first.scan))
"handles @10 / end / max : $($first.handles) / $($end.handles) / $maxH"
"threads @10 / end       : $($first.threads) / $($end.threads)"
