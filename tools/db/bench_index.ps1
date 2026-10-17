# Measures the fleet-wide "which hosts have CVE-X?" query with and without
# IX_findings_cve, plus what the index costs on the write path.
#
#   powershell -File tools\db\bench_index.ps1 [-Hosts 5000] [-Config RelWithDebInfo]
#
# Needs a login that can CREATE/DROP INDEX on nanosensor (the installing
# admin; the service's own login cannot, by design). Writes results to
# build\dbbench\. See docs/SQL_SERVER.md for what the numbers mean.
param(
    [int] $Hosts = 5000,
    [int] $InsertHosts = 300,
    [string] $Config = 'RelWithDebInfo',
    [string] $Server = '.\SQLEXPRESS'
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$bench = Join-Path $root "build\bin\$Config\ns_dbbench.exe"
$out = Join-Path $root 'build\dbbench'
New-Item -ItemType Directory -Force $out | Out-Null
$conn = "Driver={ODBC Driver 18 for SQL Server};Server=$Server;Database=nanosensor;Trusted_Connection=yes;Encrypt=no"
# go-sqlcmd cannot use shared memory against a named instance; the named-pipe
# address works without the SQL Browser service.
$instance = ($Server -split '\\')[-1]
$sqlcmdServer = "np:\\.\pipe\MSSQL`$$instance\sql\query"
$cves = Join-Path $out 'cves.txt'

$sqlcmd = if (Test-Path 'C:\Program Files\SqlCmd\sqlcmd.exe') { 'C:\Program Files\SqlCmd\sqlcmd.exe' } else { 'sqlcmd' }

function Sql([string] $q) {
    & $sqlcmd -S $sqlcmdServer -E -C -d nanosensor -b -Q $q
}

function Plan([string] $label) {
    $cve = (Get-Content $cves)[-1]   # the most widespread CVE in the set
    $q = "SET SHOWPLAN_TEXT ON;`nGO`nSELECT h.hostname, f.cve_id, f.package_name, f.package_version, f.cvss, f.severity, f.exposed, f.scan_id FROM dbo.findings f JOIN dbo.hosts h ON h.latest_scan_id = f.scan_id WHERE f.cve_id = '$cve' ORDER BY h.hostname;`nGO"
    $q | Set-Content -Encoding ascii "$out\plan.sql"
    & $sqlcmd -S $sqlcmdServer -E -C -d nanosensor -i "$out\plan.sql" -W | Out-File -Encoding utf8 "$out\plan-$label.txt"
    Write-Host "  plan ($cve) -> $out\plan-$label.txt"
}

$existing = [int]((Sql "SET NOCOUNT ON; SELECT COUNT(*) FROM dbo.hosts WHERE hostname LIKE 'bench-[0-9]%'" | Select-Object -Last 1).Trim())
if ($existing -lt $Hosts) {
    Write-Host "== loading $($Hosts - $existing) synthetic hosts (have $existing)"
    Sql "DROP INDEX IF EXISTS IX_findings_cve ON dbo.findings" | Out-Null
    & $bench load --db $conn --hosts $Hosts --seed 42 --index "$root\data\cve_index.tsv" --aliases "$root\data\cpe_aliases.tsv" | Tee-Object "$out\load.json"
} else {
    Write-Host "== fleet already loaded ($existing hosts)"
}

Write-Host '== WITHOUT IX_findings_cve'
Sql "DROP INDEX IF EXISTS IX_findings_cve ON dbo.findings" | Out-Null
Remove-Item $cves -ErrorAction SilentlyContinue
& $bench measure --db $conn --cves-file $cves --queries 30 --repeat 9 2> "$out\measure-before.txt" | Tee-Object "$out\before.json"
Plan 'before'


Write-Host '== CREATE INDEX'
$t = Measure-Command {
    Sql "CREATE INDEX IX_findings_cve ON dbo.findings (cve_id) INCLUDE (scan_id, package_name, package_version, cvss, severity, exposed)" | Out-Null
}
"{`"create_index_s`":$([math]::Round($t.TotalSeconds, 2))}" | Tee-Object "$out\create-index.json"

Write-Host '== WITH IX_findings_cve'
& $bench measure --db $conn --cves-file $cves --queries 30 --repeat 9 2> "$out\measure-after.txt" | Tee-Object "$out\after.json"
Plan 'after'

# Write cost, measured last so both read measurements saw the same table.
# Same host count and generator, different hosts; index on, then off.
Write-Host '== write cost: insert with the index, then without'
& $bench insert --db $conn --hosts $InsertHosts --tag idx --index "$root\data\cve_index.tsv" --aliases "$root\data\cpe_aliases.tsv" 2>$null | Tee-Object "$out\insert-with-index.json"
Sql "DROP INDEX IX_findings_cve ON dbo.findings" | Out-Null
& $bench insert --db $conn --hosts $InsertHosts --tag noidx --index "$root\data\cve_index.tsv" --aliases "$root\data\cpe_aliases.tsv" 2>$null | Tee-Object "$out\insert-without-index.json"
Sql "CREATE INDEX IX_findings_cve ON dbo.findings (cve_id) INCLUDE (scan_id, package_name, package_version, cvss, severity, exposed)" | Out-Null
Write-Host '== done; IX_findings_cve left in place'
