#Requires -RunAsAdministrator
# Installs nano-sensor as a Windows service running under its own low-privilege
# virtual account, and records evidence that it really is locked down.
#
#   powershell -File tools\install_service.ps1 [-Evidence build\service-evidence.txt]
#   powershell -File tools\install_service.ps1 -Uninstall
#
# What it does, in order:
#   1. copies the binaries and CVE data to %ProgramFiles%\nano-sensor
#      (admin-writable only -- a service binary in a user-writable directory
#      is a privilege-escalation bug even when the service is unprivileged)
#   2. creates %ProgramData%\nano-sensor for dumps and logs, ACL'd to
#      SYSTEM + Administrators + the service SID only
#   3. registers the service as NT SERVICE\nano-sensor with one privilege
#   4. grants that account SELECT/INSERT on the database, nothing more
#   5. starts it and collects: sc qc / qprivs / qsidtype and `nsctl status`,
#      which reports the account, elevation and privileges the service runs
#      with. What its SQL login may do: tools\db\check_service_grants.ps1.
param(
    [string] $Config = 'RelWithDebInfo',
    [string] $Server = '.\SQLEXPRESS',
    [int] $Interval = 300,
    [string] $Evidence = '',
    [switch] $Uninstall
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $env:ProgramFiles 'nano-sensor'
$state = Join-Path $env:ProgramData 'nano-sensor'
$sqlcmd = if (Test-Path 'C:\Program Files\SqlCmd\sqlcmd.exe') { 'C:\Program Files\SqlCmd\sqlcmd.exe' } else { 'sqlcmd' }
$instance = ($Server -split '\\')[-1]
$sqlServer = "np:\\.\pipe\MSSQL`$$instance\sql\query"
$conn = "Driver={ODBC Driver 18 for SQL Server};Server=$Server;Database=nanosensor;Trusted_Connection=yes;Encrypt=no"
if (-not $Evidence) { $Evidence = Join-Path $root 'build\service-evidence.txt' }

function Log([string] $s) { Write-Host $s; Add-Content -Path $Evidence -Value $s -Encoding utf8 }
function Section([string] $s) { Log ''; Log "=== $s" }

if (Get-Service nano-sensor -ErrorAction SilentlyContinue) {
    Stop-Service nano-sensor -Force -ErrorAction SilentlyContinue
    & "$dest\nano-sensor.exe" service uninstall
    Start-Sleep 2
}
if ($Uninstall) { Write-Host 'uninstalled'; exit 0 }

Set-Content -Path $Evidence -Value "nano-sensor service evidence, $(Get-Date -Format s)" -Encoding utf8

Section 'copy binaries and data'
New-Item -ItemType Directory -Force "$dest\data" | Out-Null
Copy-Item "$root\build\bin\$Config\nano-sensor.exe", "$root\build\bin\$Config\nsctl.exe" $dest -Force
Copy-Item "$root\data\cve_index.tsv", "$root\data\cpe_aliases.tsv" "$dest\data" -Force
Log "copied to $dest"

Section 'register service'
& "$dest\nano-sensor.exe" service install --state-dir $state `
    --index "$dest\data\cve_index.tsv" --aliases "$dest\data\cpe_aliases.tsv" `
    --db $conn --interval $Interval 2>&1 | ForEach-Object { Log "$_" }

Section 'state directory ACL'
New-Item -ItemType Directory -Force "$state\dumps" | Out-Null
# Replace inherited ACEs (ProgramData lets Users create files) with exactly
# three principals. The service SID exists only now that the service does.
& icacls $state /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'NT SERVICE\nano-sensor:(OI)(CI)M' | Out-Null
& icacls $state 2>&1 | ForEach-Object { Log "$_" }

Section 'SQL Server login and grants'
& $sqlcmd -S $sqlServer -E -C -i "$root\tools\db\schema.sql" 2>&1 | ForEach-Object { Log "$_" }

Section 'start'
Start-Service nano-sensor
(Get-Service nano-sensor).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Log "status: $((Get-Service nano-sensor).Status)"
Start-Sleep 8   # one scan

Section 'sc qc nano-sensor'
& sc.exe qc nano-sensor 2>&1 | ForEach-Object { Log "$_" }
Section 'sc qprivs nano-sensor'
& sc.exe qprivs nano-sensor 2>&1 | ForEach-Object { Log "$_" }
Section 'sc qsidtype nano-sensor'
& sc.exe qsidtype nano-sensor 2>&1 | ForEach-Object { Log "$_" }

Section 'nsctl status (elevated caller)'
& "$dest\nsctl.exe" status 2>&1 | ForEach-Object { Log "$_" }

Section 'agent log (last lines)'
Get-Content "$state\agent.log" -Tail 6 -ErrorAction SilentlyContinue | ForEach-Object { Log "$_" }
Log ''
Log "evidence written to $Evidence"
