# Reproduces one of the planted bugs from docs/DEBUGGING.md and collects the
# minidump it produces.
#
#   powershell -File tools\repro_fault.ps1 -Fault uaf|deadlock|worker-crash
#
# Uses the Debug build: the debug CRT fills freed memory with 0xDD, which is
# what makes the use-after-free crash deterministically (and recognisably).
# Runs the agent in the foreground, not as the service, so no elevation needed.
param(
    [Parameter(Mandatory)] [ValidateSet('uaf', 'deadlock', 'worker-crash')] [string] $Fault,
    [string] $Config = 'Debug',
    [string] $Connection = 'Driver={ODBC Driver 18 for SQL Server};Server=.\SQLEXPRESS;Database=nanosensor;Trusted_Connection=yes;Encrypt=no'
)
# Not 'Stop': in Windows PowerShell 5.1 that turns nsctl's stderr into a
# terminating error, and 'no server yet' is an expected answer while polling.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "build\bin\$Config"
$state = Join-Path $root "build\faults\$Fault"
$pipe = "\\.\pipe\ns-fault-$Fault"
if (Test-Path $state) { Remove-Item -Recurse -Force $state }

$agentArgs = @('run', '--db', "`"$Connection`"", '--state-dir', $state, '--log-file', "$state\agent.log",
    '--index', "$root\data\cve_index.tsv", '--aliases', "$root\data\cpe_aliases.tsv",
    '--interval', '3600', '--pipe', $pipe, '--inject-fault', $Fault, '--hang-timeout', '10')
$agent = Start-Process -FilePath "$bin\nano-sensor.exe" -ArgumentList $agentArgs -PassThru -WindowStyle Hidden
Write-Host "agent pid $($agent.Id), fault=$Fault"

switch ($Fault) {
    'uaf' {
        Start-Sleep 6   # let the startup scan finish
        # Wait 1 s for a scan that the fault makes take 3 s: the request
        # gives up, frees its waiter, and the worker calls into it later.
        & "$bin\nsctl.exe" scan 1000 --pipe $pipe
    }
    'deadlock' {
        # The startup scan holds the DB lock for 3 s and then wants the state
        # lock; `status` takes the state lock and then wants the DB lock.
        # Wait for the pipe (the Debug build takes a few seconds to load the
        # CVE index), then land `status` inside the 3 s window.
        for ($i = 0; $i -lt 100; $i++) {
            & "$bin\nsctl.exe" ping --pipe $pipe 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { break }
            Start-Sleep -Milliseconds 100
        }
        Start-Sleep -Milliseconds 1500
        & "$bin\nsctl.exe" status --pipe $pipe --timeout 3000
        Write-Host "nsctl gave up after its 3 s timeout; the agent's watchdog fires at 10 s"
    }
    'worker-crash' { }
}

if (-not $agent.WaitForExit(30000)) {
    Write-Host 'agent still running after 30 s -- the fault did not fire'
    Stop-Process -Id $agent.Id
    exit 1
}
Write-Host ("agent exited with 0x{0:X8}" -f $agent.ExitCode)
Write-Host '--- last log lines'
Get-Content "$state\agent.log" | Select-Object -Last 4
Write-Host '--- dumps'
Get-ChildItem "$state\dumps" -Filter *.dmp | ForEach-Object { "$($_.FullName)  ($([int]($_.Length/1KB)) KB)" }
