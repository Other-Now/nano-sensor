#Requires -RunAsAdministrator
# Copies the service's dumps and log out of its locked-down state directory
# (readable only by SYSTEM, Administrators and the service itself) so they can
# be analysed with tools\analyze_dump.ps1 from a normal shell.
#
#   powershell -File tools\collect_service_state.ps1 [-Out build\service-state]
param([string] $Out = '')
$root = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $root 'build\service-state' }
$state = Join-Path $env:ProgramData 'nano-sensor'
New-Item -ItemType Directory -Force $Out | Out-Null
Copy-Item "$state\agent.log" $Out -Force -ErrorAction SilentlyContinue
Copy-Item "$state\dumps\*.dmp" $Out -Force -ErrorAction SilentlyContinue
# Copies inherit the destination's ACL, so the originals stay locked down.
& "$env:ProgramFiles\nano-sensor\nsctl.exe" status --timeout 60000 *> "$Out\nsctl-status-elevated.txt"
Get-ChildItem $Out | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host
