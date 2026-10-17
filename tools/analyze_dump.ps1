# Runs cdb (the console engine behind WinDbg) over a minidump with this
# build's PDBs and prints just the answer, without the banner noise.
#
#   powershell -File tools\analyze_dump.ps1 -Dump <file.dmp> [-Config Debug] [-Commands "..."]
#
# The default command set is the standard first look at any crash dump:
# jump to the exception context, show the faulting instruction, the stack with
# source lines, and the locals of the faulting frame. Microsoft's public symbol
# server supplies the PDBs for ntdll/kernel32; this repo's PDBs come from the
# build directory, and must be the ones built with the binary that crashed.
param(
    [Parameter(Mandatory)] [string] $Dump,
    [string] $Config = 'Debug',
    [string] $Commands = '.ecxr; r; kn 12; .frame 0; dv /t',
    [string] $Cdb = ''
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Cdb) {
    $pkg = Get-AppxPackage Microsoft.WinDbg -ErrorAction SilentlyContinue
    if ($pkg) { $Cdb = Join-Path $pkg.InstallLocation 'amd64\cdb.exe' }
    if (-not $Cdb -or -not (Test-Path $Cdb)) {
        throw 'cdb.exe not found. Install WinDbg (winget install Microsoft.WinDbg) or pass -Cdb.'
    }
}
$bin = Join-Path $root "build\bin\$Config"
$symcache = Join-Path $env:LOCALAPPDATA 'symcache'
$sym = "$bin;srv*$symcache*https://msdl.microsoft.com/download/symbols"

$out = & $Cdb -z $Dump -y $sym -i $bin -srcpath $root -lines -c "$Commands; q" 2>&1
# Keep from the first command echo onward; drop the extension-gallery and
# NatVis chatter that every cdb session prints.
$started = $false
foreach ($line in $out) {
    $s = "$line"
    if (-not $started) {
        if ($s -match 'This dump file has an exception|^\(\w+\.\w+\):|Reading initial command') { $started = $true }
        else { continue }
    }
    if ($s -match 'NatVis script|Whitespace at start of path|^quit:|Unable to verify checksum') { continue }
    $s
}
