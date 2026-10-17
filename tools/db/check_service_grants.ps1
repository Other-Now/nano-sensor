# Proves what the service's SQL login can and cannot do, by impersonating it
# (EXECUTE AS LOGIN) from an admin's session. Run as the sysadmin that ran
# schema.sql; no elevation needed.
#
#   powershell -File tools\db\check_service_grants.ps1
param([string] $Server = '.\SQLEXPRESS')
$sqlcmd = if (Test-Path 'C:\Program Files\SqlCmd\sqlcmd.exe') { 'C:\Program Files\SqlCmd\sqlcmd.exe' } else { 'sqlcmd' }
$instance = ($Server -split '\\')[-1]
$probe = @"
SET NOCOUNT ON;
EXECUTE AS LOGIN = 'NT SERVICE\nano-sensor';
SELECT SUSER_SNAME() AS acting_as, COUNT_BIG(*) AS findings_visible FROM dbo.findings;
BEGIN TRY INSERT dbo.hosts (hostname, last_seen) VALUES ('grant-probe', SYSUTCDATETIME()); PRINT 'INSERT: allowed (expected)'; END TRY
BEGIN CATCH PRINT 'INSERT: denied (UNEXPECTED) -- ' + ERROR_MESSAGE(); END CATCH
BEGIN TRY DELETE TOP (1) FROM dbo.findings; PRINT 'DELETE: allowed (BAD)'; END TRY
BEGIN CATCH PRINT 'DELETE: denied -- ' + ERROR_MESSAGE(); END CATCH
BEGIN TRY EXEC('DROP TABLE dbo.findings'); PRINT 'DROP: allowed (BAD)'; END TRY
BEGIN CATCH PRINT 'DROP: denied -- ' + ERROR_MESSAGE(); END CATCH
BEGIN TRY EXEC('CREATE TABLE dbo.x (i int)'); PRINT 'CREATE TABLE: allowed (BAD)'; END TRY
BEGIN CATCH PRINT 'CREATE TABLE: denied -- ' + ERROR_MESSAGE(); END CATCH
REVERT;
DELETE FROM dbo.hosts WHERE hostname = 'grant-probe';
"@
$f = Join-Path $env:TEMP 'ns-grant-probe.sql'
$probe | Set-Content -Encoding ascii $f
& $sqlcmd -S "np:\\.\pipe\MSSQL`$$instance\sql\query" -E -C -d nanosensor -i $f -W
