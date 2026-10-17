-- nano-sensor schema for SQL Server (Express is enough).
--
-- Run once, as an administrator:
--   sqlcmd -S .\SQLEXPRESS -E -C -i tools\db\schema.sql
--
-- Idempotent: re-running it leaves an existing database alone.

IF DB_ID(N'nanosensor') IS NULL CREATE DATABASE nanosensor;
GO
-- Express creates databases with AUTO_CLOSE ON: when the last connection
-- closes, the database shuts down and its pages leave the buffer pool. The
-- next query then runs cold. Measured on the installed service: a
-- COUNT_BIG(*) over 1.16M findings took 163 s cold vs 0.4 s warm, long enough
-- for the hang watchdog to restart the service (docs/SERVICE.md).
ALTER DATABASE nanosensor SET AUTO_CLOSE OFF;
GO
USE nanosensor;
GO

IF OBJECT_ID(N'dbo.hosts') IS NULL
CREATE TABLE dbo.hosts (
    host_id        int IDENTITY       NOT NULL CONSTRAINT PK_hosts PRIMARY KEY,
    hostname       nvarchar(255)      NOT NULL CONSTRAINT UQ_hosts_hostname UNIQUE,
    os_name        nvarchar(128)      NULL,
    os_version     nvarchar(64)       NULL,
    last_seen      datetime2(3)       NOT NULL,
    -- Denormalised pointer to the newest scan. "Current exposure" queries join
    -- on this instead of MAX(scan_id) per host, which would be a second
    -- aggregate over every scan a host has ever reported.
    latest_scan_id bigint             NULL
);
GO

IF OBJECT_ID(N'dbo.scans') IS NULL
CREATE TABLE dbo.scans (
    scan_id        bigint IDENTITY    NOT NULL CONSTRAINT PK_scans PRIMARY KEY,
    host_id        int                NOT NULL CONSTRAINT FK_scans_hosts REFERENCES dbo.hosts(host_id),
    collected_at   datetime2(3)       NOT NULL,
    agent_version  varchar(32)        NOT NULL,
    package_count  int                NOT NULL,
    finding_count  int                NOT NULL
);
GO

-- The inventory: every installed package, per scan.
IF OBJECT_ID(N'dbo.packages') IS NULL
CREATE TABLE dbo.packages (
    scan_id        bigint             NOT NULL CONSTRAINT FK_packages_scans REFERENCES dbo.scans(scan_id),
    package_id     int                NOT NULL,
    name           nvarchar(400)      NOT NULL,
    version        nvarchar(128)      NOT NULL,
    vendor         nvarchar(256)      NOT NULL,
    source         varchar(32)        NOT NULL,
    CONSTRAINT PK_packages PRIMARY KEY (scan_id, package_id)
);
GO

IF OBJECT_ID(N'dbo.findings') IS NULL
CREATE TABLE dbo.findings (
    finding_id     bigint IDENTITY    NOT NULL CONSTRAINT PK_findings PRIMARY KEY,
    scan_id        bigint             NOT NULL CONSTRAINT FK_findings_scans REFERENCES dbo.scans(scan_id),
    cve_id         varchar(32)        NOT NULL,
    package_name   nvarchar(400)      NOT NULL,
    package_version nvarchar(128)     NOT NULL,
    cvss           decimal(3,1)       NOT NULL,
    severity       varchar(10)        NOT NULL,
    exposed        bit                NOT NULL
);
GO

-- SQL Server does not index foreign keys on its own. Without this, "findings
-- for this host's latest scan" (nsctl findings) scans the whole table.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_findings_scan')
CREATE INDEX IX_findings_scan ON dbo.findings (scan_id);
GO

-- NOTE: IX_findings_cve -- the index for "which hosts have CVE-X" -- is
-- deliberately NOT created here. tools/db/bench_index.ps1 measures that query
-- without it and then with it; see docs/SQL_SERVER.md. Create it for
-- production with:
--   CREATE INDEX IX_findings_cve ON dbo.findings (cve_id)
--       INCLUDE (scan_id, package_name, package_version, cvss, severity, exposed);

-- Least privilege for the service. Its identity is the per-service virtual
-- account NT SERVICE\nano-sensor (created when the service is installed, so
-- install the service before running this part). It can read and append; it
-- cannot DELETE and cannot run DDL, so a compromised agent can neither drop
-- tables nor erase the findings it already reported.
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'NT SERVICE\nano-sensor')
   OR SUSER_SID(N'NT SERVICE\nano-sensor') IS NOT NULL
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'NT SERVICE\nano-sensor')
        CREATE LOGIN [NT SERVICE\nano-sensor] FROM WINDOWS;
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'nano_sensor_agent')
        CREATE USER nano_sensor_agent FOR LOGIN [NT SERVICE\nano-sensor];
    GRANT SELECT, INSERT, UPDATE ON dbo.hosts    TO nano_sensor_agent;
    GRANT SELECT, INSERT         ON dbo.scans    TO nano_sensor_agent;
    GRANT SELECT, INSERT         ON dbo.packages TO nano_sensor_agent;
    GRANT SELECT, INSERT         ON dbo.findings TO nano_sensor_agent;
    PRINT 'granted NT SERVICE\nano-sensor: SELECT/INSERT (+UPDATE on hosts)';
END
ELSE
    PRINT 'NT SERVICE\nano-sensor does not exist yet -- install the service, then re-run';
GO
