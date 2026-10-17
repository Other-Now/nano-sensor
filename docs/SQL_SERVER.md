# Inventory and findings in SQL Server

The service writes every scan (the host, every installed package, and every
CVE finding) to SQL Server Express through ODBC
([src/db_odbc.cpp](../src/db_odbc.cpp), schema in
[tools/db/schema.sql](../tools/db/schema.sql)).

```
hosts     (host_id PK, hostname UNIQUE, os_*, last_seen, latest_scan_id)
scans     (scan_id PK, host_id FK, collected_at, agent_version, counts)
packages  (scan_id FK, package_id) PK, name, version, vendor, source   -- the inventory
findings  (finding_id PK, scan_id FK, cve_id, package_*, cvss, severity, exposed)
```

## Parameterized, transactional, least-privilege

- **Every value is a bound parameter.** `SQLPrepare` with `?` placeholders,
  then `SQLBindParameter`. Package names come from the registry of a machine
  the agent does not control: any installer can set its `DisplayName` to
  `x'); DROP TABLE dbo.findings; --`. The test
  `DbTest.hostile_and_unicode_names_round_trip_verbatim` stores exactly that
  string, reads it back unchanged, and checks the table still exists.
- **Unicode end to end.** `nvarchar` columns are bound as `SQL_C_WCHAR` and
  converted from UTF-8 explicitly. `SQL_C_CHAR` would go through the client
  ANSI code page and corrupt `Café Studio® 日本` (tested).
- **One transaction per scan.** Host upsert, scan row, packages, findings and
  the `latest_scan_id` pointer commit together or not at all. The test
  `a_failed_scan_rolls_back_completely` forces a failure on the last finding
  (an over-long CVE id) and checks that not even the host row survived, and
  that the connection is usable afterwards.
- **The service's login can't do much.** `NT SERVICE\nano-sensor` gets
  SELECT/INSERT on four tables (plus UPDATE on `hosts`). No DELETE, no DDL. A
  compromised agent cannot drop the tables or erase what it already reported.
  Verified with `EXECUTE AS LOGIN` in
  [tools/install_service.ps1](../tools/install_service.ps1); see
  [SERVICE.md](SERVICE.md).
- **Reconnect lazily.** At boot the SQL Server service may start after this
  one. A failed connect is logged and retried on the next scan, and a failed
  write drops the connection so the next scan reconnects cleanly.

## The index, measured before and after

The query a responder runs the morning an advisory drops: *which hosts are
exposed to CVE-X right now?*

```sql
SELECT h.hostname, f.cve_id, f.package_name, f.package_version, f.cvss, f.severity, f.exposed, f.scan_id
FROM dbo.findings f JOIN dbo.hosts h ON h.latest_scan_id = f.scan_id
WHERE f.cve_id = ? ORDER BY h.hostname
```

and the index for it:

```sql
CREATE INDEX IX_findings_cve ON dbo.findings (cve_id)
    INCLUDE (scan_id, package_name, package_version, cvss, severity, exposed);
```

**Setup.** `powershell -File tools\db\bench_index.ps1 -Hosts 1000 -InsertHosts 50`
on SQL Server 2022 Express, local, on the dev laptop.

The tool loads 1,000 synthetic hosts. Each gets 6–12 of the 20 indexed
products, at random versions taken from the NVD data, and every package goes
through the agent's real CVE matcher. That comes to **1,040,413 finding
rows**, about 1,040 per host. That's a deliberately heavy table, because
random NVD versions skew old.

The measurement uses 30 CVEs chosen at evenly spaced frequency ranks, from one
that hits 1 host to one that hits 656. The same 30 run before and after. Each
query is warmed once, then timed 9 times; the per-CVE median is reported.
Logical reads come from `SET STATISTICS IO ON`, captured over ODBC.

| | without index | with `IX_findings_cve` | change |
|---|---:|---:|---:|
| median latency (median of 30 per-CVE medians) | **191.3 ms** | **2.25 ms** | **85× faster** |
| p90 latency | 214.6 ms | 4.06 ms | 53× |
| logical reads per query (median) | **10,950** | **25** | **438× fewer** |
| logical reads, worst CVE (656 hosts) | 10,950 | 29 | |
| plan for `findings` | Clustered Index **Scan**, filter on `cve_id` | Index **Seek** on `cve_id` | |

**What it costs**, measured as well:

| | |
|---|---|
| `findings` size (used pages) | 13,780 → 24,314 (**+76%**). The index carries the INCLUDE columns, two of them `nvarchar` |
| `CREATE INDEX` on 1.04M rows | 144 s on Express |
| write throughput (50 more hosts, 59,257 rows) | 5,146 → 4,111 rows/s (**−20%**); 230 → 288 ms per host scan |

Raw output: [evidence/sql-bench/](evidence/sql-bench/), including the
`SHOWPLAN_TEXT` before and after, and the per-CVE table.

**Reading the numbers honestly:**

- **Logical reads are the robust number.** They don't depend on cache state or
  machine load. Without the index, every query reads 10,950 pages whether it
  returns 1 host or 656: it's a full scan. With it, reads track the result
  size (25–29 pages).
- **Latencies are warm-cache.** The whole table (about 108 MB) fits in Express's
  buffer pool, so even the "before" number is a scan of RAM, not disk. On a
  real fleet table larger than memory, the gap would be wider, not narrower.
- **Why INCLUDE.** Without it, the seek would be followed by one key lookup
  per matching row into the clustered index. INCLUDE trades 76% more storage
  and 20% slower inserts for zero lookups. The trade suits this table:
  the service writes once per host every 5 minutes, and people read it during
  incidents.
- **Not measured:** a narrow index without INCLUDE, or a clustered index on
  `(cve_id, ...)`. Both are reasonable alternatives with different trade-offs;
  only the shipped design was measured.

## Insert path

Inserts are row-at-a-time on one prepared statement inside one transaction:
about **5,000 rows/s** locally. A typical real host scan (41 packages, 20
findings on the dev machine) takes a few milliseconds. The synthetic hosts,
with about 1,000 findings each, take about 230 ms. ODBC array binding
(`SQL_ATTR_PARAMSET_SIZE`) would cut round trips by the batch size. It hasn't
been done because one scan per host every 5 minutes doesn't need it; the bulk
load is the only place it would show.
