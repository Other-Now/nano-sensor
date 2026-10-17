#include "ns/db.hpp"

#include "ns/version.hpp"

#include <windows.h>
#include <sql.h>
#include <sqlext.h>

#include <ctime>
#include <string>
#include <vector>

namespace ns {

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), n);
    out.pop_back();
    return out;
}

std::string narrow(const wchar_t* s, size_t len) {
    if (len == 0) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(len), nullptr, 0,
                                      nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(len), out.data(), n, nullptr, nullptr);
    return out;
}

bool ok(SQLRETURN rc) { return rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO; }

// All diagnostic records on a handle, joined. Used for errors and, with
// SET STATISTICS IO ON, for the "logical reads" messages the benchmark parses.
std::string diag(SQLSMALLINT type, SQLHANDLE h) {
    std::string out;
    SQLWCHAR state[6], msg[1024];
    SQLINTEGER native = 0;
    SQLSMALLINT len = 0;
    for (SQLSMALLINT i = 1;
         SQLGetDiagRecW(type, h, i, state, &native, msg, 1024, &len) == SQL_SUCCESS; ++i) {
        if (!out.empty()) out += "\n";
        out += narrow(msg, static_cast<size_t>(len));
    }
    return out;
}

// Owns one statement handle and the buffers bound to it. ODBC reads bound
// parameters at SQLExecute time, not at bind time, so the buffers must live as
// long as the statement -- keeping them here makes that impossible to get wrong.
class Stmt {
public:
    // Every statement gets a query timeout. Without one, a slow or blocked
    // query waits forever while the caller holds the agent's DB lock -- and
    // the only thing that would end it is the hang watchdog killing the
    // service. 30 s fails a statement well inside the watchdog's 120 s.
    explicit Stmt(SQLHDBC dbc) {
        SQLAllocHandle(SQL_HANDLE_STMT, dbc, &h_);
        SQLSetStmtAttrW(h_, SQL_ATTR_QUERY_TIMEOUT, reinterpret_cast<SQLPOINTER>(30), 0);
    }
    ~Stmt() {
        if (h_) SQLFreeHandle(SQL_HANDLE_STMT, h_);
    }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    SQLHSTMT h() const { return h_; }

    bool prepare(const wchar_t* sql, std::string& err) {
        if (ok(SQLPrepareW(h_, const_cast<SQLWCHAR*>(sql), SQL_NTS))) return true;
        err = "prepare: " + diag(SQL_HANDLE_STMT, h_);
        return false;
    }

    // Parameter slots are allocated once per statement and rebound by value on
    // every row. Fixed column sizes match the schema, so a too-long value fails
    // with a truncation error instead of being silently cut.
    void bind_wstr(SQLUSMALLINT i, SQLULEN column_size) {
        slot(i).kind = Slot::WStr;
        slot(i).column_size = column_size;
    }
    void bind_str(SQLUSMALLINT i, SQLULEN column_size) {
        slot(i).kind = Slot::Str;
        slot(i).column_size = column_size;
    }
    void bind_i64(SQLUSMALLINT i) { slot(i).kind = Slot::I64; }
    void bind_double(SQLUSMALLINT i) { slot(i).kind = Slot::Dbl; }
    void bind_bit(SQLUSMALLINT i) { slot(i).kind = Slot::Bit; }
    void bind_ts(SQLUSMALLINT i) { slot(i).kind = Slot::Ts; }

    void set(SQLUSMALLINT i, const std::string& v) {
        auto& s = slot(i);
        if (s.kind == Slot::WStr) {
            s.w = widen(v);
            s.ind = static_cast<SQLLEN>(s.w.size() * sizeof(wchar_t));
        } else {
            s.s = v;
            s.ind = static_cast<SQLLEN>(s.s.size());
        }
    }
    void set(SQLUSMALLINT i, std::int64_t v) { slot(i).i64 = v; slot(i).ind = 0; }
    void set(SQLUSMALLINT i, double v) { slot(i).dbl = v; slot(i).ind = 0; }
    void set_bit(SQLUSMALLINT i, bool v) { slot(i).bit = v ? 1 : 0; slot(i).ind = 0; }
    void set_unix_ms(SQLUSMALLINT i, std::int64_t ms) {
        const std::time_t t = static_cast<std::time_t>(ms / 1000);
        std::tm tm{};
        gmtime_s(&tm, &t);
        auto& ts = slot(i).ts;
        ts.year = static_cast<SQLSMALLINT>(tm.tm_year + 1900);
        ts.month = static_cast<SQLUSMALLINT>(tm.tm_mon + 1);
        ts.day = static_cast<SQLUSMALLINT>(tm.tm_mday);
        ts.hour = static_cast<SQLUSMALLINT>(tm.tm_hour);
        ts.minute = static_cast<SQLUSMALLINT>(tm.tm_min);
        ts.second = static_cast<SQLUSMALLINT>(tm.tm_sec);
        ts.fraction = static_cast<SQLUINTEGER>((ms % 1000) * 1000000);
        slot(i).ind = 0;
    }

    bool execute(std::string& err) {
        // (Re)bind every slot. Rebinding is cheap -- it records pointers, it
        // does not touch the server -- and std::string buffers may have moved.
        for (SQLUSMALLINT i = 1; i <= slots_.size(); ++i) {
            auto& s = slots_[i - 1];
            SQLRETURN rc = SQL_SUCCESS;
            switch (s.kind) {
            case Slot::WStr:
                rc = SQLBindParameter(h_, i, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
                                      s.column_size, 0, s.w.data(), 0, &s.ind);
                break;
            case Slot::Str:
                rc = SQLBindParameter(h_, i, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
                                      s.column_size, 0, s.s.data(), 0, &s.ind);
                break;
            case Slot::I64:
                rc = SQLBindParameter(h_, i, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0,
                                      &s.i64, 0, &s.ind);
                break;
            case Slot::Dbl:
                rc = SQLBindParameter(h_, i, SQL_PARAM_INPUT, SQL_C_DOUBLE, SQL_DOUBLE, 0, 0,
                                      &s.dbl, 0, &s.ind);
                break;
            case Slot::Bit:
                rc = SQLBindParameter(h_, i, SQL_PARAM_INPUT, SQL_C_BIT, SQL_BIT, 0, 0,
                                      &s.bit, 0, &s.ind);
                break;
            case Slot::Ts:
                rc = SQLBindParameter(h_, i, SQL_PARAM_INPUT, SQL_C_TYPE_TIMESTAMP,
                                      SQL_TYPE_TIMESTAMP, 23, 3, &s.ts, 0, &s.ind);
                break;
            case Slot::None:
                break;
            }
            if (!ok(rc)) {
                err = "bind: " + diag(SQL_HANDLE_STMT, h_);
                return false;
            }
        }
        const SQLRETURN rc = SQLExecute(h_);
        if (rc == SQL_NO_DATA) return true;  // UPDATE that matched nothing
        if (!ok(rc)) {
            err = diag(SQL_HANDLE_STMT, h_);
            return false;
        }
        return true;
    }

    // First column of the first row as an integer (OUTPUT INSERTED.id).
    bool fetch_i64(std::int64_t& out, bool& found) {
        found = false;
        const SQLRETURN rc = SQLFetch(h_);
        if (rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO) {
            SQLLEN ind = 0;
            SQLBIGINT v = 0;
            SQLGetData(h_, 1, SQL_C_SBIGINT, &v, 0, &ind);
            out = v;
            found = ind != SQL_NULL_DATA;
        }
        SQLCloseCursor(h_);
        return rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO || rc == SQL_NO_DATA;
    }

private:
    struct Slot {
        enum Kind { None, WStr, Str, I64, Dbl, Bit, Ts } kind = None;
        SQLULEN column_size = 0;
        std::wstring w;
        std::string s;
        SQLBIGINT i64 = 0;
        double dbl = 0;
        unsigned char bit = 0;
        SQL_TIMESTAMP_STRUCT ts{};
        SQLLEN ind = 0;
    };

    Slot& slot(SQLUSMALLINT i) {
        if (slots_.size() < i) slots_.resize(i);
        return slots_[i - 1];
    }

    SQLHSTMT h_ = nullptr;
    std::vector<Slot> slots_;
};

std::string get_text(SQLHSTMT h, SQLUSMALLINT col) {
    wchar_t buf[1024];
    SQLLEN ind = 0;
    if (!ok(SQLGetData(h, col, SQL_C_WCHAR, buf, sizeof(buf), &ind)) || ind == SQL_NULL_DATA) {
        return {};
    }
    return narrow(buf, static_cast<size_t>(ind) / sizeof(wchar_t));
}

// Reads the FindingRow column layout shared by host_findings / hosts_affected.
void read_rows(SQLHSTMT h, std::vector<FindingRow>& out) {
    while (ok(SQLFetch(h))) {
        FindingRow r;
        r.hostname = get_text(h, 1);
        r.cve_id = get_text(h, 2);
        r.package_name = get_text(h, 3);
        r.package_version = get_text(h, 4);
        SQLLEN ind = 0;
        SQLGetData(h, 5, SQL_C_DOUBLE, &r.cvss, 0, &ind);
        r.severity = get_text(h, 6);
        unsigned char bit = 0;
        SQLGetData(h, 7, SQL_C_BIT, &bit, 0, &ind);
        r.exposed = bit != 0;
        SQLBIGINT sid = 0;
        SQLGetData(h, 8, SQL_C_SBIGINT, &sid, 0, &ind);
        r.scan_id = sid;
        out.push_back(std::move(r));
    }
}

// Drains every result set so the trailing info messages (STATISTICS IO is
// reported after the rows) are collected too.
void drain_messages(SQLHSTMT h, std::string* messages) {
    if (messages) {
        const std::string d = diag(SQL_HANDLE_STMT, h);
        if (!d.empty()) *messages += d + "\n";
    }
    for (;;) {
        const SQLRETURN rc = SQLMoreResults(h);
        if (messages && (rc == SQL_SUCCESS_WITH_INFO || rc == SQL_SUCCESS)) {
            const std::string d = diag(SQL_HANDLE_STMT, h);
            if (!d.empty()) *messages += d + "\n";
        }
        if (rc == SQL_NO_DATA || !ok(rc)) break;
    }
}

constexpr const wchar_t* kRowColumns =
    L"h.hostname, f.cve_id, f.package_name, f.package_version, "
    L"CAST(f.cvss AS float), f.severity, f.exposed, f.scan_id ";

} // namespace

struct Db::Impl {
    SQLHENV env = nullptr;
    SQLHDBC dbc = nullptr;
    bool connected = false;

    void set_autocommit(bool on) {
        SQLSetConnectAttrW(dbc, SQL_ATTR_AUTOCOMMIT,
                           reinterpret_cast<SQLPOINTER>(static_cast<std::uintptr_t>(
                               on ? SQL_AUTOCOMMIT_ON : SQL_AUTOCOMMIT_OFF)),
                           SQL_IS_UINTEGER);
    }
};

Db::Db() : impl_(std::make_unique<Impl>()) {}
Db::~Db() { disconnect(); }

bool Db::connected() const { return impl_->connected; }

bool Db::connect(const std::string& connection_string, std::string& error) {
    disconnect();
    if (!ok(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &impl_->env))) {
        error = "SQLAllocHandle(ENV) failed";
        return false;
    }
    SQLSetEnvAttr(impl_->env, SQL_ATTR_ODBC_VERSION, reinterpret_cast<SQLPOINTER>(SQL_OV_ODBC3),
                  0);
    SQLAllocHandle(SQL_HANDLE_DBC, impl_->env, &impl_->dbc);
    SQLSetConnectAttrW(impl_->dbc, SQL_ATTR_LOGIN_TIMEOUT, reinterpret_cast<SQLPOINTER>(5), 0);

    std::wstring cs = widen(connection_string);
    const SQLRETURN rc = SQLDriverConnectW(impl_->dbc, nullptr, cs.data(), SQL_NTS, nullptr, 0,
                                           nullptr, SQL_DRIVER_NOPROMPT);
    if (!ok(rc)) {
        error = "connect: " + diag(SQL_HANDLE_DBC, impl_->dbc);
        disconnect();
        return false;
    }
    impl_->connected = true;
    return true;
}

void Db::disconnect() {
    if (impl_->connected) SQLDisconnect(impl_->dbc);
    impl_->connected = false;
    if (impl_->dbc) SQLFreeHandle(SQL_HANDLE_DBC, impl_->dbc);
    if (impl_->env) SQLFreeHandle(SQL_HANDLE_ENV, impl_->env);
    impl_->dbc = nullptr;
    impl_->env = nullptr;
}

bool Db::record_scan(const Inventory& inv, const std::vector<Finding>& findings,
                     std::int64_t& scan_id, std::string& error) {
    if (!impl_->connected) {
        error = "not connected";
        return false;
    }
    SQLHDBC dbc = impl_->dbc;
    impl_->set_autocommit(false);

    const auto fail = [&](const std::string& what) {
        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
        impl_->set_autocommit(true);
        error = what;
        return false;
    };

    std::string err;
    std::int64_t host_id = 0;
    bool found = false;

    // Host: update-then-insert. hostname has a UNIQUE constraint, so two
    // writers racing on a new host get a constraint error, not a duplicate.
    {
        Stmt upd(dbc);
        if (!upd.prepare(L"UPDATE dbo.hosts SET os_name = ?, os_version = ?, "
                         L"last_seen = SYSUTCDATETIME() OUTPUT INSERTED.host_id "
                         L"WHERE hostname = ?",
                         err))
            return fail(err);
        upd.bind_wstr(1, 128);
        upd.bind_wstr(2, 64);
        upd.bind_wstr(3, 255);
        upd.set(1, inv.host.os_name);
        upd.set(2, inv.host.os_version);
        upd.set(3, inv.host.hostname);
        if (!upd.execute(err) || !upd.fetch_i64(host_id, found)) return fail("host update: " + err);
    }
    if (!found) {
        Stmt ins(dbc);
        if (!ins.prepare(L"INSERT dbo.hosts (hostname, os_name, os_version, last_seen) "
                         L"OUTPUT INSERTED.host_id VALUES (?, ?, ?, SYSUTCDATETIME())",
                         err))
            return fail(err);
        ins.bind_wstr(1, 255);
        ins.bind_wstr(2, 128);
        ins.bind_wstr(3, 64);
        ins.set(1, inv.host.hostname);
        ins.set(2, inv.host.os_name);
        ins.set(3, inv.host.os_version);
        if (!ins.execute(err) || !ins.fetch_i64(host_id, found) || !found)
            return fail("host insert: " + err);
    }

    {
        Stmt s(dbc);
        if (!s.prepare(L"INSERT dbo.scans (host_id, collected_at, agent_version, "
                       L"package_count, finding_count) OUTPUT INSERTED.scan_id "
                       L"VALUES (?, ?, ?, ?, ?)",
                       err))
            return fail(err);
        s.bind_i64(1);
        s.bind_ts(2);
        s.bind_str(3, 32);
        s.bind_i64(4);
        s.bind_i64(5);
        s.set(1, host_id);
        s.set_unix_ms(2, inv.collected_at_unix_ms);
        s.set(3, std::string(kAgentVersion));
        s.set(4, static_cast<std::int64_t>(inv.packages.size()));
        s.set(5, static_cast<std::int64_t>(findings.size()));
        if (!s.execute(err) || !s.fetch_i64(scan_id, found) || !found)
            return fail("scan insert: " + err);
    }

    // One prepared statement, executed per row. The plan is compiled once on
    // the server and reused; only the bound values change.
    {
        Stmt p(dbc);
        if (!p.prepare(L"INSERT dbo.packages (scan_id, package_id, name, version, vendor, "
                       L"source) VALUES (?, ?, ?, ?, ?, ?)",
                       err))
            return fail(err);
        p.bind_i64(1);
        p.bind_i64(2);
        p.bind_wstr(3, 400);
        p.bind_wstr(4, 128);
        p.bind_wstr(5, 256);
        p.bind_str(6, 32);
        std::int64_t ordinal = 0;
        for (const auto& pkg : inv.packages) {
            p.set(1, scan_id);
            p.set(2, ordinal++);
            p.set(3, pkg.name.substr(0, 400));
            p.set(4, pkg.version.substr(0, 128));
            p.set(5, pkg.vendor.substr(0, 256));
            p.set(6, pkg.source.substr(0, 32));
            if (!p.execute(err)) return fail("package insert: " + err);
        }
    }

    {
        Stmt f(dbc);
        if (!f.prepare(L"INSERT dbo.findings (scan_id, cve_id, package_name, package_version, "
                       L"cvss, severity, exposed) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       err))
            return fail(err);
        f.bind_i64(1);
        f.bind_str(2, 32);
        f.bind_wstr(3, 400);
        f.bind_wstr(4, 128);
        f.bind_double(5);
        f.bind_str(6, 10);
        f.bind_bit(7);
        for (const auto& x : findings) {
            f.set(1, scan_id);
            f.set(2, x.cve_id);
            f.set(3, x.package_name.substr(0, 400));
            f.set(4, x.package_version.substr(0, 128));
            f.set(5, x.cvss_score);
            f.set(6, x.cvss_severity.empty() ? std::string("NONE") : x.cvss_severity);
            f.set_bit(7, x.network_exposed);
            if (!f.execute(err)) return fail("finding insert: " + err);
        }
    }

    {
        Stmt u(dbc);
        if (!u.prepare(L"UPDATE dbo.hosts SET latest_scan_id = ? WHERE host_id = ?", err))
            return fail(err);
        u.bind_i64(1);
        u.bind_i64(2);
        u.set(1, scan_id);
        u.set(2, host_id);
        if (!u.execute(err)) return fail("latest_scan_id: " + err);
    }

    if (!ok(SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT))) {
        return fail("commit: " + diag(SQL_HANDLE_DBC, dbc));
    }
    impl_->set_autocommit(true);
    return true;
}

bool Db::host_findings(const std::string& hostname, double min_cvss, int limit,
                       std::vector<FindingRow>& out, std::string& error) {
    if (!impl_->connected) {
        error = "not connected";
        return false;
    }
    Stmt s(impl_->dbc);
    const std::wstring sql = std::wstring(L"SELECT TOP (?) ") + kRowColumns +
                             L"FROM dbo.hosts h JOIN dbo.findings f "
                             L"ON f.scan_id = h.latest_scan_id "
                             L"WHERE h.hostname = ? AND f.cvss >= ? "
                             L"ORDER BY f.cvss DESC, f.cve_id";
    if (!s.prepare(sql.c_str(), error)) return false;
    s.bind_i64(1);
    s.bind_wstr(2, 255);
    s.bind_double(3);
    s.set(1, static_cast<std::int64_t>(limit));
    s.set(2, hostname);
    s.set(3, min_cvss);
    if (!s.execute(error)) return false;
    read_rows(s.h(), out);
    drain_messages(s.h(), nullptr);
    return true;
}

bool Db::hosts_affected(const std::string& cve_id, std::vector<FindingRow>& out,
                        std::string& error, std::string* messages) {
    if (!impl_->connected) {
        error = "not connected";
        return false;
    }
    Stmt s(impl_->dbc);
    const std::wstring sql = std::wstring(L"SELECT ") + kRowColumns +
                             L"FROM dbo.findings f JOIN dbo.hosts h "
                             L"ON h.latest_scan_id = f.scan_id "
                             L"WHERE f.cve_id = ? ORDER BY h.hostname";
    if (!s.prepare(sql.c_str(), error)) return false;
    s.bind_str(1, 32);
    s.set(1, cve_id);
    if (!s.execute(error)) return false;
    if (messages) {
        const std::string d = diag(SQL_HANDLE_STMT, s.h());
        if (!d.empty()) *messages += d + "\n";
    }
    read_rows(s.h(), out);
    drain_messages(s.h(), messages);
    return true;
}

bool Db::exec(const std::string& sql, std::string& error, std::string* messages) {
    if (!impl_->connected) {
        error = "not connected";
        return false;
    }
    Stmt s(impl_->dbc);
    std::wstring w = widen(sql);
    const SQLRETURN rc = SQLExecDirectW(s.h(), w.data(), SQL_NTS);
    if (!ok(rc) && rc != SQL_NO_DATA) {
        error = diag(SQL_HANDLE_STMT, s.h());
        return false;
    }
    drain_messages(s.h(), messages);
    return true;
}

bool Db::scalar(const std::string& sql, std::int64_t& out, std::string& error) {
    if (!impl_->connected) {
        error = "not connected";
        return false;
    }
    Stmt s(impl_->dbc);
    std::wstring w = widen(sql);
    if (!ok(SQLExecDirectW(s.h(), w.data(), SQL_NTS))) {
        error = diag(SQL_HANDLE_STMT, s.h());
        return false;
    }
    bool found = false;
    s.fetch_i64(out, found);
    if (!found) out = 0;
    return true;
}

bool Db::column(const std::string& sql, std::vector<std::string>& out, std::string& error) {
    if (!impl_->connected) {
        error = "not connected";
        return false;
    }
    Stmt s(impl_->dbc);
    std::wstring w = widen(sql);
    if (!ok(SQLExecDirectW(s.h(), w.data(), SQL_NTS))) {
        error = diag(SQL_HANDLE_STMT, s.h());
        return false;
    }
    while (ok(SQLFetch(s.h()))) out.push_back(get_text(s.h(), 1));
    return true;
}

} // namespace ns
