#include "ns/agent.hpp"

#include "ns/crashdump.hpp"
#include "ns/cve.hpp"
#include "ns/db.hpp"
#include "ns/json.hpp"
#include "ns/log.hpp"
#include "ns/platform.hpp"
#include "ns/procinfo.hpp"
#include "ns/version.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

namespace ns {

namespace {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

struct ScanResult {
    bool ok = false;
    std::int64_t scan_id = 0;  // 0 when not written to SQL Server
    std::size_t packages = 0;
    std::size_t findings = 0;
    std::size_t critical = 0;
    std::int64_t duration_ms = 0;
    std::int64_t finished_unix_ms = 0;
    std::string worst;
    std::string db_error;
};

class ScanListener {
public:
    virtual ~ScanListener() = default;
    virtual void on_scan_complete(const ScanResult& r) = 0;
};

// Parks a pipe request until the next scan finishes.
class ScanWaiter final : public ScanListener {
public:
    void on_scan_complete(const ScanResult& r) override {
        std::lock_guard<std::mutex> lock(mu_);
        result_ = r;
        done_ = true;
        cv_.notify_all();
    }

    bool wait(milliseconds timeout, ScanResult& out) {
        std::unique_lock<std::mutex> lock(mu_);
        if (!cv_.wait_for(lock, timeout, [&] { return done_; })) return false;
        out = result_;
        return true;
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    bool done_ = false;
    ScanResult result_;
};

// Turns "stuck forever" into "dump + restart".
//
// A deadlocked service is worse than a crashed one: the SCM still shows it
// RUNNING, nothing restarts it, and it silently stops reporting. Anything that
// can block registers a Scope; if one outlives the timeout the watchdog writes
// a dump of every thread -- the evidence for the deadlock -- and exits, which
// the SCM treats as a failure and restarts per the recovery policy.
class Watchdog {
public:
    class Scope {
    public:
        Scope(Watchdog& w, std::string what) : w_(w), id_(w.enter(std::move(what))) {}
        ~Scope() { w_.leave(id_); }
        Scope(const Scope&) = delete;
        Scope& operator=(const Scope&) = delete;

    private:
        Watchdog& w_;
        std::uint64_t id_;
    };

    void start(int timeout_s) {
        if (timeout_s <= 0) return;
        timeout_ = std::chrono::seconds(timeout_s);
        thread_ = std::thread([this] { loop(); });
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            stopping_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

private:
    std::uint64_t enter(std::string what) {
        std::lock_guard<std::mutex> lock(mu_);
        const std::uint64_t id = ++next_;
        active_.emplace(id, Entry{std::move(what), Clock::now()});
        return id;
    }

    void leave(std::uint64_t id) {
        std::lock_guard<std::mutex> lock(mu_);
        active_.erase(id);
    }

    void loop() {
        crashdump::on_thread_start();
        std::unique_lock<std::mutex> lock(mu_);
        while (!stopping_) {
            cv_.wait_for(lock, milliseconds(500));
            const auto now = Clock::now();
            for (const auto& [id, e] : active_) {
                if (now - e.since < timeout_) continue;
                const std::string what = e.what;
                const auto age_ms =
                    std::chrono::duration_cast<milliseconds>(now - e.since).count();
                lock.unlock();
                on_hang(what, age_ms);  // does not return
            }
        }
    }

    [[noreturn]] static void on_hang(const std::string& what, std::int64_t age_ms) {
        log_error("hang detected; writing dump and exiting so the SCM restarts the service",
                  {{"stuck", what}, {"age_ms", std::to_string(age_ms)}});
        std::string path, err;
        if (crashdump::write_now("hang", path, err)) {
            log_error("hang dump written", {{"dump", path}});
        } else {
            log_error("hang dump failed", {{"error", err}});
        }
        // Not exit(): the threads holding the locks are deadlocked, and static
        // destructors or atexit handlers that touch the same state would hang
        // the exit path too.
        std::_Exit(4);
    }

    struct Entry {
        std::string what;
        Clock::time_point since;
    };

    std::mutex mu_;
    std::condition_variable cv_;
    bool stopping_ = false;
    std::uint64_t next_ = 0;
    std::map<std::uint64_t, Entry> active_;
    Clock::duration timeout_{};
    std::thread thread_;
};

// The finding to put in the log line: highest CVSS.
std::string worst_finding(const std::vector<Finding>& findings, Fault fault) {
    if (fault == Fault::WorkerCrash) {
        // PLANTED BUG (docs/DEBUGGING.md, bug 3): off-by-one. Sorted ascending,
        // the worst finding is the LAST element, at size()-1. at(size()) throws
        // std::out_of_range on the worker thread, where nothing catches it.
        std::vector<const Finding*> sorted;
        for (const auto& f : findings) sorted.push_back(&f);
        std::sort(sorted.begin(), sorted.end(),
                  [](const Finding* a, const Finding* b) { return a->cvss_score < b->cvss_score; });
        return sorted.at(sorted.size())->cve_id;
    }
    if (findings.empty()) return "none";
    const auto it = std::max_element(findings.begin(), findings.end(),
                                     [](const Finding& a, const Finding& b) {
                                         return a.cvss_score < b.cvss_score;
                                     });
    return it->cve_id;
}

void write_result(JsonWriter& w, const ScanResult& r) {
    w.field("ok", r.ok);
    w.field("scan_id", r.scan_id);
    w.field("packages", r.packages);
    w.field("findings", r.findings);
    w.field("critical", r.critical);
    w.field("worst", r.worst);
    w.field("duration_ms", r.duration_ms);
    w.field("finished_unix_ms", r.finished_unix_ms);
    if (!r.db_error.empty()) w.field("db_error", r.db_error);
}

std::string error_json(const std::string& msg) {
    JsonWriter w;
    w.begin_object();
    w.field("error", msg);
    w.end_object();
    return w.str();
}

bool valid_cve_id(const std::string& s) {
    // Bound as a parameter regardless; this is about a useful error message,
    // not injection.
    if (s.size() < 9 || s.size() > 32 || s.rfind("CVE-", 0) != 0) return false;
    return std::all_of(s.begin() + 4, s.end(),
                       [](char c) { return (c >= '0' && c <= '9') || c == '-'; });
}

} // namespace

bool parse_fault(std::string_view name, Fault& out) {
    if (name == "none")         { out = Fault::None;         return true; }
    if (name == "uaf")          { out = Fault::UseAfterFree; return true; }
    if (name == "deadlock")     { out = Fault::Deadlock;     return true; }
    if (name == "worker-crash") { out = Fault::WorkerCrash;  return true; }
    return false;
}

const char* fault_name(Fault f) {
    switch (f) {
    case Fault::None:         return "none";
    case Fault::UseAfterFree: return "uaf";
    case Fault::Deadlock:     return "deadlock";
    case Fault::WorkerCrash:  return "worker-crash";
    }
    return "none";
}

struct Agent::Impl {
    AgentConfig cfg;
    CveIndex index;

    // Lock order, everywhere: state_mu may be taken while holding nothing;
    // db_mu may be taken while holding nothing. Never both at once. (The
    // Deadlock fault breaks exactly this rule.)
    std::mutex db_mu;
    Db db;

    std::mutex state_mu;
    std::int64_t started_unix_ms = 0;
    std::uint64_t scans = 0;
    std::string hostname;
    ScanResult last;

    std::mutex listeners_mu;
    std::vector<std::shared_ptr<ScanListener>> listeners;

    std::mutex wake_mu;
    std::condition_variable wake_cv;
    bool scan_requested = false;
    bool stopping = false;

    Watchdog watchdog;
    ipc::Server server;
    std::thread worker;

    void request_scan() {
        {
            std::lock_guard<std::mutex> lock(wake_mu);
            scan_requested = true;
        }
        wake_cv.notify_all();
    }

    void worker_loop() {
        crashdump::on_thread_start();
        auto next = Clock::now();  // first scan immediately
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(wake_mu);
                wake_cv.wait_until(lock, next, [&] { return stopping || scan_requested; });
                if (stopping) return;
                scan_requested = false;
            }
            run_scan();
            next = Clock::now() + std::chrono::seconds(cfg.interval_s);
        }
    }

    // Caller holds db_mu.
    void write_db(const Inventory& inv, const std::vector<Finding>& findings, ScanResult& r) {
        if (cfg.db_connection.empty()) return;
        std::string err;
        // Reconnect lazily: at boot the SQL Server service may start after
        // this one, and a dropped connection should cost one cycle, not the
        // agent.
        if (!db.connected() && !db.connect(cfg.db_connection, err)) {
            r.db_error = err;
            return;
        }
        if (!db.record_scan(inv, findings, r.scan_id, err)) {
            r.db_error = err;
            db.disconnect();
        }
    }

    void update_state(const Inventory& inv, const ScanResult& r) {
        ++scans;
        hostname = inv.host.hostname;
        last = r;
    }

    void run_scan() {
        Watchdog::Scope guard(watchdog, "scan");
        const auto t0 = Clock::now();

        ScanResult r;
        const Inventory inv = collect_inventory();
        ScanSummary summary;
        const auto findings = index.scan(inv, summary);
        r.packages = inv.packages.size();
        r.findings = findings.size();
        r.critical = summary.critical;
        r.worst = worst_finding(findings, cfg.fault);

        if (cfg.fault == Fault::UseAfterFree) {
            // Widens the window so that a short `nsctl scan 1000` gives up
            // waiting before the scan completes -- the trigger for bug 1.
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }

        if (cfg.fault == Fault::Deadlock) {
            // PLANTED BUG (docs/DEBUGGING.md, bug 2): takes state_mu while
            // still holding db_mu. handle_status takes them the other way
            // round. The sleep holds the window open long enough to hit it by
            // hand with `nsctl status`.
            std::lock_guard<std::mutex> db_lock(db_mu);
            write_db(inv, findings, r);
            std::this_thread::sleep_for(std::chrono::seconds(3));
            std::lock_guard<std::mutex> state_lock(state_mu);
            r.ok = r.db_error.empty();
            r.duration_ms =
                std::chrono::duration_cast<milliseconds>(Clock::now() - t0).count();
            r.finished_unix_ms = unix_time_ms();
            update_state(inv, r);
        } else {
            {
                std::lock_guard<std::mutex> db_lock(db_mu);
                write_db(inv, findings, r);
            }
            r.ok = r.db_error.empty();
            r.duration_ms =
                std::chrono::duration_cast<milliseconds>(Clock::now() - t0).count();
            r.finished_unix_ms = unix_time_ms();
            std::lock_guard<std::mutex> state_lock(state_mu);
            update_state(inv, r);
        }

        log_info("scan complete", {{"packages", std::to_string(r.packages)},
                                   {"findings", std::to_string(r.findings)},
                                   {"worst", r.worst},
                                   {"scan_id", std::to_string(r.scan_id)},
                                   {"duration_ms", std::to_string(r.duration_ms)},
                                   {"db_error", r.db_error}});

        if (cfg.on_inventory) cfg.on_inventory(inv);

        // Hand the result to everyone waiting. Swap the list out under the
        // lock and call outside it: a listener that blocks must not block
        // registration of the next one.
        std::vector<std::shared_ptr<ScanListener>> waiting;
        {
            std::lock_guard<std::mutex> lock(listeners_mu);
            waiting.swap(listeners);
        }
        for (auto& l : waiting) l->on_scan_complete(r);
    }

    std::string handle_status() {
        const ProcInfo p = self_info();
        JsonWriter w;
        w.begin_object();
        w.field("service", kAgentName);
        w.field("version", kAgentVersion);
        w.field("fault", fault_name(cfg.fault));

        w.begin_object("process");
        w.field("pid", p.pid);
        w.field("user", p.user);
        w.field("elevated", p.elevated);
        w.field("privileges_enabled", p.privileges_enabled);
        w.field("private_bytes", p.private_bytes);
        w.field("working_set", p.working_set);
        w.field("peak_working_set", p.peak_working_set);
        w.field("handles", p.handles);
        w.field("threads", p.threads);
        w.end_object();

        w.field("pipe_requests_served", server.requests_served());
        w.field("dumps_written", crashdump::dumps_written());

        // "connected", "disconnected" or "busy". status never runs a query
        // and never waits for the DB lock: it is the command an operator
        // reaches for when something is wrong, so it must answer even when
        // the database is the thing that is wrong. The first version ran
        // COUNT_BIG(*) over findings here, and on the installed service a
        // cold, AUTO_CLOSEd database turned that into a 163 s stall that the
        // watchdog had to kill (docs/SERVICE.md).
        const char* db_state = "busy";
        {
            std::lock_guard<std::mutex> state_lock(state_mu);
            w.field("uptime_s", (unix_time_ms() - started_unix_ms) / 1000);
            w.field("hostname", hostname);
            w.field("scans_completed", scans);
            w.begin_object("last_scan");
            write_result(w, last);
            w.end_object();

            if (cfg.fault == Fault::Deadlock) {
                // PLANTED BUG (bug 2): the DB lock taken, blocking, while
                // state_mu is still held -- the opposite order to run_scan().
                std::lock_guard<std::mutex> db_lock(db_mu);
                db_state = db.connected() ? "connected" : "disconnected";
            }
        }
        if (cfg.fault != Fault::Deadlock) {
            std::unique_lock<std::mutex> db_lock(db_mu, std::try_to_lock);
            if (db_lock.owns_lock()) db_state = db.connected() ? "connected" : "disconnected";
        }

        w.begin_object("database");
        w.field("configured", !cfg.db_connection.empty());
        w.field("state", db_state);
        w.end_object();

        w.end_object();
        return w.str();
    }

    std::string handle_scan(int wait_ms) {
        // Keep the wait well inside the watchdog's budget, or a long wait
        // would itself look like a hang.
        const int cap = cfg.hang_timeout_s > 0 ? cfg.hang_timeout_s * 500 : 60000;
        wait_ms = std::clamp(wait_ms, 0, cap);

        ScanResult r;
        bool done = false;
        if (cfg.fault == Fault::UseAfterFree) {
            // PLANTED BUG (docs/DEBUGGING.md, bug 1): the waiter is owned by
            // this function, but the worker is handed a non-owning pointer to
            // it. If the wait times out, the waiter is deleted while still
            // registered, and the worker later calls a virtual method on
            // freed memory.
            auto* waiter = new ScanWaiter;
            {
                std::lock_guard<std::mutex> lock(listeners_mu);
                listeners.push_back(std::shared_ptr<ScanListener>(waiter, [](ScanListener*) {}));
            }
            request_scan();
            done = waiter->wait(milliseconds(wait_ms), r);
            delete waiter;
        } else {
            // Shared ownership: if we give up waiting, the worker's reference
            // keeps the waiter alive until it has delivered the result.
            auto waiter = std::make_shared<ScanWaiter>();
            {
                std::lock_guard<std::mutex> lock(listeners_mu);
                listeners.push_back(waiter);
            }
            request_scan();
            done = waiter->wait(milliseconds(wait_ms), r);
        }

        JsonWriter w;
        w.begin_object();
        w.field("completed", done);
        if (done) {
            w.begin_object("scan");
            write_result(w, r);
            w.end_object();
        } else {
            w.field("note", "scan still running; it will finish in the background");
        }
        w.end_object();
        return w.str();
    }

    std::string rows_json(const std::vector<FindingRow>& rows) {
        JsonWriter w;
        w.begin_object();
        w.field("count", rows.size());
        w.begin_array("rows");
        for (const auto& r : rows) {
            w.begin_object();
            w.field("host", r.hostname);
            w.field("cve", r.cve_id);
            w.field("package", r.package_name);
            w.field("version", r.package_version);
            w.field("cvss", r.cvss);
            w.field("severity", r.severity);
            w.field("exposed", r.exposed);
            w.field("scan_id", r.scan_id);
            w.end_object();
        }
        w.end_array();
        w.end_object();
        return w.str();
    }

    std::string handle_findings(double min_cvss, int limit) {
        std::string host;
        {
            std::lock_guard<std::mutex> lock(state_mu);
            host = hostname;
        }
        if (host.empty()) return error_json("no scan has completed yet");

        std::vector<FindingRow> rows;
        std::string err;
        std::lock_guard<std::mutex> lock(db_mu);
        if (!db.connected()) return error_json("database not connected");
        if (!db.host_findings(host, min_cvss, std::clamp(limit, 1, 1000), rows, err)) {
            return error_json(err);
        }
        return rows_json(rows);
    }

    std::string handle_affected(const std::string& cve) {
        if (!valid_cve_id(cve)) return error_json("expected a CVE id like CVE-2024-6387");
        std::vector<FindingRow> rows;
        std::string err;
        std::lock_guard<std::mutex> lock(db_mu);
        if (!db.connected()) return error_json("database not connected");
        if (!db.hosts_affected(cve, rows, err)) return error_json(err);
        return rows_json(rows);
    }
};

Agent::Agent(AgentConfig cfg) : impl_(std::make_unique<Impl>()) { impl_->cfg = std::move(cfg); }

Agent::~Agent() { stop(); }

bool Agent::start(std::string& error) {
    auto& m = *impl_;
    if (!m.index.load_rules(m.cfg.index_path, error)) return false;
    if (!m.index.load_aliases(m.cfg.alias_path, error)) return false;

    if (!m.cfg.db_connection.empty()) {
        std::string err;
        if (!m.db.connect(m.cfg.db_connection, err)) {
            // Not fatal: retried on every scan.
            log_warn("database unavailable; will retry each scan", {{"error", err}});
        }
    }

    m.started_unix_ms = unix_time_ms();
    m.watchdog.start(m.cfg.hang_timeout_s);

    const std::string sddl = m.cfg.pipe_sddl.empty() ? ipc::default_sddl() : m.cfg.pipe_sddl;
    if (!m.server.start(m.cfg.pipe_name, sddl,
                        [this](const std::string& req, const ipc::ClientInfo& who) {
                            return handle(req, who);
                        },
                        error)) {
#if defined(_WIN32)
        m.watchdog.stop();
        return false;
#else
        // The control pipe is Windows-only; on Linux the agent still scans
        // and reports, it just has no local control channel.
        log_info("control channel not available on this platform", {{"reason", error}});
        error.clear();
#endif
    }

    m.worker = std::thread([this] { impl_->worker_loop(); });
    log_info("agent started", {{"pipe", m.cfg.pipe_name},
                               {"interval_s", std::to_string(m.cfg.interval_s)},
                               {"db", m.cfg.db_connection.empty() ? "off" : "on"},
                               {"fault", fault_name(m.cfg.fault)}});
    return true;
}

void Agent::stop() {
    auto& m = *impl_;
    m.server.stop();
    {
        std::lock_guard<std::mutex> lock(m.wake_mu);
        m.stopping = true;
    }
    m.wake_cv.notify_all();
    if (m.worker.joinable()) m.worker.join();
    m.watchdog.stop();
}

std::string Agent::handle(const std::string& request, const ipc::ClientInfo& who) {
    std::istringstream in(request);
    std::string cmd;
    in >> cmd;

    Watchdog::Scope guard(impl_->watchdog, "pipe:" + cmd);
    log_info("pipe request", {{"cmd", cmd},
                              {"client_pid", std::to_string(who.pid)},
                              {"client_user", who.user}});

    if (cmd == "ping") return R"({"pong":true})";
    if (cmd == "status") return impl_->handle_status();
    if (cmd == "scan") {
        // A failed extraction writes 0, so the default has to be restored
        // rather than pre-set.
        int wait_ms = 0;
        if (!(in >> wait_ms)) wait_ms = 30000;
        return impl_->handle_scan(wait_ms);
    }
    if (cmd == "findings") {
        double min_cvss = 0.0;
        int limit = 0;
        if (!(in >> min_cvss)) min_cvss = 0.0;
        if (!(in >> limit)) limit = 20;
        return impl_->handle_findings(min_cvss, limit);
    }
    if (cmd == "affected") {
        std::string cve;
        in >> cve;
        return impl_->handle_affected(cve);
    }
    if (cmd == "dump") {
        std::string path, err;
        if (!crashdump::write_now("manual", path, err)) return error_json(err);
        JsonWriter w;
        w.begin_object();
        w.field("dump", path);
        w.end_object();
        return w.str();
    }
    return error_json("unknown command; expected ping|status|scan|findings|affected|dump");
}

} // namespace ns
