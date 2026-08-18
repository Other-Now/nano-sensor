#include "ns/service.hpp"

#include "ns/log.hpp"

#include <windows.h>

#include <atomic>
#include <string>

namespace ns::service {

namespace {

std::atomic<bool> g_stop{false};
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
std::function<int()> g_body;
int g_exit_code = 0;

const wchar_t* kServiceNameW = L"nano-sensor";

void report_status(DWORD state, DWORD wait_hint_ms = 0) {
    if (!g_status_handle) return;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = NO_ERROR;
    g_status.dwWaitHint = wait_hint_ms;

    // Accepting STOP only once actually running. Advertising it during
    // START_PENDING invites the SCM to send a stop the handler is not yet ready
    // to service.
    g_status.dwControlsAccepted =
        (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;

    // The checkpoint must advance during any *_PENDING state or the SCM decides
    // the service has hung and kills it.
    static DWORD checkpoint = 1;
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;

    SetServiceStatus(g_status_handle, &g_status);
}

void WINAPI control_handler(DWORD control) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        // Report STOP_PENDING with a generous hint BEFORE setting the flag: the
        // agent finishes its current cycle, and without the hint the SCM would
        // consider a mid-collection stop to be a hang.
        report_status(SERVICE_STOP_PENDING, 30000);
        g_stop.store(true, std::memory_order_relaxed);
        break;
    default:
        break;
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerW(kServiceNameW, control_handler);
    if (!g_status_handle) return;

    report_status(SERVICE_START_PENDING, 5000);
    report_status(SERVICE_RUNNING);

    g_exit_code = g_body ? g_body() : 0;

    report_status(SERVICE_STOPPED);
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int need = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(need), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), need);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

BOOL WINAPI console_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop.store(true, std::memory_order_relaxed);
        return TRUE;
    }
    return FALSE;
}

} // namespace

const char* name() { return "nano-sensor"; }

bool stop_requested() { return g_stop.load(std::memory_order_relaxed); }
void request_stop() { g_stop.store(true, std::memory_order_relaxed); }

int run(const std::function<int()>& body) {
    g_body = body;

    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceNameW), service_main},
        {nullptr, nullptr},
    };

    if (StartServiceCtrlDispatcherW(table)) {
        return g_exit_code;
    }

    // Not launched by the SCM. This is the expected path when a human runs the
    // binary from a console, and it is what lets one executable be both the
    // service and the interactive tool.
    const DWORD err = GetLastError();
    if (err != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        log_warn("service dispatcher failed; running in the foreground",
                 {{"error", std::to_string(err)}});
    }
    SetConsoleCtrlHandler(console_handler, TRUE);
    return body();
}

bool install(const std::string& exe_path, const std::string& arguments,
             std::string& error) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!manager) {
        error = "OpenSCManager failed (Administrator required), error " +
                std::to_string(GetLastError());
        return false;
    }

    // The registered command line must be absolute and quoted. An unquoted path
    // containing a space is the classic unquoted-service-path privilege
    // escalation: Windows would try C:\Program.exe before
    // C:\Program Files\...\nano-sensor.exe, and anyone who can write to C:\
    // then owns a SYSTEM service.
    const std::string command = "\"" + exe_path + "\"" +
                                (arguments.empty() ? "" : " " + arguments);

    SC_HANDLE svc = CreateServiceW(
        manager, kServiceNameW, L"nano-sensor security sensor",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, widen(command).c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!svc) {
        const DWORD err = GetLastError();
        error = (err == ERROR_SERVICE_EXISTS)
                    ? "the nano-sensor service is already installed"
                    : "CreateService failed, error " + std::to_string(err);
        CloseServiceHandle(manager);
        return false;
    }

    // Restart on crash, twice, then give up and leave it stopped for a human.
    // A sensor that silently restart-loops forever is worse than one that is
    // visibly down.
    SC_ACTION actions[3] = {};
    actions[0] = {SC_ACTION_RESTART, 10000};
    actions[1] = {SC_ACTION_RESTART, 30000};
    actions[2] = {SC_ACTION_NONE, 0};
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 86400;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    CloseServiceHandle(svc);
    CloseServiceHandle(manager);
    return true;
}

bool uninstall(std::string& error) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        error = "OpenSCManager failed (Administrator required), error " +
                std::to_string(GetLastError());
        return false;
    }

    SC_HANDLE svc = OpenServiceW(manager, kServiceNameW, SERVICE_STOP | DELETE);
    if (!svc) {
        error = "the nano-sensor service is not installed";
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);  // best effort

    const bool ok = DeleteService(svc) != 0;
    if (!ok) error = "DeleteService failed, error " + std::to_string(GetLastError());

    CloseServiceHandle(svc);
    CloseServiceHandle(manager);
    return ok;
}

} // namespace ns::service
