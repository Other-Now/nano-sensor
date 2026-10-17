#include "ns/ipc.hpp"

#include "ns/crashdump.hpp"
#include "ns/log.hpp"

#include <windows.h>
#include <sddl.h>

#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

namespace ns::ipc {

namespace {

constexpr DWORD kMaxInstances = 8;
constexpr DWORD kBufferBytes = 64 * 1024;
constexpr DWORD kMaxRequestBytes = 4 * 1024;

thread_local std::uint32_t t_last_call_error = 0;

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), n);
    out.pop_back();
    return out;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
    out.pop_back();
    return out;
}

std::string win_error(const char* what, DWORD err) {
    return std::string(what) + " failed, error " + std::to_string(err) +
           (err == ERROR_ACCESS_DENIED ? " (access denied)" : "");
}

// Who is on the other end. The client connected at SECURITY_IDENTIFICATION,
// so impersonating it yields a token that can be *queried* but not used to
// open anything -- which is all this needs.
//
// The SID is copied out and resolved to a name only AFTER RevertToSelf.
// LookupAccountSid is an RPC to LSA, and a thread impersonating at
// Identification level cannot make calls as that identity -- the first
// version looked the name up while still impersonating, and every caller came
// back as "?".
std::string client_user(HANDLE pipe) {
    if (!ImpersonateNamedPipeClient(pipe)) {
        return "?(impersonate " + std::to_string(GetLastError()) + ")";
    }

    alignas(SID) unsigned char sid[SECURITY_MAX_SID_SIZE];
    bool have_sid = false;
    DWORD err = 0;
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        alignas(TOKEN_USER) unsigned char buf[256];
        DWORD len = 0;
        if (GetTokenInformation(token, TokenUser, buf, sizeof(buf), &len)) {
            const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf);
            have_sid = CopySid(sizeof(sid), sid, tu->User.Sid) != FALSE;
        }
        if (!have_sid) err = GetLastError();
        CloseHandle(token);
    } else {
        err = GetLastError();
    }

    // Failing to stop impersonating would leave this thread running as the
    // client for every later request. There is no safe way to continue.
    if (!RevertToSelf()) TerminateProcess(GetCurrentProcess(), 0xE0000002);

    if (!have_sid) return "?(token " + std::to_string(err) + ")";
    wchar_t name[256], domain[256];
    DWORD nlen = 256, dlen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, sid, name, &nlen, domain, &dlen, &use)) {
        return "?(lookup " + std::to_string(GetLastError()) + ")";
    }
    return narrow(std::wstring(domain) + L"\\" + name);
}

} // namespace

std::string default_sddl() { return "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"; }

struct Server::Impl {
    std::wstring name;
    PSECURITY_DESCRIPTOR sd = nullptr;
    SECURITY_ATTRIBUTES sa{};
    Handler handler;

    std::atomic<bool> stopping{false};
    std::atomic<std::uint64_t> served{0};
    std::thread acceptor;
    std::atomic<bool> acceptor_done{false};

    struct Client {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex mu;
    std::vector<Client> clients;

    HANDLE create_instance(bool first) {
        const DWORD open_mode = PIPE_ACCESS_DUPLEX | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
        // PIPE_REJECT_REMOTE_CLIENTS: the pipe is not reachable over SMB at all.
        // The NU deny ACE in the DACL says the same thing; two independent
        // locks, because a DACL edit by a careless admin should not be enough
        // to expose the service to the network.
        const DWORD pipe_mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
                                PIPE_REJECT_REMOTE_CLIENTS;
        return CreateNamedPipeW(name.c_str(), open_mode, pipe_mode, kMaxInstances,
                                kBufferBytes, kBufferBytes, 0, &sa);
    }

    void reap(bool all) {
        std::lock_guard<std::mutex> lock(mu);
        for (auto it = clients.begin(); it != clients.end();) {
            if (all || it->done->load()) {
                it->thread.join();
                it = clients.erase(it);
            } else {
                ++it;
            }
        }
    }

    void serve(HANDLE pipe) {
        crashdump::on_thread_start();

        char req[kMaxRequestBytes];
        DWORD got = 0;
        if (!ReadFile(pipe, req, sizeof(req), &got, nullptr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_MORE_DATA) {
                const std::string msg = R"({"error":"request too large"})";
                DWORD put = 0;
                WriteFile(pipe, msg.data(), static_cast<DWORD>(msg.size()), &put, nullptr);
            }
            CloseHandle(pipe);
            return;
        }

        ClientInfo who;
        ULONG pid = 0;
        if (GetNamedPipeClientProcessId(pipe, &pid)) who.pid = pid;
        who.user = client_user(pipe);

        const std::string request(req, got);
        log_debug("pipe request", {{"request", request},
                                   {"client_pid", std::to_string(who.pid)},
                                   {"client_user", who.user}});

        const std::string response = handler(request, who);
        served.fetch_add(1);

        DWORD put = 0;
        if (WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &put,
                      nullptr)) {
            // Wait for the client to close its end before closing ours. Closing
            // first could discard a response the client has not read yet.
            char sink;
            DWORD n = 0;
            ReadFile(pipe, &sink, 1, &n, nullptr);
        }
        CloseHandle(pipe);
    }

    // Next listening instance. ERROR_PIPE_BUSY means all kMaxInstances are in
    // use; wait for one to finish rather than spinning.
    HANDLE next_instance() {
        for (;;) {
            HANDLE h = create_instance(false);
            if (h != INVALID_HANDLE_VALUE || stopping.load()) return h;
            const DWORD err = GetLastError();
            if (err != ERROR_PIPE_BUSY) {
                log_error("cannot create pipe instance", {{"error", std::to_string(err)}});
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            reap(false);
        }
    }

    void accept_loop(HANDLE instance) {
        crashdump::on_thread_start();

        while (!stopping.load() && instance != INVALID_HANDLE_VALUE) {
            const BOOL connected =
                ConnectNamedPipe(instance, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
            if (stopping.load()) break;

            // Create the next listening instance BEFORE handing this one off.
            // In the other order there is a window where the only instances
            // are busy ones that are about to close. A client arriving then
            // gets ERROR_PIPE_BUSY, calls WaitNamedPipe, the busy instances
            // close, the pipe has zero instances, and WaitNamedPipe fails with
            // ERROR_FILE_NOT_FOUND -- which reads as "service not running".
            // The concurrent-client test caught it (2 of 6 clients refused,
            // ~1 run in 2); in this order, 0 failures in 200 repeats.
            HANDLE connected_instance = instance;
            instance = next_instance();

            if (connected) {
                auto done = std::make_shared<std::atomic<bool>>(false);
                std::thread t([this, connected_instance, done] {
                    serve(connected_instance);
                    done->store(true);
                });
                std::lock_guard<std::mutex> lock(mu);
                clients.push_back({std::move(t), done});
            } else {
                CloseHandle(connected_instance);
            }
            reap(false);
        }
        if (instance != INVALID_HANDLE_VALUE) CloseHandle(instance);
        acceptor_done.store(true);
    }
};

Server::Server() : impl_(std::make_unique<Impl>()) {}
Server::~Server() { stop(); }

bool Server::start(const std::string& pipe_name, const std::string& sddl, Handler handler,
                   std::string& error) {
    impl_->name = widen(pipe_name);
    impl_->handler = std::move(handler);

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            widen(sddl).c_str(), SDDL_REVISION_1, &impl_->sd, nullptr)) {
        error = win_error("parsing the pipe SDDL", GetLastError());
        return false;
    }
    impl_->sa.nLength = sizeof(impl_->sa);
    impl_->sa.lpSecurityDescriptor = impl_->sd;
    impl_->sa.bInheritHandle = FALSE;

    HANDLE first = impl_->create_instance(true);
    if (first == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        error = (err == ERROR_ACCESS_DENIED)
                    ? "pipe name already in use by another process (possible squatter); "
                      "refusing to share it"
                    : win_error("CreateNamedPipe", err);
        return false;
    }

    impl_->acceptor = std::thread([this, first] { impl_->accept_loop(first); });
    return true;
}

void Server::stop() {
    if (!impl_ || !impl_->acceptor.joinable()) return;
    impl_->stopping.store(true);

    // The acceptor is blocked in ConnectNamedPipe. Cancel it, and connect to
    // ourselves as a fallback -- CancelSynchronousIo is a no-op if the thread
    // has not reached the call yet, and then it would block forever.
    while (!impl_->acceptor_done.load()) {
        CancelSynchronousIo(impl_->acceptor.native_handle());
        HANDLE h = CreateFileW(impl_->name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    impl_->acceptor.join();

    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        for (auto& c : impl_->clients) {
            if (!c.done->load()) CancelSynchronousIo(c.thread.native_handle());
        }
    }
    impl_->reap(true);

    if (impl_->sd) {
        LocalFree(impl_->sd);
        impl_->sd = nullptr;
    }
}

std::uint64_t Server::requests_served() const { return impl_->served.load(); }

std::uint32_t last_call_error() { return t_last_call_error; }

bool call(const std::string& pipe_name, const std::string& request, std::string& response,
          std::string& error, std::uint32_t timeout_ms) {
    t_last_call_error = 0;
    const std::wstring name = widen(pipe_name);
    const auto fail = [&](const char* what, DWORD err) {
        t_last_call_error = err;
        error = win_error(what, err);
        return false;
    };

    HANDLE h = INVALID_HANDLE_VALUE;
    for (;;) {
        h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY) {
            // Every instance is connected; wait for one to listen. Note that
            // WaitNamedPipe returns at once with ERROR_FILE_NOT_FOUND if the
            // pipe has no instances at all at that moment.
            if (WaitNamedPipeW(name.c_str(), timeout_ms)) continue;
            err = GetLastError();
            if (err == ERROR_SEM_TIMEOUT) return fail("waiting for a free pipe instance", err);
        }
        if (err == ERROR_FILE_NOT_FOUND) {
            t_last_call_error = err;
            error = "no server on " + pipe_name + " (is the service running?)";
            return false;
        }
        return fail("opening the pipe", err);
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);

    // Overlapped I/O so a wedged server -- say, a deadlocked one -- costs the
    // caller timeout_ms, not forever.
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const auto wait_io = [&](BOOL started, DWORD& n) -> DWORD {
        if (started) {
            return GetOverlappedResult(h, &ov, &n, FALSE) ? 0 : GetLastError();
        }
        DWORD err = GetLastError();
        if (err == ERROR_MORE_DATA) {
            // Completed immediately with part of a message; still need the count.
            GetOverlappedResult(h, &ov, &n, FALSE);
            return err;
        }
        if (err != ERROR_IO_PENDING) return err;
        if (WaitForSingleObject(ov.hEvent, timeout_ms) != WAIT_OBJECT_0) {
            CancelIoEx(h, &ov);
            GetOverlappedResult(h, &ov, &n, TRUE);
            return WAIT_TIMEOUT;
        }
        return GetOverlappedResult(h, &ov, &n, FALSE) ? 0 : GetLastError();
    };

    bool ok = false;
    DWORD n = 0;
    DWORD err = wait_io(
        WriteFile(h, request.data(), static_cast<DWORD>(request.size()), nullptr, &ov), n);
    if (err != 0) {
        fail("writing the request", err);
    } else {
        response.clear();
        char buf[16 * 1024];
        for (;;) {
            ResetEvent(ov.hEvent);
            err = wait_io(ReadFile(h, buf, sizeof(buf), nullptr, &ov), n);
            if (err == 0 || err == ERROR_MORE_DATA) response.append(buf, n);
            if (err == ERROR_MORE_DATA) continue;
            if (err == 0) {
                ok = true;
            } else if (err == WAIT_TIMEOUT) {
                t_last_call_error = err;
                error = "server did not answer within " + std::to_string(timeout_ms) + " ms";
            } else {
                fail("reading the response", err);
            }
            break;
        }
    }

    CloseHandle(ov.hEvent);
    CloseHandle(h);
    return ok;
}

} // namespace ns::ipc
