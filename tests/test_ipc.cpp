#include <gtest/gtest.h>

#include "ns/ipc.hpp"

#include <windows.h>

#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace {

// A unique pipe per test, so a crashed run cannot squat the next one.
std::string unique_pipe() {
    std::random_device rd;
    return R"(\\.\pipe\nano-sensor-test-)" + std::to_string(GetCurrentProcessId()) + "-" +
           std::to_string(rd());
}

ns::ipc::Handler echo() {
    return [](const std::string& req, const ns::ipc::ClientInfo&) { return "echo:" + req; };
}

// "Some other standard user": this process's token with the user SID and
// BUILTIN\Administrators turned deny-only. Everyone, Users, Authenticated
// Users and the rest stay enabled. So the token is not SYSTEM, not an
// elevated admin, and not the pipe's owner -- but it is a normal, logged-on
// local account, which an over-broad ACE (Everyone, Users) would admit.
HANDLE make_stranger_token() {
    HANDLE proc = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &proc)) {
        return nullptr;
    }
    DWORD len = 0;
    alignas(TOKEN_USER) unsigned char ubuf[256];
    GetTokenInformation(proc, TokenUser, ubuf, sizeof(ubuf), &len);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(ubuf);

    alignas(SID) unsigned char admins[SECURITY_MAX_SID_SIZE];
    DWORD admins_len = sizeof(admins);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &admins_len);

    // SIDs not present in the token are ignored, so this works the same in an
    // elevated CI runner and an unelevated developer shell.
    SID_AND_ATTRIBUTES deny[2] = {{user->User.Sid, 0}, {admins, 0}};

    HANDLE restricted = nullptr;
    const BOOL ok = CreateRestrictedToken(proc, 0, 2, deny, 0, nullptr, 0, nullptr, &restricted);
    CloseHandle(proc);
    if (!ok) return nullptr;

    HANDLE imp = nullptr;
    DuplicateToken(restricted, SecurityImpersonation, &imp);
    CloseHandle(restricted);
    return imp;
}

} // namespace

TEST(Ipc, round_trip_with_production_acl) {
    const auto name = unique_pipe();
    ns::ipc::Server server;
    ns::ipc::ClientInfo seen;
    std::string err;
    ASSERT_TRUE(server.start(name, ns::ipc::default_sddl(),
                             [&](const std::string& req, const ns::ipc::ClientInfo& who) {
                                 seen = who;
                                 return "echo:" + req;
                             },
                             err))
        << err;

    std::string resp;
    ASSERT_TRUE(ns::ipc::call(name, "status", resp, err)) << err;
    EXPECT_EQ(resp, "echo:status");
    EXPECT_EQ(server.requests_served(), 1u);

    // The server identified the caller by impersonating it.
    EXPECT_EQ(seen.pid, GetCurrentProcessId());
    EXPECT_NE(seen.user, "?");
    EXPECT_FALSE(seen.user.empty());
}

// The second pipe instance needs FILE_CREATE_PIPE_INSTANCE from the same DACL.
// Without the OWNER RIGHTS entry this is where the server would lock itself out.
TEST(Ipc, serves_many_sequential_and_concurrent_clients) {
    const auto name = unique_pipe();
    ns::ipc::Server server;
    std::string err;
    ASSERT_TRUE(server.start(name, ns::ipc::default_sddl(), echo(), err)) << err;

    for (int i = 0; i < 20; ++i) {
        std::string resp;
        ASSERT_TRUE(ns::ipc::call(name, "n" + std::to_string(i), resp, err)) << err;
        EXPECT_EQ(resp, "echo:n" + std::to_string(i));
    }

    std::vector<std::thread> ts;
    std::vector<std::string> errors(6);
    for (int i = 0; i < 6; ++i) {
        ts.emplace_back([&, i] {
            std::string r, e;
            if (!ns::ipc::call(name, "c" + std::to_string(i), r, e)) {
                errors[i] = e;
            } else if (r != "echo:c" + std::to_string(i)) {
                errors[i] = "wrong response: " + r;
            }
        });
    }
    for (auto& t : ts) t.join();
    for (int i = 0; i < 6; ++i) EXPECT_EQ(errors[i], "") << "client " << i;
}

TEST(Ipc, stranger_is_denied_by_the_kernel) {
    const auto name = unique_pipe();
    ns::ipc::Server server;
    std::string err;
    ASSERT_TRUE(server.start(name, ns::ipc::default_sddl(), echo(), err)) << err;

    HANDLE stranger = make_stranger_token();
    ASSERT_NE(stranger, nullptr);

    std::string resp;
    bool ok = true;
    std::uint32_t code = 0;
    std::thread t([&] {
        SetThreadToken(nullptr, stranger);
        ok = ns::ipc::call(name, "status", resp, err);
        code = ns::ipc::last_call_error();
        RevertToSelf();
    });
    t.join();
    CloseHandle(stranger);

    EXPECT_FALSE(ok);
    EXPECT_EQ(code, static_cast<std::uint32_t>(ERROR_ACCESS_DENIED)) << err;
    EXPECT_EQ(server.requests_served(), 0u);  // the server never saw it
}

// Control: the same stranger token IS admitted by a DACL that allows Everyone
// read/write -- so the denial above comes from our DACL, not from something
// incidental about restricted tokens. This is also the bug the default DACL
// exists to prevent: a pipe created with a NULL DACL or an Everyone ACE.
TEST(Ipc, stranger_admitted_by_permissive_acl_control) {
    const auto name = unique_pipe();
    ns::ipc::Server server;
    std::string err;
    // Everyone (WD) gets read/write; the owner keeps create-instance rights.
    ASSERT_TRUE(server.start(name, "D:P(A;;GRGW;;;WD)(A;;GA;;;OW)", echo(), err)) << err;

    HANDLE stranger = make_stranger_token();
    ASSERT_NE(stranger, nullptr);
    std::string resp;
    bool ok = false;
    std::thread t([&] {
        SetThreadToken(nullptr, stranger);
        ok = ns::ipc::call(name, "hi", resp, err);
        RevertToSelf();
    });
    t.join();
    CloseHandle(stranger);

    EXPECT_TRUE(ok) << err;
    EXPECT_EQ(resp, "echo:hi");
}

TEST(Ipc, refuses_to_share_a_squatted_name) {
    const auto name = unique_pipe();
    std::wstring wname(name.begin(), name.end());

    // Someone else got there first.
    HANDLE squatter = CreateNamedPipeW(wname.c_str(), PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_WAIT, 4, 4096, 4096, 0, nullptr);
    ASSERT_NE(squatter, INVALID_HANDLE_VALUE);

    ns::ipc::Server server;
    std::string err;
    EXPECT_FALSE(server.start(name, ns::ipc::default_sddl(), echo(), err));
    EXPECT_NE(err.find("already in use"), std::string::npos) << err;
    CloseHandle(squatter);
}

TEST(Ipc, large_response_crosses_message_buffers) {
    const auto name = unique_pipe();
    ns::ipc::Server server;
    std::string err;
    const std::string big(300 * 1024, 'x');
    ASSERT_TRUE(server.start(name, ns::ipc::default_sddl(),
                             [&](const std::string&, const ns::ipc::ClientInfo&) { return big; },
                             err))
        << err;
    std::string resp;
    ASSERT_TRUE(ns::ipc::call(name, "big", resp, err)) << err;
    EXPECT_EQ(resp.size(), big.size());
    EXPECT_EQ(resp, big);
}

TEST(Ipc, oversized_request_is_rejected) {
    const auto name = unique_pipe();
    ns::ipc::Server server;
    std::string err;
    ASSERT_TRUE(server.start(name, ns::ipc::default_sddl(), echo(), err)) << err;
    std::string resp;
    ASSERT_TRUE(ns::ipc::call(name, std::string(8000, 'a'), resp, err)) << err;
    EXPECT_EQ(resp, R"({"error":"request too large"})");
    EXPECT_EQ(server.requests_served(), 0u);
}

// A wedged server costs the client its timeout, not forever. This is what
// keeps `nsctl status` usable against a deadlocked service.
TEST(Ipc, client_times_out_on_a_hung_server) {
    const auto name = unique_pipe();
    ns::ipc::Server server;
    std::string err;
    ASSERT_TRUE(server.start(name, ns::ipc::default_sddl(),
                             [](const std::string&, const ns::ipc::ClientInfo&) {
                                 std::this_thread::sleep_for(std::chrono::milliseconds(1500));
                                 return std::string("late");
                             },
                             err))
        << err;

    const auto t0 = std::chrono::steady_clock::now();
    std::string resp;
    EXPECT_FALSE(ns::ipc::call(name, "status", resp, err, 200));
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    EXPECT_LT(ms, 1000);
    EXPECT_NE(err.find("did not answer"), std::string::npos) << err;
}

TEST(Ipc, no_server_is_a_clear_error) {
    std::string resp, err;
    EXPECT_FALSE(ns::ipc::call(unique_pipe(), "status", resp, err, 200));
    EXPECT_NE(err.find("no server"), std::string::npos) << err;
}

TEST(Ipc, stop_is_prompt_with_no_clients) {
    ns::ipc::Server server;
    std::string err;
    ASSERT_TRUE(server.start(unique_pipe(), ns::ipc::default_sddl(), echo(), err)) << err;
    const auto t0 = std::chrono::steady_clock::now();
    server.stop();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    EXPECT_LT(ms, 500);
}
