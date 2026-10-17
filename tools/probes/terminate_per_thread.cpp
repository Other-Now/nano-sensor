#include <cstdio>
#include <exception>
#include <stdexcept>
#include <thread>
#include <vector>
#include <windows.h>

void handler() {
    std::printf("CUSTOM terminate handler ran on thread %lu\n", GetCurrentThreadId());
    std::fflush(stdout);
    ExitProcess(42);
}

int main(int argc, char**) {
    std::set_terminate(handler);
    std::printf("main thread %lu installed handler\n", GetCurrentThreadId());
    std::fflush(stdout);
    if (argc > 1) {
        std::vector<int> v;
        (void)v.at(3);
    }
    std::thread t([] {
        std::vector<int> v;
        (void)v.at(3);
    });
    t.join();
    return 0;
}
