# Crash dumps and three planted bugs

The service runs unattended under an account nobody logs in as. When it dies,
the only evidence it leaves is what it writes on the way down. This document
covers how it writes that evidence (minidumps), and three bugs debugged from
the dumps alone, without attaching a debugger to a live process.

The bugs are **planted**: real code paths whose buggy variant is switched back
on with `--inject-fault`. That makes every result here reproducible from a
clean checkout:

```powershell
powershell -File tools\repro_fault.ps1 -Fault uaf            # bug 1
powershell -File tools\repro_fault.ps1 -Fault deadlock       # bug 2
powershell -File tools\repro_fault.ps1 -Fault worker-crash   # bug 3
powershell -File tools\analyze_dump.ps1 -Dump <path from the line above>
```

`analyze_dump.ps1` runs `cdb` (the console engine behind WinDbg) with the
build's PDBs and Microsoft's symbol server. The same `.dmp` opens in Visual
Studio. See [Opening the dumps in Visual Studio](#opening-the-dumps-in-visual-studio).

## How dumps get written

[src/crashdump_windows.cpp](../src/crashdump_windows.cpp) routes every way the
process can die into one `MiniDumpWriteDump` call:

| path | hook | dump name |
|---|---|---|
| access violation etc., any thread | `SetUnhandledExceptionFilter` | `*-crash.dmp` |
| C++ exception nobody catches | `std::set_terminate`, **per thread** (bug 3) | `*-terminate.dmp` |
| pure virtual call, CRT invalid parameter | `_set_purecall_handler`, `_set_invalid_parameter_handler` | `*-purecall.dmp` ... |
| deadlock / hang | watchdog thread, no exception | `*-hang.dmp` |
| on demand | `nsctl dump` | `*-manual.dmp` |

Choices that matter:

- **Dump type:** `MiniDumpWithIndirectlyReferencedMemory` plus thread, handle
  and data-segment info. This captures the heap blocks that stack values point
  at, which is what made bug 1's freed object visible. That's about 1.7 MB per
  dump; a full-memory dump would be about 100× larger.
- **Terminate and purecall dumps raise a real SEH exception first** (code
  `0xE0000001`) and write the dump from its `__except` filter. So the dump has
  an exception record, and `.ecxr` lands on the dying thread. A plain
  `MiniDumpWriteDump` from the handler would produce a dump with no exception
  in it.
- **Nothing on the crash path allocates.** The path is built in a fixed buffer,
  and `dbghelp.dll` is loaded at startup, not inside the handler. Inside the
  handler, the loader lock or the heap may be what just broke.
- **PDBs for every config, Release included** (`/Zi` + `/DEBUG`). They stay
  with the build and are not shipped to hosts. "Stay with the build" was not
  enough: after a rebuild, the real hang dump in [SERVICE.md](SERVICE.md)
  could no longer be symbolized (`nano_sensor+0x860fc`), because the PDB no
  longer matched the binary that crashed. Every shipped build's PDB belongs in
  a symbol store (`symstore.exe`), keyed by build. That is not automated here.

## Bug 1: use-after-free across threads

**Symptom.** `nsctl scan 1000` returns `{"completed":false,...}`. About 2 s
later the service dies with `0xC0000005` (access violation).

**The dump** (Debug build), `.ecxr`:

```
rax=dddddddddddddddd ... rcx=000001fdf2314320
nano_sensor!ns::Agent::Impl::run_scan+0x786 [src\agent.cpp @ 371]:
00007ff6`d9d50606 488b4008  mov rax,qword ptr [rax+8] ds:dddddddd`dddddde5=????????????????
```

- `rax` holds the object's **vtable pointer**, and it is `0xDDDDDDDDDDDDDDDD`.
  The MSVC debug heap fills freed blocks with `0xDD`, so this object has been
  deleted.
- `[rax+8]` is vtable slot 1, the first virtual after the destructor:
  `ScanListener::on_scan_complete`.
- Line 371 is `for (auto& l : waiting) l->on_scan_complete(r);`, on the
  **scan worker thread** (`kn` shows `worker_loop` → `run_scan`).

The object the `shared_ptr` points at
([full transcript](evidence/bug1-uaf-windbg.txt)):

```
0:010> dx -r1 l
l : {...} [Type: std::shared_ptr<ScanListener>]
    [ptr] : 0x2002cf95090
0:010> dq poi(@rcx) L8
00000200`2cf95090  dddddddd`dddddddd dddddddd`dddddddd
00000200`2cf950a0  dddddddd`dddddddd dddddddd`dddddddd
...
```

Every byte of the object is freed-fill, yet a live `shared_ptr` points at it.
In the first capture, the shared_ptr's control block was in the dump too and
read `_Uses = 1`: the `shared_ptr` believed its object was alive. It never
owned the object. It was built with a no-op deleter around a raw pointer whose
real owner was the pipe handler. (Whether the control block lands in a
minidump depends on whether some stack value points at it.)

**Root cause.** The `scan` handler (`handle_scan`) allocates a `ScanWaiter`,
registers it with the worker, and waits up to `wait_ms`. On timeout it
`delete`s the waiter. The waiter is still registered, so when the scan
finishes, the worker calls into freed memory.

**Fix (the default code path).** The waiter is `std::make_shared` and
registered as a real `shared_ptr`. If the handler gives up, the worker's
reference keeps the waiter alive until it has delivered the result, and the
last reference frees it.

**Release builds hide it.** The same repro against the RelWithDebInfo build
did not crash in 3 of 3 runs. Nothing scrubs a freed block in a release
build, so the stale vtable pointer was presumably still intact and the call
"worked". `on_scan_complete` then wrote into a freed block: heap corruption
that surfaces later, somewhere unrelated.
Under AddressSanitizer (`cmake -B build-asan -DNS_ASAN=ON`) the same release
code stops at the bad read with the whole history:

```
ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8 ... thread T5
    #0 ns::Agent::Impl::run_scan        src\agent.cpp:371
freed by thread T6 here:
    #1 ns::Agent::Impl::handle_scan     src\agent.cpp:456
previously allocated by thread T6 here:
    #1 ns::Agent::Impl::handle_scan     src\agent.cpp:449
```

([full ASan report](evidence/bug1-uaf-asan.txt))

## Bug 2: deadlock (lock-order inversion)

**Symptom.** `nsctl status` sent while a scan is writing to SQL Server never
answers. The client gives up at its own 3 s timeout (`server did not answer
within 3000 ms`). At 10 s, the watchdog writes a hang dump and exits with
code 4.

The service would otherwise show RUNNING in the SCM forever while doing
nothing. A hang that leaves no evidence is worse than a crash, which is why
the watchdog exists.

**The dump.** There's no exception to jump to, so start with every thread
(`~*kn`). Two threads are parked in `RtlAcquireSRWLockExclusive`, which is
what `std::mutex::lock` becomes on MSVC:

```
  10  ... ntdll!RtlAcquireSRWLockExclusive
          MSVCP140D!_Mtx_lock
          nano_sensor!ns::Agent::Impl::run_scan+0x25d      [src\agent.cpp @ 335]
          nano_sensor!ns::Agent::Impl::worker_loop

  11  ... ntdll!RtlAcquireSRWLockExclusive
          MSVCP140D!_Mtx_lock
          nano_sensor!ns::Agent::Impl::handle_status+0x9a3 [src\agent.cpp @ 417]
          nano_sensor!ns::Agent::handle
```

Which mutex each thread wants, and who owns each one
([full transcript](evidence/bug2-deadlock-windbg.txt)):

```
0:010> .frame 6 ; dv            -> _Mtx = 0x14c2a7e6c58     (thread 10 wants state_mu)
0:011> .frame 6 ; dv            -> _Mtx = 0x14c2a7e6c00     (thread 11 wants db_mu)

0:010> dx &this->db_mu      : 0x14c2a7e6c00 : locked   [locking_thread_id] : 7752   = 0x1E48 = thread 10
0:010> dx &this->state_mu   : 0x14c2a7e6c58 : locked   [locking_thread_id] : 4796   = 0x12BC = thread 11
```

Thread 10 holds `db_mu` and wants `state_mu`; thread 11 holds `state_mu` and
wants `db_mu`. That's a cycle.

A raw `SRWLOCK` does not record its owner, and `!locks` only understands
`CRITICAL_SECTION`. MSVC's `std::mutex` keeps the owning thread id next to the
SRW lock, and the debugger's STL visualiser shows it. That turns "these two
threads look stuck" into proof.

**Root cause.** `run_scan` takes `db_mu` and then `state_mu`; `handle_status`
takes `state_mu` and then `db_mu`.

**Fix (the default code path).** One rule, written at the top of
`Agent::Impl`: never hold both. The scan releases `db_mu` before updating
state. `status` copies state under `state_mu`, releases it, and only then
takes `db_mu` for the live row count.

## Bug 3: a C++ exception on a worker thread left no dump

**Symptom (before the fix).** The service vanished. Exit code `0xC0000409`. No
dump, no log line. Nothing.

**Why.** The planted bug is an off-by-one: `sorted.at(sorted.size())` in
`worst_finding`, on the scan worker thread. It throws `std::out_of_range`,
nothing catches it, and the C++ runtime calls `std::terminate`. But:

1. **MSVC keeps the terminate handler per thread.** `std::set_terminate` in
   `main` does nothing for threads started later; they still have the default
   handler, which calls `abort()`.
   [tools/probes/terminate_per_thread.cpp](../tools/probes/terminate_per_thread.cpp)
   shows it in 30 lines. The same throw runs the custom handler on the main
   thread (exit 42) and skips it on a worker thread (`0xC0000409`).
2. **In a release build, `abort()` is `__fastfail`.** That exits through
   `0xC0000409` (`STATUS_STACK_BUFFER_OVERRUN`, reused as "fail fast") and
   **bypasses `SetUnhandledExceptionFilter` by design**. So the crash filter
   never ran either.

The A/B, release build (`-Config RelWithDebInfo`):

| | exit code | dump | log |
|---|---|---|---|
| worker thread **without** `crashdump::on_thread_start()` | `0xC0000409` | none | nothing after "inventory collected" |
| worker thread **with** it | `0xE0000001` | `*-terminate.dmp` | `"uncaught C++ exception","what":"invalid vector subscript"` |

**Testing only in Debug hides this.** In the Debug build, `abort()` raises a
breakpoint exception (`0x80000003`) instead of fast-failing. That exception
*does* reach the unhandled-exception filter, so a dump appeared and the gap
was invisible. The process then hung on the hidden "abort() has been called"
dialog until the watchdog killed it.

**The dump (after the fix)**, `.ecxr; kn`
([full transcript](evidence/bug3-worker-crash-windbg.txt)):

```
00 KERNELBASE!RaiseException
01 nano_sensor!ns::crashdump::raise_and_dump        [src\crashdump_windows.cpp @ 112]
02 nano_sensor!ns::crashdump::terminate_handler     [src\crashdump_windows.cpp @ 138]
03 ucrtbased!terminate
04 VCRUNTIME140_1D!FindHandler<__FrameHandler4>
   ...
0b KERNELBASE!RaiseException
0c VCRUNTIME140D!_CxxThrowException
0d MSVCP140D!std::_Xout_of_range
0f nano_sensor!std::vector<...>::at                 [vector @ 1950]
10 nano_sensor!ns::`anonymous namespace'::worst_finding   [src\agent.cpp @ 176]
11 nano_sensor!ns::Agent::Impl::run_scan              [src\agent.cpp @ 319]
12 nano_sensor!ns::Agent::Impl::worker_loop
```

The throwing frame is still on the stack. `_CxxFrameHandler4` (frame 04)
calls `terminate()` during the *search* phase, when it finds no handler,
before unwinding anything. So a dump written from the terminate handler shows
exactly where the exception was thrown, with that frame's locals intact.

**Fix.** Every thread the agent starts (scan worker, watchdog, pipe acceptor,
each pipe client thread) calls `crashdump::on_thread_start()` first. The
off-by-one itself is fixed in the default path (`max_element`, with an empty
check).

## Opening the dumps in Visual Studio

The dumps open the same way in Visual Studio 2022 (Community is free). The
steps:

1. **File → Open → File…**, pick the `.dmp`. VS shows the *Minidump File
   Summary*: exception code, faulting module, and the module list with symbol
   status.
2. **Set symbol paths**: point VS at `build\bin\Debug` (or the config that
   crashed). Under **Tools → Options → Debugging → Symbols**, enable
   *Microsoft Symbol Servers*.
3. **Debug with Native Only**. VS stops on the faulting instruction, as if the
   crash had just happened under the debugger.
4. Bug 1: in the **Autos/Locals** window, expand `l` (the `shared_ptr`):
   `[ptr]` points at memory whose vtable shows `0xdddddddddddddddd`. A
   **Memory** window on that address shows the `0xDD` fill.
5. Bug 2: **Debug → Windows → Parallel Stacks** shows the two threads blocked
   in `_Mtx_lock`. **Threads** → double-click each → **Locals** shows which
   `std::mutex` each is waiting on, and the visualiser shows its
   `locking_thread_id`.
6. Bug 3: the **Call Stack** window shows `worst_finding` → `vector::at` below
   the terminate handler. Double-click the frame to see `sorted` and its size.
