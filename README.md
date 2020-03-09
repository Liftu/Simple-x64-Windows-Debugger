# Simple x64 Windows Debugger
Just a simple x64 Windows debugger written in C++

## Documentation
### Used WinAPI functions
These are the usefull functions provided by the Windows API which are used for making the core functionalities of this debugger.

#### Processes functions
- [CreateProcessA][CreateProcessA_Link] : Creates a new process. Setting **DEBUG_PROCESS** as a flag for the **dwCreationFlags** parameter allows the process to receive all related debug events using the [WaitForDebugEvent](#debugging-functions) function.

- [OpenProcess][OpenProcess_Link] : Opens an existing process. In order to perform debugging, we have to set the **dwDesiredAccess** parameter to **PROCESS_ALL_ACCESS**.

<!-- - [Process32First][Process32First_link]
- [Process32Next][Process32Next_Link] -->

#### Debugging functions
- [DebugActiveProcess][DebugActiveProcess_Link] : Attach the debugger to an active process.

- [WaitForDebugEvent][WaitForDebugEvent_Link] : Waits for a debugging event to occur in a debugged process. The provided [DEBUG_EVENT][DEBUG_EVENT_Link] structure contains a **dwDebugEventCode** member that can informs us if the event comes from a breakpoint (**EXCEPTION_DEBUG_EVENT**). If the event is triggered by a breakpoint, then the **u** member would be an [EXCEPTION_DEBUG_INFO][EXCEPTION_DEBUG_INFO_Link] structure which can provides us extra informations about the event via its [EXCEPTION_RECORD][EXCEPTION_RECORD_Link] structure member.

- [ContinueDebugEvent][ContinueDebugEvent_Link] : Enables a debugger to continue a thread that previously reported a debugging event. The options to continue the thread that reported the debugging event have to be specified inside the **dwContinueStatus** parameter.


#### Threads functions
- [CreateToolhelp32Snapshot][CreateToolhelp32Snapshot_Link] : Creates a snapshot of a given process. Setting **TH32CS_SNAPTHREAD** as a flag for **dwFlags** will provides all the threads in the snapshot. We will then have to compare each thread's owner ID to the ID of the debugged process.

- [Thread32First][Thread32First_Link] : Retrieves the first thread of a process' snapshot as a [THREADENTRY32][THREADENTRY32_Link] structure.

- [Thread32Next][Thread32Next_Link] : Loops through the rest of the threads of a process' snapshot.

- [OpenThread][OpenThread_Link] : Opens a thread so we can get its context.

- [GetThreadContext][GetThreadContext_Link] : Retrieves the context of a given thread in which we can find all its registers' states. Feeding the [CONTEXT][CONTEXT_Link] with **CONTEXT_FULL** and **CONTEXT_DEBUG_REGISTERS** grants us access to all of the thread's registers we need.

- [SetThreadContext][SetThreadContext_Link] : Sets the context of a given thread which allows us to modify its registers' states.


#### Memory functions
- [ReadProcessMemory][ReadProcessMemory_Link] : Reads the memory of a process at a given address.

- [WriteProcessMemory][WriteProcessMemory_Link] : Writes to the memory of a process at a given address.

##### Memory pages related functions
- [GetSystemInfo][GetSystemInfo_Link] : Provides us a [SYSTEM_INFO][SYSTEM_INFO_Link] stucture that contains a **dwPageSize** member which gives us the correct page size of the system.

- [VirtualQueryEx][VirtualQueryEx_Link] : Retrieves informations about the memory page of a given address of a process. The [MEMORY_BASIC_INFORMATION][MEMORY_BASIC_INFORMATION_Link] structure provides us the **BaseAddress** of the memory page as well as its access **Protect**ion (which are defined in the [Memory Protection Constants][Memory_Protection_contants_Link])

- [VirtualProtectEx][VirtualProtectEx_Link] : Allows us to edit the access protection of a given memory page of a process. We can add a **GUARD_PAGE** access protection to a memory page in order to trigger memory breakpoint on access to this page.


#### Address resolving functions
- [GetModuleHandle][GetModuleHandleA_Link] : Provides a **HMODULE** handle of a specified loaded module.

- [GetProcAddress][GetProcAddress_Link] : Retrieves the address of an exported function or variable from a given module handle.





[CreateProcessA_Link]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
[OpenProcess_Link]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
[Process32First_link]: https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
[Process32Next_Link]: https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next

[DebugActiveProcess_Link]: https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess
[WaitForDebugEvent_Link]: https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent
[ContinueDebugEvent_Link]: https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent

[CreateToolhelp32Snapshot_Link]: https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
[Thread32First_Link]: https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first
[Thread32Next_Link]: https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next
[OpenThread_link]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
[GetThreadContext_Link]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext
[SetThreadContext_Link]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext

[ReadProcessMemory_Link]: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
[WriteProcessMemory_Link]: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

[GetSystemInfo_Link]: https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo
[VirtualQueryEx_Link]: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
[VirtualProtectEx_Link]: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex

[GetModuleHandleA_Link]: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
[GetProcAddress_Link]: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress


[DEBUG_EVENT_Link]: https://docs.microsoft.com/fr-fr/windows/win32/api/minwinbase/ns-minwinbase-debug_event
[EXCEPTION_DEBUG_INFO_Link]: https://docs.microsoft.com/fr-fr/windows/win32/api/minwinbase/ns-minwinbase-exception_debug_info
[EXCEPTION_RECORD_Link]: https://docs.microsoft.com/fr-fr/windows/win32/api/winnt/ns-winnt-exception_record

[THREADENTRY32_Link]: https://docs.microsoft.com/fr-fr/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32
[CONTEXT_Link]: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-arm64_nt_context

[SYSTEM_INFO_Link]: https://docs.microsoft.com/fr-fr/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
[MEMORY_BASIC_INFORMATION_Link]: https://docs.microsoft.com/fr-fr/windows/win32/api/winnt/ns-winnt-memory_basic_information
[Memory_Protection_contants_Link]: https://docs.microsoft.com/fr-fr/windows/win32/memory/memory-protection-constants
