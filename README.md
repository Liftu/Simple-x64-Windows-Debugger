# Simple Windows Debugger
Just a simple Windows debugger written in C++

## Used WinAPI functions
These are the usefull functions provided by the Windows API which are use in this program for making the core of the debugger.

### Processes functions
- [CreateProcessA][CreateProcessA_Link] : Set **DEBUG_PROCESS** as a flag for **dwCreationFlags** allows the process to receive all related debug events using the [WaitForDebugEvent](#anchor-have-to-be-added) function.
- [OpenProcess][OpenProcess_Link] : In order to perform debugging, we have to set **dwDesiredAccess** member to **PROCESS_ALL_ACCESS**.
<!-- - [Process32First][Process32First_link]
- [Process32Next][Process32Next_Link] -->

### Debugging functions
- [DebugActiveProcess][DebugActiveProcess_Link]
- [WaitForDebugEvent][WaitForDebugEvent_Link]
- [ContinueDebugEvent][ContinueDebugEvent_Link]

### Threads functions
- [CreateToolhelp32Snapshot][CreateToolhelp32Snapshot_Link]
- [Thread32First][Thread32First_Link]
- [Thread32Next][Thread32Next_Link]
- [OpenThread][OpenThread_Link]
- [GetThreadContext][GetThreadContext_Link]
- [SetThreadContext][SetThreadContext_Link]

### Memory functions
- [ReadProcessMemory][ReadProcessMemory_Link]
- [WriteProcessMemory][WriteProcessMemory_Link]

#### Memory pages related functions
- [GetSystemInfo][GetSystemInfo_Link] : Provides us a [SYSTEM_INFO][SYSTEM_INFO_Link] stucture that contains a **dwPageSize** member which gives us the correct page size for the system.
- [VirtualQueryEx][VirtualQueryEx_Link]
- [VirtualProtectEx][VirtualProtectEx_Link]

### Address resolving functions
- [GetModuleHandleA][GetModuleHandleA_Link]
- [GetProcAddress][GetProcAddress_Link] (#wait)





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


[SYSTEM_INFO_Link]: https://docs.microsoft.com/fr-fr/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
