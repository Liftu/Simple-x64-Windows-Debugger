#pragma once

#include <Windows.h>
#include <tlhelp32.h>
#include <map>

// Hardware breakpoints conditions //
#define HW_EXECUTE 0x0
#define HW_WRITE 0x1
#define HW_ACCESS 0x3


class Debugger
{
public:
	Debugger();
	~Debugger();

	// Process //
	enum class ProcessStatus
	{
		NONE,
		SUSPENDED,
		INTERRUPTED,
		RUNNING
	};

	BOOL loadProcess(LPCTSTR executablePath, LPTSTR arguments);
	BOOL attachProcess(DWORD pid);
	BOOL detachProcess();
	BOOL continueProcess();
	Debugger::ProcessStatus getProcessStatus();

	// Threads/contexts //
	UINT enumerateThreads(THREADENTRY32* threadEntryArray[]);
	LPCONTEXT getThreadContext(DWORD threadID);
	BOOL setThreadContext(DWORD threadID, LPCONTEXT threadContext);
	BOOL setRegister(DWORD threadID, LPCTSTR reg, DWORD64 value);

	// Breakpoints //
	BOOL addSoftwareBreakpoint(LPVOID address, BOOL isPersistent);
	BOOL delSoftwareBreakpoint(LPVOID address);
	BOOL addHardwareBreakpoint(LPVOID address, BYTE length, BYTE condition, BOOL isPersistent);
	BOOL delHardwareBreakpoint(BYTE slot);
	BOOL addMemoryBreakpoint(LPVOID address, /*DWORD size, */BYTE condition, BOOL isPersistent);
	BOOL delMemoryBreakpoint(LPVOID address);


private:
	VOID logEvent(LPCTSTR message);

	BOOL debugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL exceptionDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL createProcessDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL createThreadDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL exitProcessDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL exitThreadDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL loadDllDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL unloadDllDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL outputDebugStringEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL RIPEventHandler(const DEBUG_EVENT* debugEvent);

	BOOL softwareBreakpointExceptionHandler(const DEBUG_EVENT* debugEvent);
	BOOL hardwareBreakpointExceptionHandler(const DEBUG_EVENT* debugEvent);
	BOOL memoryBreakpointExceptionHandler(const DEBUG_EVENT* debugEvent);

	BOOL isDebuggerActive;
	HANDLE hProcess;
	DWORD processID;
	HANDLE hThread;
	DWORD threadID;
	ProcessStatus processStatus;
	DWORD continueStatus;
	BOOL firstBreakpointOccured;
	DWORD pageSize;

	// Software breakpoints //
	struct SoftwareBreakpoint
	{
		LPVOID address;
		BYTE originalByte;
		BOOL isPersistent;
	};
	typedef std::map<LPVOID, SoftwareBreakpoint> SoftwareBreakpoints;
	SoftwareBreakpoints softwareBreakpoints;

	// Hardware breakpoints //
	struct HardwareBreakpoint
	{
		LPVOID address;
		BYTE length;
		BYTE condition;
		BOOL isPersistent;
	};
	// The BYTE specify on which DR register the address is strored (DR0 - DR3)
	typedef std::map<BYTE, HardwareBreakpoint> HardwareBreakpoints;
	HardwareBreakpoints hardwareBreakpoints;

	// Memory breakpoints //
	struct MemoryBreakpoint
	{
		LPVOID address;
		//DWORD size;
		BYTE condition;
		MEMORY_BASIC_INFORMATION memoryBasicInfo;
		BOOL isPersistent;
	};
	typedef std::map<LPVOID, MemoryBreakpoint> MemoryBreakpoints;
	MemoryBreakpoints memoryBreakpoints;
};
