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

	// Processes //
	VOID runProcess();
	BOOL loadProcess(LPCTSTR executablePath, LPTSTR arguments);
	BOOL attachProcess(DWORD pid);
	BOOL detachProcess();

	// Threads/contexts //
	UINT enumerateThreads(THREADENTRY32* threadEntryArray[]);
	LPCONTEXT getThreadContext(DWORD threadID);
	BOOL setThreadContext(DWORD threadID, LPCONTEXT threadContext);
	BOOL setRegister(DWORD threadID, LPCTSTR reg, DWORD64 value);

	// Breakpoints //
	BOOL addSoftwareBreakpoint(LPVOID address, BOOL isPersistent);
	BOOL delSoftwareBreakpoint(LPVOID address);
	BOOL addHardwareBreakpoint(LPVOID address, BYTE length, BYTE condition, BOOL isPersistent);
	BOOL delHardwareBreakpoint(LPVOID address);
	BOOL addMemoryBreakpoint(LPVOID address);
	BOOL delMemoryBreakpoint(LPVOID address);

private:
	VOID getDebugEvent();

	DWORD softwareBreakpointExceptionHandler(DWORD threadID, LPVOID exceptionAddress);
	DWORD hardwareBreakpointExceptionHandler(DWORD threadID, LPVOID exceptionAddress);

	BOOL isDebuggerActive;
	UINT processID;
	HANDLE hProcess;

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

	};
	typedef std::map<LPVOID, MemoryBreakpoint> MemoryBreakpoints;
	MemoryBreakpoints memoryBreakpoints;
};
