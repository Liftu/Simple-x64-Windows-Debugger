#pragma once

#include <Windows.h>
#include <tlhelp32.h>
#include <map>

class Debugger
{
public:
	Debugger();
	~Debugger();

	VOID runProcess();
	BOOL loadProcess(LPCTSTR executablePath, LPTSTR arguments);
	BOOL attachProcess(DWORD pid);
	BOOL detachProcess();
	UINT enumerateThreads(THREADENTRY32* threadEntryArray[]);
	LPCONTEXT getThreadContext(DWORD threadID);
	BOOL setThreadContext(DWORD threadID, LPCONTEXT threadContext);
	BOOL setRegister(DWORD threadID, LPCTSTR reg, DWORD64 value);
	BOOL addSoftwareBreakpoint(LPVOID address, BOOL isPersistent);
	BOOL delSoftwareBreakpoint(LPVOID address);
	BOOL addHardwareBreakpoint(LPVOID address);
	BOOL delHardwareBreakpoint(LPVOID address);
	BOOL addMemoryBreakpoint(LPVOID address);
	BOOL delMemoryBreakpoint(LPVOID address);

private:
	VOID getDebugEvent();
	DWORD softwareBreakpointExceptionHandler(DWORD threadID, LPVOID exceptionAddress);

	BOOL isDebuggerActive;
	UINT processID;
	HANDLE hProcess;

	// Software breakpoints
	struct SoftwareBreakpoint
	{
		LPVOID address;
		BYTE originalByte;
		BOOL isPersistent;
	};
	typedef std::map<LPVOID, SoftwareBreakpoint> SoftwareBreakpoints;
	SoftwareBreakpoints softwareBreakpoints;

	// Hardware breakpoints
	struct HardwareBreakpoint
	{
		LPVOID address;

	};
	typedef std::map<LPVOID, HardwareBreakpoint> HardwareBreakpoints;
	HardwareBreakpoints hardwareBreakpoints;

	// Memory breakpoints
	struct MemoryBreakpoint
	{
		LPVOID address;

	};
	typedef std::map<LPVOID, MemoryBreakpoint> MemoryBreakpoints;
	MemoryBreakpoints memoryBreakpoints;
};
