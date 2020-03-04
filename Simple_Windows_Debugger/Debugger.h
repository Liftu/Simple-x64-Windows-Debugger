#pragma once

#include <Windows.h>
#include <tlhelp32.h>

class Debugger
{
public:
	Debugger();
	~Debugger();

	VOID runProcess();
	BOOL loadProcess(LPCTSTR executablePath, LPTSTR arguments);
	BOOL attachProcess(UINT pid);
	BOOL detachProcess();
	UINT enumerateThreads(THREADENTRY32* threadEntryArray[]);
	LPCONTEXT getThreadContext(UINT threadID);

private:
	VOID getDebugEvent();

	BOOL isDebuggerActive;
	UINT processID;
	HANDLE hProcess;
};

