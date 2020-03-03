#pragma once

#include <Windows.h>

class Debugger
{
public:
	Debugger();
	~Debugger();

	VOID runProcess();
	BOOL loadProcess(LPCTSTR executablePath, LPTSTR arguments);
	BOOL attachProcess(UINT pid);
	BOOL detachProcess();

private:
	VOID getDebugEvent();

	BOOL isDebuggerActive;
	UINT processID;
	HANDLE hProcess;
};

