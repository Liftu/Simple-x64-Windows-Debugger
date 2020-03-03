#include "Debugger.h"

Debugger::Debugger()
{
	this->isDebuggerActive = FALSE;
	this->processID = NULL;
	this->hProcess = NULL;
}

Debugger::~Debugger()
{
	if (this->isDebuggerActive)
	{
		this->detachProcess();
	}
}

VOID Debugger::runProcess()
{
	while (this->isDebuggerActive)
	{
		this->getDebugEvent();
	}
}

VOID Debugger::getDebugEvent()
{
	DEBUG_EVENT debugEvent;
	if (WaitForDebugEvent(&debugEvent, INFINITE))
	{
		this->isDebuggerActive = FALSE;
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	}
}

BOOL Debugger::loadProcess(LPCTSTR executablePath, LPTSTR arguments)
{
	STARTUPINFO startupInfo;
	// Clean all the members of startupInfo.
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	// Provide the size of startupInfo to cb.
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION processInformation;

	if (CreateProcess(executablePath, arguments, NULL, NULL, NULL, DEBUG_PROCESS, NULL, NULL, &startupInfo, &processInformation))
	{
		this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processInformation.dwProcessId);
		this->isDebuggerActive = true;
		this->processID = processInformation.dwProcessId;

		//MessageBox(NULL, "Successfully loaded process.", "Success", MB_OK | MB_ICONINFORMATION);
		return TRUE;
	}
	else
	{
		//MessageBox(NULL, "Error loading process. Check the parameters.", "Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
}

BOOL Debugger::attachProcess(UINT pid)
{
	this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	
	if (DebugActiveProcess(pid))
	{
		this->isDebuggerActive = TRUE;
		this->processID = pid;

		//MessageBox(NULL, "Successfully attached process.", "Success", MB_OK | MB_ICONINFORMATION);
		return TRUE;
	}
	else
	{
		//MessageBox(NULL, "Error attaching process. Check the pid.", "Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
}

BOOL Debugger::detachProcess()
{
	if (DebugActiveProcessStop(this->processID))
	{
		this->isDebuggerActive = FALSE;
		//MessageBox(NULL, "Successfully detached from process.", "Success", MB_OK | MB_ICONINFORMATION);
		return TRUE;
	}
	else
	{
		//MessageBox(NULL, "Error detaching from process.", "Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
}
