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
		return TRUE;
	}
	else
	{
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
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL Debugger::detachProcess()
{
	if (DebugActiveProcessStop(this->processID))
	{
		this->isDebuggerActive = FALSE;
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

UINT Debugger::enumerateThreads(THREADENTRY32* threadEntryArray[])
{
	UINT threadNumber = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, this->processID);
	if (snapshot)
	{
		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(threadEntry);
		BOOL success = Thread32First(snapshot, &threadEntry);
		while (success)
		{
			if (threadEntry.th32OwnerProcessID == this->processID)
			{
				threadNumber++;
				// Dynamically add an element to the array of thread entry.
				// /!\ Experimental
				THREADENTRY32* tempThreadEntryArray = new THREADENTRY32[threadNumber];
				memcpy_s(tempThreadEntryArray, (threadNumber - 1) * sizeof(THREADENTRY32), *threadEntryArray, (threadNumber - 1) * sizeof(THREADENTRY32));
				tempThreadEntryArray[threadNumber - 1] = threadEntry;
				delete[] *threadEntryArray;
				*threadEntryArray = tempThreadEntryArray;
			}
			success = Thread32Next(snapshot, &threadEntry);
		}
		CloseHandle(snapshot);
	}
	return threadNumber;
}

LPCONTEXT Debugger::getThreadContext(UINT threadID)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
	if (GetThreadContext(hThread, &context))
	{
		CloseHandle(hThread);
		return &context;
	}
	else
	{
		return NULL;
	}
}
