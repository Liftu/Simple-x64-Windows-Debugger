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
		DWORD continueStatus = DBG_CONTINUE;
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
		LPCONTEXT threadContext = this->getThreadContext(debugEvent.dwThreadId);

		//std::cout << "Event code : " << debugEvent.dwDebugEventCode << std::endl;

		if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			DWORD exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
			PVOID exceptionAddress = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

			if (exceptionCode == EXCEPTION_ACCESS_VIOLATION)
			{
				//std::cout << "Exception access violation at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
			}
			else if (exceptionCode == EXCEPTION_BREAKPOINT)
			{	// This exception is for soft breakpoints
				//std::cout << "Exception breakpoint at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
				continueStatus = this->breakpointExceptionHandler();
			}
			else if (exceptionCode == EXCEPTION_GUARD_PAGE)
			{	// This exception is for memory breakpoints
				//std::cout << "Exception guard page at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
			}
			else if (exceptionCode == EXCEPTION_SINGLE_STEP)
			{	// This exception is for hardware breakpoints
				//std::cout << "Exception single step at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
			}
			else
			{
				//std::cout << "Exception not handled at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
			}
		}
		else if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			this->isDebuggerActive = FALSE;
		}

		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	}
}

DWORD Debugger::breakpointExceptionHandler()
{
	return DBG_CONTINUE;
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
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);

	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(hThread, &threadContext))
	{
		CloseHandle(hThread);
		return &threadContext;
	}
	else
	{
		return NULL;
	}
}
