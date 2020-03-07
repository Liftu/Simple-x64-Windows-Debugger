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
		//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
		//LPCONTEXT threadContext = this->getThreadContext(debugEvent.dwThreadId);

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
			{	// This exception is for software breakpoints
				continueStatus = this->softwareBreakpointExceptionHandler(debugEvent.dwThreadId, exceptionAddress);
			}
			else if (exceptionCode == EXCEPTION_SINGLE_STEP)
			{	// This exception is for hardware breakpoints
				continueStatus = this->hardwareBreakpointExceptionHandler(debugEvent.dwThreadId, exceptionAddress);
			}
			else if (exceptionCode == EXCEPTION_GUARD_PAGE)
			{	// This exception is for memory breakpoints
				//std::cout << "Exception guard page at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
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

#include <iostream>//
DWORD Debugger::softwareBreakpointExceptionHandler(DWORD threadID, LPVOID exceptionAddress)
{
	std::cout << std::hex << " Exception software breakpoint at address : 0x" << exceptionAddress << std::dec << std::endl;//

	if (this->softwareBreakpoints.count(exceptionAddress))
	{
		// We restore the changed byte and delete the breakpoint.
		this->delSoftwareBreakpoint(exceptionAddress);
		// We have to go back of 1 byte backward because the INT3 instruction got executed.
		this->setRegister(threadID, "RIP", (DWORD64)exceptionAddress);
	}
	return DBG_CONTINUE;
}

DWORD Debugger::hardwareBreakpointExceptionHandler(DWORD threadID, LPVOID exceptionAddress)
{
	std::cout << "Exception hardware breakpoint at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
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

BOOL Debugger::attachProcess(DWORD pid)
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
	UINT threadsNumber = 0;
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
				threadsNumber++;
				// Dynamically add an element to the array of thread entry.
				THREADENTRY32* tempThreadEntryArray = new THREADENTRY32[threadsNumber];
				memcpy_s(tempThreadEntryArray, (threadsNumber - 1) * sizeof(THREADENTRY32), *threadEntryArray, (threadsNumber - 1) * sizeof(THREADENTRY32));
				tempThreadEntryArray[threadsNumber - 1] = threadEntry;
				delete[] *threadEntryArray;
				*threadEntryArray = tempThreadEntryArray;
			}
			success = Thread32Next(snapshot, &threadEntry);
		}
		CloseHandle(snapshot);
	}
	return threadsNumber;
}

LPCONTEXT Debugger::getThreadContext(DWORD threadID)
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

BOOL Debugger::setThreadContext(DWORD threadID, LPCONTEXT threadContext)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
	
	if (SetThreadContext(hThread, threadContext))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL Debugger::setRegister(DWORD threadID, LPCTSTR reg, DWORD64 value)
{
	LPCONTEXT threadContext = this->getThreadContext(threadID);

	if (_stricmp(reg, "RAX") == 0)		threadContext->Rax = value;
	else if (_stricmp(reg, "RBX") == 0)	threadContext->Rbx = value;
	else if (_stricmp(reg, "RCX") == 0)	threadContext->Rcx = value;
	else if (_stricmp(reg, "RDX") == 0)	threadContext->Rdx = value;
	else if (_stricmp(reg, "RSI") == 0)	threadContext->Rsi = value;
	else if (_stricmp(reg, "RDI") == 0)	threadContext->Rdi = value;
	else if (_stricmp(reg, "RSP") == 0)	threadContext->Rsp = value;
	else if (_stricmp(reg, "RBP") == 0)	threadContext->Rbp = value;
	else if (_stricmp(reg, "RIP") == 0)	threadContext->Rip = value;
	else if (_stricmp(reg, "R8") == 0)	threadContext->R8 = value;
	else if (_stricmp(reg, "R9") == 0)	threadContext->R9 = value;
	else if (_stricmp(reg, "R10") == 0)	threadContext->R10 = value;
	else if (_stricmp(reg, "R11") == 0)	threadContext->R11 = value;
	else if (_stricmp(reg, "R12") == 0)	threadContext->R12 = value;
	else if (_stricmp(reg, "R13") == 0)	threadContext->R13 = value;
	else if (_stricmp(reg, "R14") == 0)	threadContext->R14 = value;
	else if (_stricmp(reg, "R15") == 0)	threadContext->R15 = value;
	else return FALSE;

	if (this->setThreadContext(threadID, threadContext))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL Debugger::addSoftwareBreakpoint(LPVOID address, BOOL isPersistent)
{
	// Checks if address is already in soft breakpoint list
	if (!this->softwareBreakpoints.count(address))
	{
		BYTE originalByte;
		SIZE_T count;
		if (ReadProcessMemory(this->hProcess, address, &originalByte, 1, &count))
		{
			BYTE INT3Byte = 0xCC;
			if (WriteProcessMemory(this->hProcess, address, &INT3Byte, 1, &count))
			{
				SoftwareBreakpoint softwareBreakpoint;
				softwareBreakpoint.address = address;
				softwareBreakpoint.originalByte = originalByte;
				softwareBreakpoint.isPersistent = isPersistent;

				this->softwareBreakpoints[address] = softwareBreakpoint;
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOL Debugger::delSoftwareBreakpoint(LPVOID address)
{
	SoftwareBreakpoints::iterator breakpoint = this->softwareBreakpoints.find(address);
	if (breakpoint != this->softwareBreakpoints.end())
	{
		BYTE originalByte = breakpoint->second.originalByte;
		SIZE_T count;
		if (WriteProcessMemory(this->hProcess, address, &originalByte, 1, &count))
		{
			this->softwareBreakpoints.erase(breakpoint);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL Debugger::addHardwareBreakpoint(LPVOID address, BYTE length, BYTE condition, BOOL isPersistent)
{
	if (length == 1 || length == 2 || length == 4)
	{
		// length-- because the following codes are used for determining length :
		//      00 - 1 byte length
		//      01 - 2 byte length
		//      10 - undefined
		//      11 - 4 byte length
		length--;

		if (condition == HW_EXECUTE || condition == HW_WRITE || condition == HW_ACCESS)
		{
			// We may need to check if we already have a hardware breakpoint at an address.
			// I don't kmow what happens when 2 hardware breakpoints target the same address.

			// Checks for an available sport on DR registers
			BYTE availableSpot;
			if (!hardwareBreakpoints.count(0))		availableSpot = 0;
			else if (!hardwareBreakpoints.count(1))	availableSpot = 1;
			else if (!hardwareBreakpoints.count(2))	availableSpot = 2;
			else if (!hardwareBreakpoints.count(3))	availableSpot = 3;
			else
				return FALSE;

			THREADENTRY32* threadEntries = new THREADENTRY32[0];
			INT threadsNumber = this->enumerateThreads(&threadEntries);
			for (INT i = 0; i < threadsNumber; i++)
			{
				LPCONTEXT threadContext = this->getThreadContext(threadEntries[i].th32ThreadID);

				// Stores the address in the available register.
				switch (availableSpot)
				{
				case 0: threadContext->Dr0 = (DWORD64)address;
					break;
				case 1: threadContext->Dr1 = (DWORD64)address;
					break;
				case 2: threadContext->Dr2 = (DWORD64)address;
					break;
				case 3: threadContext->Dr3 = (DWORD64)address;
					break;
				default:
					return FALSE;
				}

				// Enables the breakpoint by setting its type (Local/Global)
				// in the first 8 bits (0-7) of DR7.
				// The breakpoints are "Local" in our case.
				threadContext->Dr7 |= 1 << (availableSpot * 2);

				// Sets the condition of the breakpoint in the last 16 bits of DR7 (groups of 2 bits every 4 bits).
				threadContext->Dr7 |= condition << ((availableSpot * 4) + 16);

				// Sets the length of the breakpoint in the last 18 bits of DR7 (groups of 2 bits every 4 bits).
				threadContext->Dr7 |= length << ((availableSpot * 4) + 18);

				this->setThreadContext(threadEntries[i].th32ThreadID, threadContext);
			}
				// Adds the hardware breakpoint to the list.
				HardwareBreakpoint hardwareBreakpoint = {address, length, condition, isPersistent};
				hardwareBreakpoints[availableSpot] = hardwareBreakpoint;
		}
	}
	return FALSE;
}

BOOL Debugger::delHardwareBreakpoint(LPVOID address)
{
	return 0;
}

BOOL Debugger::addMemoryBreakpoint(LPVOID address)
{
	return 0;
}

BOOL Debugger::delMemoryBreakpoint(LPVOID address)
{
	return 0;
}
