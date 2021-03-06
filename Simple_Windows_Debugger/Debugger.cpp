#include "Debugger.h"
#include <iostream>//

Debugger::Debugger()
{
	this->isDebuggerActive = FALSE;
	this->hProcess = NULL;
	this->processID = NULL;
	this->hThread = NULL;
	this->threadID = NULL;
	this->processStatus = ProcessStatus::NONE;
	this->continueStatus = DBG_CONTINUE;
	this->firstBreakpointOccured = FALSE;
	// Get the default memory page size.
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	this->pageSize = systemInfo.dwPageSize;
}

Debugger::~Debugger()
{
	if (this->isDebuggerActive)
	{
		this->detachProcess();
	}
}

BOOL Debugger::loadProcess(LPCTSTR executablePath, LPTSTR arguments)
{
	// Checks if a process isn't already being debugged
	if (this->processStatus == ProcessStatus::NONE)
	{
		STARTUPINFO startupInfo;
		// Clean all the members of startupInfo.
		ZeroMemory(&startupInfo, sizeof(startupInfo));
		// Provide the size of startupInfo to cb.
		startupInfo.cb = sizeof(startupInfo);
		startupInfo.dwFlags = STARTF_USESHOWWINDOW;
		startupInfo.wShowWindow = SW_HIDE;

		PROCESS_INFORMATION processInformation;

		if (CreateProcess(executablePath, arguments, NULL, NULL, NULL, 
			DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_SUSPENDED, 
			NULL, NULL, &startupInfo, &processInformation))
		{
			this->hProcess = processInformation.hProcess;
			this->processID = processInformation.dwProcessId;
			this->hThread = processInformation.hThread;
			this->threadID = processInformation.dwThreadId;
			this->processStatus = ProcessStatus::SUSPENDED;
			this->isDebuggerActive = true;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL Debugger::attachProcess(DWORD pid)
{
	this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (DebugActiveProcess(pid))
	{
		this->isDebuggerActive = TRUE;
		this->processID = pid;
		this->processStatus = ProcessStatus::RUNNING;
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
		this->processStatus = ProcessStatus::NONE;
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL Debugger::continueProcess()
{
	if (this->processStatus != ProcessStatus::NONE)
	{
		if (this->processStatus == ProcessStatus::SUSPENDED)
		{
			ResumeThread(this->hThread);
		}
		else
		{
			ContinueDebugEvent(this->processID, this->threadID, this->continueStatus);
		}

		DEBUG_EVENT debugEvent;
		while (WaitForDebugEvent(&debugEvent, INFINITE))
		{
			if (this->debugEventHandler(&debugEvent))
			{
				ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, this->continueStatus);
			}
			else 
			{
				break;
			}
		}
		return TRUE;
	}
	return FALSE;
}

Debugger::ProcessStatus Debugger::getProcessStatus()
{
	return this->processStatus;
}

BOOL Debugger::debugEventHandler(const DEBUG_EVENT* debugEvent)
{
	switch (debugEvent->dwDebugEventCode)
	{
	case CREATE_PROCESS_DEBUG_EVENT:
		return this->createProcessDebugEventHandler(debugEvent);

	case CREATE_THREAD_DEBUG_EVENT:
		return this->createThreadDebugEventHandler(debugEvent);

	case EXCEPTION_DEBUG_EVENT:
		return this->exceptionDebugEventHandler(debugEvent);

	case EXIT_PROCESS_DEBUG_EVENT:
		return this->exitProcessDebugEventHandler(debugEvent);
		
	case EXIT_THREAD_DEBUG_EVENT:
		return this->exitThreadDebugEventHandler(debugEvent);

	case LOAD_DLL_DEBUG_EVENT:
		return this->loadDllDebugEventHandler(debugEvent);

	case UNLOAD_DLL_DEBUG_EVENT:
		return this->unloadDllDebugEventHandler(debugEvent);

	case OUTPUT_DEBUG_STRING_EVENT:
		return this->outputDebugStringEventHandler(debugEvent);

	case RIP_EVENT:
		return this->RIPEventHandler(debugEvent);

	default:
		this->logEvent("Unknown debug event.\n");
		return FALSE;
	}
	return true;
}

BOOL Debugger::exceptionDebugEventHandler(const DEBUG_EVENT* debugEvent)
{
	switch (debugEvent->u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		//std::cout << "Exception access violation at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
		this->logEvent("Accedd violation debug event.\n");
		this->processStatus = ProcessStatus::INTERRUPTED;
		return FALSE;

	case EXCEPTION_BREAKPOINT:
		//This exception is for software breakpoints
		return this->softwareBreakpointExceptionHandler(debugEvent);

	case EXCEPTION_SINGLE_STEP:
		// This exception is for hardware breakpoints
		return this->hardwareBreakpointExceptionHandler(debugEvent);

	case EXCEPTION_GUARD_PAGE:
		// This exception is for memory breakpoints
		return this->memoryBreakpointExceptionHandler(debugEvent);

	default:
		// Unhandled exceptions
		//std::cout << "Exception not handled at address : 0x" << std::hex << exceptionAddress << std::dec << std::endl;
		this->logEvent("Unhandled debug event.\n");
		this->processStatus = ProcessStatus::INTERRUPTED;
		return FALSE;;
	}

}

BOOL Debugger::createProcessDebugEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("Process created.\n");
	return TRUE;
}

BOOL Debugger::createThreadDebugEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("A new thread has been created.\n");
	return TRUE;
}

BOOL Debugger::exitProcessDebugEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("Process exited.\n");
	this->processStatus = ProcessStatus::NONE;
	return this->isDebuggerActive = FALSE;
}

BOOL Debugger::exitThreadDebugEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("A thread has been exited.\n");
	return TRUE;
}

BOOL Debugger::loadDllDebugEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("Load dll [");
	if (debugEvent->u.LoadDll.lpImageName != NULL)
	{
		// May be necessary to inscrease the maximum size of the string.
		LPTSTR dllName = (LPTSTR)malloc(sizeof(LPTSTR) * MAX_PATH);
		GetFinalPathNameByHandle(debugEvent->u.LoadDll.hFile, dllName, MAX_PATH, FILE_NAME_NORMALIZED);
		this->logEvent(dllName);
	}
	else
	{
		this->logEvent("Unknown");
	}
	this->logEvent("]\n");
	return TRUE;
}

BOOL Debugger::unloadDllDebugEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("Unload dll");
	return TRUE;
}

BOOL Debugger::outputDebugStringEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("A debug string has been outputed.\n");
	return FALSE;
}

BOOL Debugger::RIPEventHandler(const DEBUG_EVENT * debugEvent)
{
	this->logEvent("A RIP event occured.\n");
	return FALSE;
}

BOOL Debugger::softwareBreakpointExceptionHandler(const DEBUG_EVENT* debugEvent)
{
	PVOID exceptionAddress = debugEvent->u.Exception.ExceptionRecord.ExceptionAddress;
	std::cout << std::hex << "Exception software breakpoint at address : 0x" << exceptionAddress << std::dec << std::endl;//

	this->threadID = debugEvent->dwThreadId;
	this->hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->threadID);

	if (this->softwareBreakpoints.count(exceptionAddress))
	{
		// We restore the changed byte and delete the breakpoint.
		this->delSoftwareBreakpoint(exceptionAddress);
		// We have to go back of 1 byte backward because the INT3 instruction got executed.
		this->setRegister(debugEvent->dwThreadId, "RIP", (DWORD64)exceptionAddress);
	}
	else
	{
		if (!this->firstBreakpointOccured)
		{
			// I would like to give control to user so he can puts breakpoints after the process has started.
			this->firstBreakpointOccured = TRUE;
		}
	}
	return TRUE;
}

BOOL Debugger::hardwareBreakpointExceptionHandler(const DEBUG_EVENT* debugEvent)
{
	PVOID exceptionAddress = debugEvent->u.Exception.ExceptionRecord.ExceptionAddress;
	std::cout << std::hex << "Exception hardware breakpoint at address : 0x" << exceptionAddress << std::dec << std::endl;//

	this->threadID = debugEvent->dwThreadId;
	this->hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->threadID);
	LPCONTEXT threadContext = this->getThreadContext(debugEvent->dwThreadId);
	
	BYTE slot;
	// DR6 set one of its 4 first bits corresponding to the breakpoint has been hit (DR0-DR3)
	if		((threadContext->Dr6 & 0x1) && this->hardwareBreakpoints.count(0)) slot = 0;
	else if ((threadContext->Dr6 & 0x2) && this->hardwareBreakpoints.count(1)) slot = 1;
	else if ((threadContext->Dr6 & 0x4) && this->hardwareBreakpoints.count(2)) slot = 2;
	else if ((threadContext->Dr6 & 0x8) && this->hardwareBreakpoints.count(3)) slot = 3;
	else // not a hardware breakpoint
	{ 
		return TRUE;
	}

	// Removes the hardware breakpoint
	this->delHardwareBreakpoint(slot);

	return TRUE;
}

BOOL Debugger::memoryBreakpointExceptionHandler(const DEBUG_EVENT* debugEvent)
{
	LPVOID exceptionAddress = (LPVOID)debugEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
	std::cout << std::hex << "Exception memory breakpoint at address : 0x" << exceptionAddress << std::dec << std::endl;//

	this->threadID = debugEvent->dwThreadId;
	this->hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->threadID);

	MemoryBreakpoints::iterator breakpoint = this->memoryBreakpoints.find(exceptionAddress);
	if (breakpoint != this->memoryBreakpoints.end())
	{
		// If the exception is triggered by our memory breakpoint
		//std::cout << std::hex << "Exception memory breakpoint at address : 0x" << exceptionAddress << std::dec << std::endl;//

		if (breakpoint->second.isPersistent)
		{
			//MEMORY_BASIC_INFORMATION memoryBasicInfo;
			//if (VirtualQueryEx(this->hProcess, exceptionAddress, &memoryBasicInfo, sizeof(memoryBasicInfo)) >= sizeof(memoryBasicInfo))
			//{
			//	LPVOID exceptionAddressPage = memoryBasicInfo.BaseAddress;
			//	DWORD oldProtect;
			//	VirtualProtectEx(this->hProcess, exceptionAddressPage, 1, memoryBasicInfo.Protect | PAGE_GUARD, &oldProtect);
			//}
			//return TRUE;
		}
		else
		{
			this->delMemoryBreakpoint(exceptionAddress);
		}

		return TRUE;
	}
	else
	{
		// If the exception occurs in the page guard of our breakpoint but is not our breakpoint then restore the page guard.
		// Running this code before process has really started seems to cause an infinite loop
		// I'm trying to figure out how to break to the first windows driven breakpoint and then give control to the user.

		//MEMORY_BASIC_INFORMATION memoryBasicInfo;
		//if (VirtualQueryEx(this->hProcess, exceptionAddress, &memoryBasicInfo, sizeof(memoryBasicInfo)) >= sizeof(memoryBasicInfo))
		//{
		//	LPVOID exceptionAddressPage = memoryBasicInfo.BaseAddress;
		//	DWORD oldProtect;
		//	VirtualProtectEx(this->hProcess, exceptionAddressPage, 1, memoryBasicInfo.Protect | PAGE_GUARD, &oldProtect);
		//}
		//return TRUE;
	}
	return TRUE;
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
				SoftwareBreakpoint softwareBreakpoint = { address, originalByte, isPersistent };
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
			BYTE availableSlot;
			if (!hardwareBreakpoints.count(0)) availableSlot = 0;
			else if (!hardwareBreakpoints.count(1))	availableSlot = 1;
			else if (!hardwareBreakpoints.count(2))	availableSlot = 2;
			else if (!hardwareBreakpoints.count(3))	availableSlot = 3;
			else
				return FALSE;

			THREADENTRY32* threadEntries = new THREADENTRY32[0];
			INT threadsNumber = this->enumerateThreads(&threadEntries);
			for (INT i = 0; i < threadsNumber; i++)
			{
				LPCONTEXT threadContext = this->getThreadContext(threadEntries[i].th32ThreadID);

				// Stores the address in the available register.
				switch (availableSlot)
				{
				case 0: threadContext->Dr0 = (DWORD64)address; break;
				case 1: threadContext->Dr1 = (DWORD64)address; break;
				case 2: threadContext->Dr2 = (DWORD64)address; break;
				case 3: threadContext->Dr3 = (DWORD64)address; break;
				default: 
					return FALSE;
				}

				// Enables the breakpoint by setting its type (Local/Global)
				// in the first 8 bits (0-7) of DR7.
				// The breakpoints are "Local" in our case.
				threadContext->Dr7 |= 1 << (availableSlot * 2);
				// Sets the condition of the breakpoint in the last 16 bits of DR7 (groups of 2 bits every 4 bits).
				threadContext->Dr7 |= condition << ((availableSlot * 4) + 16);
				// Sets the length of the breakpoint in the last 18 bits of DR7 (groups of 2 bits every 4 bits).
				threadContext->Dr7 |= length << ((availableSlot * 4) + 18);

				this->setThreadContext(threadEntries[i].th32ThreadID, threadContext);
			}
			// Adds the hardware breakpoint to the list.
			HardwareBreakpoint hardwareBreakpoint = { address, length, condition, isPersistent };
			hardwareBreakpoints[availableSlot] = hardwareBreakpoint;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL Debugger::delHardwareBreakpoint(BYTE slot)
{
	THREADENTRY32* threadEntries = new THREADENTRY32[0];
	INT threadsNumber = this->enumerateThreads(&threadEntries);
	for (INT i = 0; i < threadsNumber; i++)
	{
		LPCONTEXT threadContext = this->getThreadContext(threadEntries[i].th32ThreadID);

		// Reset the breakpoint address in the register
		switch (slot)
		{
		case 0: threadContext->Dr0 = 0x0; break;
		case 1: threadContext->Dr1 = 0x0; break;
		case 2: threadContext->Dr2 = 0x0; break;
		case 3: threadContext->Dr3 = 0x0; break;
		default: continue; break;
		}

		// Disable the breakpoint in DR7
		threadContext->Dr7 &= ~(1 << (slot * 2));
		// Reset the condition of the breakpoint in DR7
		threadContext->Dr7 &= ~(3 << ((slot * 4) + 16));
		// Reset the length of the breakpoint in DR7
		threadContext->Dr7 &= ~(3 << ((slot * 4) + 18));

		this->setThreadContext(threadEntries[i].th32ThreadID, threadContext);
	}
	this->hardwareBreakpoints.erase(slot);
	return TRUE;
}

BOOL Debugger::addMemoryBreakpoint(LPVOID address, /*DWORD size, */BYTE condition, BOOL isPersistent)
{
	// The size functionnality is disabled for the moment.
	MEMORY_BASIC_INFORMATION memoryBasicInfo;
	// Gets the memory page infos and checks if it got all the infos
	if (VirtualQueryEx(this->hProcess, address, &memoryBasicInfo, sizeof(memoryBasicInfo)) >= sizeof(memoryBasicInfo))
	{
		// Get the base address of the current memory page;
		LPVOID currentPage = memoryBasicInfo.BaseAddress;
		// Loop on every pages within the range of the memory breakpoint
		while ((DWORD64)currentPage <= ((DWORD64)address))// + size))
		{
			DWORD oldProtect;
			// Sets the guard page protection on the memory page;
			if (!VirtualProtectEx(this->hProcess, currentPage, 1, memoryBasicInfo.Protect | PAGE_GUARD, &oldProtect))
				return FALSE;
			// Next page (sorry, I didn't find a nicer way to do it)
			currentPage = (LPVOID) ((DWORD64)currentPage + this->pageSize);
		}
		MemoryBreakpoint memorybreakpoint = { address, /*size, */condition, memoryBasicInfo, isPersistent };
		memoryBreakpoints[address] = memorybreakpoint;
		return TRUE;
	}
	return FALSE;
}

BOOL Debugger::delMemoryBreakpoint(LPVOID address)
{
	MemoryBreakpoints::iterator breakpoint = memoryBreakpoints.find(address);
	if (breakpoint != memoryBreakpoints.end())
	{
		LPVOID currentPage = breakpoint->second.memoryBasicInfo.BaseAddress;
		while ((DWORD64)currentPage <= ((DWORD64)breakpoint->second.address))// + breakpoint->second.size))
		{
			// Checks if the memory page isn't in the range of another memory breakpoint before removing the guard page on it.
			BOOL pageAlreadyUsed = FALSE;
			for (MemoryBreakpoints::iterator breakpoints = this->memoryBreakpoints.begin(); 
					breakpoints != this->memoryBreakpoints.end() && !pageAlreadyUsed; breakpoints++)
			{
				if (breakpoints != breakpoint)
				{
					LPVOID memoryPage = breakpoints->second.memoryBasicInfo.BaseAddress;
					while ((DWORD64)memoryPage <= ((DWORD64)breakpoints->second.address))// + breakpoints->second.size))
					{
						if (memoryPage == currentPage)
						{
							pageAlreadyUsed = TRUE;
							break;
						}
						memoryPage = (LPVOID) ((DWORD64)currentPage + this->pageSize);
					}
				}
			}

			// If this memory page has no other breakpoints using it : remove the guard page.
			if (!pageAlreadyUsed)
			{
				DWORD oldProtect;
				if (!VirtualProtectEx(this->hProcess, currentPage, 1, breakpoint->second.memoryBasicInfo.Protect, &oldProtect))
					return FALSE;
			}

			currentPage = (LPVOID) ((DWORD64)currentPage + this->pageSize);
		}
		memoryBreakpoints.erase(breakpoint);
		return TRUE;
	}
	return FALSE;
}

VOID Debugger::logEvent(LPCTSTR message)
{
	// Just print it on stdout for now.
	std::cout << message;
}