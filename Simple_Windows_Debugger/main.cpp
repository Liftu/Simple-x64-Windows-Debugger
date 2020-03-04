#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <tlhelp32.h>

#include "Debugger.h"

Debugger debugger;

void attach()
{
	std::cout << "PID : ";
	unsigned int pid;
	std::cin >> pid;
	if (debugger.attachProcess(pid)) 
	{
		std::cout << "process attached to " << pid << std::endl;
	}
}

void load()
{
	if (debugger.loadProcess("C:\\Windows\\System32\\calc.exe", NULL))
	{
		std::cout << "process loaded " << std::endl;
	}
}

void dumpthreadRegisters()
{
	THREADENTRY32* threadEntries = new THREADENTRY32[0];
	// To be debug !!
	UINT nbThreads = debugger.enumerateThreads(&threadEntries);

	for (int i = 0; i < nbThreads; i++)
	{
		CONTEXT* thread = debugger.getThreadContext(threadEntries[i].th32ThreadID);
		std::cout << "[*] Dumping registers for thread ID: " << threadEntries[i].th32ThreadID << std::endl << std::hex;
		std::cout << "[*] RIP: 0x" << std::setfill('0') << std::setw(12) << thread->Rip << std::endl;
		std::cout << "[*] RSP: 0x" << std::setfill('0') << std::setw(12) << thread->Rsp << std::endl;
		std::cout << "[*] RBP: 0x" << std::setfill('0') << std::setw(12) << thread->Rbp << std::endl;
		std::cout << "[*] RAX: 0x" << std::setfill('0') << std::setw(12) << thread->Rax << std::endl;
		std::cout << "[*] RBX: 0x" << std::setfill('0') << std::setw(12) << thread->Rbx << std::endl;
		std::cout << "[*] RCX: 0x" << std::setfill('0') << std::setw(12) << thread->Rcx << std::endl;
		std::cout << "[*] RDX: 0x" << std::setfill('0') << std::setw(12) << thread->Rdx << std::endl;
		std::cout << "[*] End dump." << std::endl << std::endl << std::dec;
	}
}

int main(int argc, char* argv[])
{
	debugger = Debugger();
	
	//load();
	attach();
	//debugger.runProcess();

	dumpthreadRegisters();

	debugger.detachProcess();

	system("PAUSE");
	return 0;
}

