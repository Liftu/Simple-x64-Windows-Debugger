#include <Windows.h>
#include <iostream>
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

int main(int argc, char* argv[])
{
	debugger = Debugger();
	
	//load();
	attach();
	//debugger.runProcess();

	THREADENTRY32* threadEntries = new THREADENTRY32[0];
	// To be debug !!
	UINT nbThreads = debugger.enumerateThreads(threadEntries);

	for (int i = 0; i < nbThreads; i++)
	{
		CONTEXT* thread = debugger.getThreadContext(threadEntries[i].th32ThreadID);
		std::cout << "[*] Dumping registers for thread ID: " << threadEntries[i].th32ThreadID << std::endl;
		std::cout << "[*] RIP: " << thread->Rip << std::endl;
		std::cout << "[*] RSP: " << thread->Rsp << std::endl;
		std::cout << "[*] RBP: " << thread->Rbp << std::endl;
		std::cout << "[*] RAX: " << thread->Rax << std::endl;
		std::cout << "[*] RBX: " << thread->Rbx << std::endl;
		std::cout << "[*] RCX: " << thread->Rcx << std::endl;
		std::cout << "[*] RDX: " << thread->Rdx << std::endl;
		std::cout << "[*] End dump." << std::endl;
	}

	debugger.detachProcess();

	system("PAUSE");
	return 0;
}

