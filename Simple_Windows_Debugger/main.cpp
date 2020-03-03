#include <Windows.h>
#include <iostream>

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
	
	attach();

	system("PAUSE");
	return 0;
}

