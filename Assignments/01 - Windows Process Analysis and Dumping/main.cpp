#include <iostream>

#include "Process.h"

using namespace std;


int main() {
	// Get the process ID from name
	DWORD dwProcessNum = ProcessInfo::getPidByName(L"Notepad.exe");
	
	// Check if the process is enabled or not.
	if (dwProcessNum == 0) {
		cout << "There's no notepad.exe opened, please open a process and then re-run the application." << endl;
		return 1;
	}
	
	// Print the process ID
	cout << "Process ID: " << dwProcessNum << endl;

	// Get the PEB information
	PPEB pPbi = ProcessInfo::getPbiByPid(dwProcessNum);

	return 0;
}