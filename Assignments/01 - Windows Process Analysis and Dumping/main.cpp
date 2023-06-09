#include <iostream>

#include "Process.h"

using namespace std;


int main() {
	// Get the process ID from name
	DWORD dwProcessNum = ProcessInfo::getPidByName(L"notepad.exe");
	
	// Check if the process is enabled or not.
	if (dwProcessNum == 0) {
		cout << "There's no notepad.exe opened, please open a process and then re-run the application." << endl;
		return 1;
	}
	
	// Print the process ID
	cout << "Process ID: " << dwProcessNum << endl;
	cout << endl;

	// Get the PBI information
	ProcessInfo_tstrAllInfo procAllInfo = { 0 };

	StdError stdReturn = ProcessInfo::getPbiAndPebByPid(dwProcessNum, &procAllInfo);
	if (stdReturn != ERROR_SUCCESS) {
		cout << "[ERROR] Failed while getting the PBI for the PID:" << dwProcessNum << "." << endl;
	}
	
	// Print the process PBI information in table format
	ProcessInfo::printProcessPbiAndPeb(&procAllInfo);
	return 0;
}