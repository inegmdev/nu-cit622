#include <iostream>

#include "Process.h"

using namespace std;


int main() {
	// Get the process ID from name
	DWORD dwProcessId = ProcessInfo::getPidByName(L"notepad.exe");
	
	// Check if the process is enabled or not.
	if (dwProcessId == 0) {
		cout << "There's no notepad.exe opened, please open a process and then re-run the application." << endl;
		return 1;
	}
	
	// Print the process ID
	cout << "Process ID: " << dwProcessId << endl;
	cout << endl;

	// Get the PBI information
	ProcessInfo_tstrAllInfo procAllInfo = { 0 };

	StdError stdReturn = ProcessInfo::getProcInfoByPid(dwProcessId, &procAllInfo);
	if (stdReturn != ERROR_SUCCESS) {
		cout << "[ERROR] Failed while getting the PBI for the PID:" << dwProcessId << "." << endl;
		return ERROR_GEN_FAILURE;
	}
	
	// Print the process PBI information in table format
	ProcessInfo::printProcInfo(&procAllInfo);

	// Dump the process by PID
	ProcessInfo::dumpProcessByPid(dwProcessId);
	return 0;
}