#include <iostream>

#include "Process.h"
#include <codecvt>


using namespace std;

static void vidHelp(void) {
	std::cout << std::endl
		<< 
		"Help: Usage for the program:\n\n"
		"  ./program -p <process_pid>\n"
		"  or\n"
		"  ./program -n <name_of_executable>\n"
		"      e.g `./program -n notepad.exe`\n"
		<< std::endl ;
}

int main(int argc, char* argv[]) {

	if (argc != 3) {
		std::cout << "[ERROR] Invalid number of arguments!" << std::endl;
		vidHelp();
		return 1;
	}

	std::string option = argv[1];
	std::string value = argv[2];

	DWORD dwProcessId = 0;

	if (option == "-p") {
		// Working by PID
		dwProcessId = std::stoi(value);
	}
	else if (option == "-n") {
		// Using name
		// Convert from std::string to std::wstring
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		// Get the process ID from name
		dwProcessId = ProcessInfo::getPidByName(converter.from_bytes(value));


		// Check if the process is enabled or not.
		if (dwProcessId == 0) {
			cout << "There's no (" << value  << ") opened, please give the name of a process executable that is currently working." << endl;
			return 1;
		}
	}
	else
	{
		std::cout << "[ERROR] Invalid option!" << std::endl;
		vidHelp();
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
	

	// Print the process header informations
	ProcessInfo::printProcHeaders(dwProcessId);
	
	// Print the process header informations
	ProcessInfo::vidPrintProcExportsImports(dwProcessId);

	// Print the process PBI information in table format
	ProcessInfo::printProcInfo(&procAllInfo);

	// Dump the process by PID
	// ProcessInfo::dumpProcessByPid(dwProcessId);
	return 0;
}