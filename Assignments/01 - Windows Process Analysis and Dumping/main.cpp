#include <iostream>

#include "Process.h"

using namespace std;


int main() {
	DWORD dwProcessNum = ProcessInfo::getPidByName(L"Notepad.exe");
	cout << "Process ID: " << dwProcessNum << endl;
	return 0;
}