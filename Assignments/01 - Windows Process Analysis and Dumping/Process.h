#pragma once

#include <string>
#include "Windows.h"

class ProcessInfo {
public:
	static DWORD getPidByName(const std::wstring& processName);
};
