#pragma once
#include <Windows.h>
#include "globals.h"


PVOID ResolveFunctionAddress(HMODULE moduleHandle, unsigned long targetHash);


HMODULE GetModuleHandleHash(unsigned long targetHash);

void LogHashW(wchar_t* name);
void LogHashA(char* name);
