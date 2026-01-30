#pragma once
#include <Windows.h>
#include "globals.h"

BOOL SetupProcessParameters(IN HANDLE processHandle, IN LPWSTR targetProcessPath, OUT PVOID* outImageBase);

BOOL ExecuteHerpaderping(IN LPWSTR tempFilePath, IN LPWSTR legitImagePath, IN PBYTE payloadBuffer, IN DWORD payloadSize);
