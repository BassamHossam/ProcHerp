#pragma once
#include <Windows.h>
#include "globals.h"

// Renamed from InitializeProcessParms
BOOL SetupProcessParameters(IN HANDLE processHandle, IN LPWSTR targetProcessPath, OUT PVOID* outImageBase);

// Renamed from HerpaderpProcess
BOOL ExecuteHerpaderping(IN LPWSTR tempFilePath, IN LPWSTR legitImagePath, IN PBYTE payloadBuffer, IN DWORD payloadSize);
