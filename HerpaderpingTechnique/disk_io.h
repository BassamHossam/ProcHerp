#pragma once
#include <Windows.h>

BOOL LoadFileIntoMemory(LPWSTR filePath, PBYTE* outFileBuffer, PDWORD outFileSize);

BOOL OverwriteTargetFile(HANDLE sourceFileHandle, PBYTE sourceBuffer, DWORD sourceBufferSize, HANDLE destinationFileHandle, BOOL overwriteByHandle);
