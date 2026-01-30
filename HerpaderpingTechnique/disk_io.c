#include "disk_io.h"
#include "globals.h"
#include <stdio.h>

BOOL LoadFileIntoMemory(LPWSTR filePath, PBYTE* outFileBuffer, PDWORD outFileSize) {
    HANDLE fileHandle = NULL;
    PBYTE tempBuffer = NULL;
    DWORD fileSize = 0;
    DWORD bytesRead = 0;

    if (!filePath || !outFileSize || !outFileBuffer)
        return FALSE;

    if ((fileHandle = CreateFileW(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateFileW Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    if ((fileSize = GetFileSize(fileHandle, NULL)) == INVALID_FILE_SIZE) {
        fprintf(stderr, "[-] GetFileSize Failed With Error : %d\n", GetLastError());
        goto CLEANUP;
    }

    if (!(tempBuffer = ALLOC_MEMORY(fileSize))) {
        fprintf(stderr, "[-] Memory Allocation Failed\n"); // Typo fixed from "Faild\m"
        goto CLEANUP;
    }

    if (!ReadFile(fileHandle, tempBuffer, fileSize, &bytesRead, NULL) || fileSize != bytesRead) {
        fprintf(stderr, "[-] ReadFile Error\n"); // Typo fixed from "Error\m"
        goto CLEANUP;
    }

    *outFileBuffer = tempBuffer;
    *outFileSize = fileSize;

CLEANUP:
    CloseHandle(fileHandle);
    if (tempBuffer && !*outFileBuffer)
        LocalFree(tempBuffer);

    return *outFileBuffer == NULL ? FALSE : TRUE;
}

BOOL OverwriteTargetFile(HANDLE sourceFileHandle, PBYTE sourceBuffer, DWORD sourceBufferSize, HANDLE destinationFileHandle, BOOL overwriteByHandle) {
    PBYTE fileBuffer = sourceBuffer;
    DWORD fileSize = sourceBufferSize;
    DWORD bytesWritten = 0;
    BOOL result = FALSE;

    if (!destinationFileHandle || destinationFileHandle == INVALID_HANDLE_VALUE)
        return FALSE;

    if ((overwriteByHandle && !sourceFileHandle) || (overwriteByHandle && sourceFileHandle == INVALID_HANDLE_VALUE))
        return FALSE;

    if ((!overwriteByHandle && !sourceBuffer) || (!overwriteByHandle && !sourceBufferSize))
        return FALSE;

    if (overwriteByHandle) {
        DWORD bytesRead = 0;
        if ((fileSize = GetFileSize(sourceFileHandle, NULL)) == INVALID_FILE_SIZE) {
            fprintf(stderr, "[-] GetFileSize Error\n");
            return FALSE;
        }

        if (!(fileBuffer = LocalAlloc(LPTR, (SIZE_T)fileSize))) {
            fprintf(stderr, "[-] LocalAlloc Failed \n");
            return FALSE;
        }

        if (SetFilePointer(sourceFileHandle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            fprintf(stderr, "[-] SetFilePointer [1]\n");
            return FALSE;
        }

        if (SetFilePointer(destinationFileHandle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            fprintf(stderr, "[-] SetFilePointer [2]\n");
            return FALSE;
        }

        if (!ReadFile(sourceFileHandle, fileBuffer, fileSize, &bytesRead, NULL) || fileSize != bytesRead) {
            fprintf(stderr, "[-] ReadFile Failed \n");
            goto END_OF_FUNCTION;
        }
    }

    if (!WriteFile(destinationFileHandle, fileBuffer, fileSize, &bytesWritten, NULL) || fileSize != bytesWritten) {
        fprintf(stderr, "WriteFile Failed\n");
        goto END_OF_FUNCTION;
    }

    if (!FlushFileBuffers(destinationFileHandle)) {
        fprintf(stderr, " [-] FlushFileBuffers\n");
        goto END_OF_FUNCTION;
    }

    if (!SetEndOfFile(destinationFileHandle)) {
        fprintf(stderr, "[-] SetEndOfFile\n");
        goto END_OF_FUNCTION;
    }

    result = TRUE;

END_OF_FUNCTION:
    if (fileBuffer && overwriteByHandle)
        LocalFree(fileBuffer);
    return result;
}
