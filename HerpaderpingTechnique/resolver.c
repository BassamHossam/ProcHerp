#include "resolver.h"
#include "obfuscation.h"
#include <stdio.h>

PVOID ResolveFunctionAddress(HMODULE moduleHandle, unsigned long targetHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleHandle + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleHandle + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* addressOfNames = (DWORD*)((BYTE*)moduleHandle + exportDirectory->AddressOfNames);
    DWORD* addressOfFunctions = (DWORD*)((BYTE*)moduleHandle + exportDirectory->AddressOfFunctions);
    WORD* addressOfOrdinals = (WORD*)((BYTE*)moduleHandle + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)moduleHandle + addressOfNames[i]);
        unsigned long currentHash = CalculateStringHashA(functionName);
        if (currentHash == targetHash) {
            WORD ordinal = addressOfOrdinals[i];
            void* functionAddress = (void*)((BYTE*)moduleHandle + addressOfFunctions[ordinal]);
            return functionAddress;
        }
    }
    return NULL;
}

HMODULE GetModuleHandleHash(unsigned long targetHash) {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA ldrData = peb->Ldr;
    PLIST_ENTRY listEntry = &ldrData->InMemoryOrderModuleList;
    PLIST_ENTRY currentEntry = listEntry->Flink;
    
    while (currentEntry != listEntry) {
        MY_PLDR_DATA_TABLE_ENTRY_BASE tableEntry = (MY_PLDR_DATA_TABLE_ENTRY_BASE)((BYTE*)currentEntry - sizeof(LIST_ENTRY));
        if (tableEntry->BaseDllName.Buffer) {
            unsigned long currentHash = CalculateStringHashW(tableEntry->BaseDllName.Buffer);
            if (currentHash == targetHash) {
                return (HMODULE)tableEntry->DllBase;
            }
        }
        currentEntry = currentEntry->Flink;
    }
    return NULL;
}

void LogHashW(wchar_t* name) {
    printf("Hash for %ls is: 0x%08lx\n", name, (unsigned long)CalculateStringHashW(name));
}

void LogHashA(char* name) {
    printf("[#] Hash For %s is: 0x%08lx\n", name, CalculateStringHashA(name));
}
