#pragma once
#include "ntapis.h"
typedef struct _NtApiFunctionTable {
    fn_RtlInitUnicodeString RtlInitUnicodeString;
    fn_NtReadVirtualMemory NtReadVirtualMemory;
    fn_NtOpenProcess NtOpenProcess;
    fn_NtCreateFile NtCreateFile;
    fn_NtCreateSection NtCreateSection;
    fn_NtCreateProcessEx NtCreateProcessEx;
    fn_NtWriteFile NtWriteFile;
    fn_NtQuerySystemInformation NtQuerySystemInformation;
    fn_NtClose NtClose;
    fn_NtAllocateVirtualMemory NtAllocateVirtualMemory;
    fn_NtCreateThreadEx NtCreateThreadEx;
    fn_RtlCreateProcessParametersEx RtlCreateProcessParametersEx;
    fn_NtWriteVirtualMemory NtWriteVirtualMemory;
    fn_NtQueryInformationFile NtQueryInformationFile;
    fn_NtQueryInformationProcess NtQueryInformationProcess;
    fn_CreateEnvironmentBlock CreateEnvironmentBlock;
} NtApiFunctionTable, *PNtApiFunctionTable;

extern NtApiFunctionTable GlobalNtApiTable;

#define ALLOC_MEMORY(SIZE) LocalAlloc(LPTR, (SIZE_T)SIZE)
#define PROCESS_CREATION_FLAG_INHERIT_HANDLES 0x00000004
