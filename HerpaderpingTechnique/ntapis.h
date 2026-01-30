#pragma once 
#ifndef _N_T_API_H_ 
#define _N_T_API_H_

#include <Windows.h>
#include <winternl.h>

#pragma warning(disable: 4005) 

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef _MY_PS_ATTRIBUTE_DEFINED 
#define _MY_PS_ATTRIBUTE_DEFINED
#define FileStandardInformation 5 
#define ProcessBasicInformation 0
//#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x01


typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} MY_PEB, * PMY_PEB;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;


typedef struct _MY_RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    BYTE Reserved[200];
    ULONG_PTR EnvironmentSize;
} MY_RTL_USER_PROCESS_PARAMETERS, * PMY_RTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI* fn_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID, * MY_PCLIENT_ID;
typedef struct _MY_PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} MY_PS_ATTRIBUTE, * PMY_PS_ATTRIBUTE;

typedef struct _MY_PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    MY_PS_ATTRIBUTE Attributes[1];
} MY_PS_ATTRIBUTE_LIST, * PMY_PS_ATTRIBUTE_LIST;

#endif
typedef struct _MY_LDR_DATA_TABLE_ENTRY_BASE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY_BASE, * MY_PLDR_DATA_TABLE_ENTRY_BASE;

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;

} USTRING;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG Reserved
    );


typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    PVOID ThreadParameter
    );
typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION, * MY_PPROCESS_BASIC_INFORMATION;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
//typedef struct _MY_RTL_USER_PROCESS_PARAMETERS {
//    ULONG MaximumLength;
//    ULONG Length;
//    ULONG Flags;
//    ULONG DebugFlags;
//    HANDLE ConsoleHandle;
//    ULONG ConsoleFlags;
//    HANDLE StandardInput;
//    HANDLE StandardOutput;
//    HANDLE StandardError;
//    CURDIR CurrentDirectory;
//    UNICODE_STRING DllPath;
//    UNICODE_STRING ImagePathName;
//    UNICODE_STRING CommandLine;
//    PVOID Environment;
//    ULONG StartingX;
//    ULONG StartingY;
//    ULONG CountX;
//    ULONG CountY;
//    ULONG CountCharsX;
//    ULONG CountCharsY;
//    ULONG FillAttribute;
//    ULONG WindowFlags;
//    ULONG ShowWindowFlags;
//    UNICODE_STRING WindowTitle;
//    UNICODE_STRING DesktopInfo;
//    UNICODE_STRING ShellInfo;
//    UNICODE_STRING RuntimeData;
//    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
//    ULONG_PTR EnvironmentSize;
//    ULONG_PTR EnvironmentVersion;
//    PVOID PackageDependencyData;
//    ULONG ProcessGroupId;
//    ULONG LoaderThreads;
//} MY_RTL_USER_PROCESS_PARAMETERS, * MT_PRTL_USER_PROCESS_PARAMETERS;


typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;
//typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;



typedef NTSTATUS(NTAPI* fn_NtQueryInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass
    );
typedef NTSTATUS(NTAPI* fn_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

typedef NTSTATUS(NTAPI* fn_NtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );
typedef NTSTATUS(NTAPI* fn_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fn_NtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
    );

typedef NTSTATUS(NTAPI* fn_NtWriteFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

typedef NTSTATUS(NTAPI* fn_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fn_NtClose)(
    HANDLE Handle
    );

typedef NTSTATUS(NTAPI* fn_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PUSER_THREAD_START_ROUTINE StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PMY_PS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(NTAPI* fn_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
    );

typedef NTSTATUS(NTAPI* fn_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* fn_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* fn_RtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
    );
typedef NTSTATUS(NTAPI* fn_NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    MY_PCLIENT_ID ClientId
    );
typedef BOOL(WINAPI* fn_CreateEnvironmentBlock)(
    LPVOID* lpEnvironment,
    HANDLE hToken,
    BOOL bInherit
    );

typedef NTSTATUS(NTAPI* fn_SystemFunction032)(
    struct USTRING* Data,
    struct USTRING* Key
    );

#endif