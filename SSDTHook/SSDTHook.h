#pragma once
#include <fltKernel.h>
#include <ntimage.h>

#pragma warning(disable:4100) //Unreference parameter
#pragma warning(disable:4152) //function pointer transfer
#pragma warning(disable:4305) //ULONG64 --> other
#pragma warning(disable:4047) //ULONG64 --> PVOID

typedef NTSTATUS(NTAPI* LPFN_NTTERMINATEPROCESS)(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE{
	PVOID  			ServiceTableBase;
	PVOID  			ServiceCounterTableBase;
	ULONG_PTR  		NumberOfServices;
	PVOID  			ParameterTableBase;
}SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

VOID WPOFF();
VOID WPON();
void DriverUnload(PDRIVER_OBJECT DriverObject);
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID BaseAddress);
BOOLEAN GetSsdtAddress(ULONG64* VirtualAddress);
BOOLEAN GetSsdtFunctionService(CHAR* FunctionName, ULONG32* FunctionService);
BOOLEAN MappingDataInRing0Space(WCHAR* FileFullPath, PVOID* VirtualAddress, PSIZE_T ViewSize);
ULONG32 CalcServiceOffsetInSsdt(PVOID ServiceTableBase, PVOID FunctionAddress, ULONG32 ParameterCount);

VOID InlineHook(ULONG64 OriginalFunctionAddress, ULONG64 FakeFunctionAddress, UCHAR* CodeData, ULONG32 CodeLength);
VOID  UninlineHook(PVOID OriginalFunctionAddress, UCHAR* CodeData, ULONG32 CodeLength);
NTSTATUS NTAPI FakeNtTerminateProcess(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);
VOID HookSsdt(PVOID ServiceTableBase, ULONG32 FunctionService, PVOID FakeFunctionAddress, PVOID OriginalFunctionAddress, ULONG32 OriginalFunctionParameterCount, UCHAR* CodeData, ULONG32 CodeLength);
VOID UnhookSsdt(PVOID ServiceTableBase, ULONG32 FunctionService, ULONG32 OriginalFunctionOffset, PVOID OriginalFunctionAddress, UCHAR* CodeData, ULONG32 CodeLength);
