#include "SSDTHook.h"

//////////////////////////////////////////////////////////////////////////
PVOID							__ServiceTableBase;
ULONG32							__NtTerminateProcessService; //为API的系统服务索引
ULONG							__NtTerminateProcessOffset; //API的偏移
LPFN_NTTERMINATEPROCESS			__NtTerminateProcess;
UCHAR							__CodeData[15] = { 0 };
BOOLEAN							__IsHook;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	DbgPrint("DriverEntry\r\n");

	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ULONG64 SsdtAddress;
	if (!GetSsdtAddress(&SsdtAddress))
	{
		return Status;
	}

	char* FunctionName = "NtTerminateProcess";
	if (!GetSsdtFunctionService(FunctionName, &__NtTerminateProcessService))
	{
		return STATUS_UNSUCCESSFUL;
	}

	__ServiceTableBase = ((PSYSTEM_SERVICE_DESCRIPTOR_TABLE)SsdtAddress)->ServiceTableBase;

	__NtTerminateProcessOffset = ((PULONG32)__ServiceTableBase)[__NtTerminateProcessService];

	ULONG32 Index = __NtTerminateProcessOffset >> 4;
	__NtTerminateProcess = (PVOID)((ULONG64)__ServiceTableBase + Index);

	HookSsdt(__ServiceTableBase, __NtTerminateProcessService, FakeNtTerminateProcess, KeBugCheckEx, 5, __CodeData, 15);

	return STATUS_SUCCESS;
}

BOOLEAN GetSsdtAddress(ULONG64* VirtualAddress)
{
	PUCHAR Start = (PUCHAR)__readmsr(0xc0000082); //KiSystemCall64
	PUCHAR End = Start + PAGE_SIZE;
	INT64 Offset;
	UCHAR v1, v2, v3;
	for (PUCHAR i = Start; i < End; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			v1 = *i;
			v2 = *(i + 1);
			v3 = *(i + 2);
			if (v1 == 0x4c && v2 == 0x8d && v3 == 0x15) 
			{
				memcpy(&Offset, i + 3, 4); 
				*VirtualAddress = (ULONG64)i + Offset + 7;
				break;
			}
		}
	}
	if (VirtualAddress == NULL)
	{
		return FALSE;
	}

	return TRUE;
}

BOOLEAN GetSsdtFunctionService(CHAR* FunctionName, ULONG32* FunctionService)
{
	BOOLEAN IsOk = FALSE;

	WCHAR* FileFullPath = L"\\SystemRoot\\System32\\ntdll.dll";
	PVOID VirtualAddress = NULL;
	SIZE_T ViewSize = 0;
	IsOk = MappingDataInRing0Space(FileFullPath, &VirtualAddress, &ViewSize);
	if (IsOk == FALSE)
	{
		return FALSE;
	}
	else
	{
		__try 
		{
			PIMAGE_NT_HEADERS ImageNtHeaders = RtlImageNtHeader(VirtualAddress);
			if (ImageNtHeaders && ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((UINT8*)VirtualAddress + ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); 
				UINT32* AddressOfFunctions = (UINT32*)((UINT8*)VirtualAddress + ImageExportDirectory->AddressOfFunctions);
				UINT32* AddressOfNames = (UINT32*)((UINT8*)VirtualAddress + ImageExportDirectory->AddressOfNames);
				UINT16* AddressOfNameOrdinals = (UINT16*)((UINT8*)VirtualAddress + ImageExportDirectory->AddressOfNameOrdinals);
				for (SIZE_T i = 0; i < (ImageExportDirectory->NumberOfNames); i++)
				{
					char* TempString = (char*)((ULONG64)VirtualAddress + AddressOfNames[i]);   //获得函数名称
					if (!_stricmp(FunctionName, TempString))
					{
						ULONG32 FunctionOrdinal = AddressOfNameOrdinals[i];
						PVOID FunctionAddress = (PVOID)((UINT8*)VirtualAddress + AddressOfFunctions[FunctionOrdinal]);
						*FunctionService = *(ULONG32*)((UINT8*)FunctionAddress + 4);
						break;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}
	ZwUnmapViewOfSection(NtCurrentProcess(), VirtualAddress);  //解除映射
	if (*FunctionService == -1)
	{
		return FALSE;
	}

	return TRUE;
}

BOOLEAN MappingDataInRing0Space(WCHAR* FileFullPath, PVOID* VirtualAddress, PSIZE_T ViewSize)
{
	if (!FileFullPath && MmIsAddressValid(FileFullPath))
	{
		return FALSE;
	}
	if (!VirtualAddress && MmIsAddressValid(VirtualAddress))
	{
		return FALSE;
	}

	//将文件路径转换成UNICODE_STRING存储
	UNICODE_STRING unstFileFullPath;
	RtlInitUnicodeString(&unstFileFullPath, FileFullPath);

	//根据UNICODE_STRING创建对象属性
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &unstFileFullPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	//获得文件句柄
	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status = IoCreateFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL,
		0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING );
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	//根据文件句柄创建映射对象
	ObjectAttributes.ObjectName = NULL;

#define SEC_IMAGE  0x001000000
	HANDLE SectionHandle;
	Status = ZwCreateSection(&SectionHandle, SECTION_QUERY | SECTION_MAP_READ, &ObjectAttributes, NULL, PAGE_WRITECOPY, SEC_IMAGE, FileHandle );
	ZwClose(FileHandle);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	Status = ZwMapViewOfSection(SectionHandle, NtCurrentProcess(), VirtualAddress, 0, 0, 0, ViewSize, ViewUnmap, 0, PAGE_WRITECOPY );
	ZwClose(SectionHandle);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	return TRUE;
}

ULONG32 CalcServiceOffsetInSsdt(PVOID ServiceTableBase, PVOID FunctionAddress, ULONG32 ParameterCount)
{
	ULONG32 FunctionOffset = (ULONG32)((ULONG64)FunctionAddress - (ULONG64)ServiceTableBase);
	FunctionOffset = FunctionOffset << 4;
	if (ParameterCount > 4)
	{
		ParameterCount = ParameterCount - 4;     //NtReadFile  9个参数
	}
	else
	{
		ParameterCount = 0;
	}

	CHAR LowBit;
	memcpy(&LowBit, &FunctionOffset, 1);

#define SETBIT(x,y)		x |=  (1 << y)         //将X的第Y位置1
#define CLRBIT(x,y)		x &= ~(1 << y)        //将X的第Y位清0
#define GETBIT(x,y)		(x & (1 << y))    //取X的第Y位，返回0或非0

	CHAR Bits[4];
	for (int i = 0; i < 4; i++)    //一个16进制 4个二进制      0000
	{
		Bits[i] = GETBIT(ParameterCount, i);
		if (Bits[i])
		{
			SETBIT(LowBit, i);
		}
		else
		{
			CLRBIT(LowBit, i);
		}
	}
	/*
	ulParamCount    i        szBits[i]    b       i       b
	0101            0         1          0000     0      0001   set
	0101            1         0          0001     1      0001   clr
	0101            2         1          0001     2      0101   set
	0101            3         0          0101     3      0101   clr

	*/
	//把数据复制回去
	memcpy(&FunctionOffset, &LowBit, 1);
	return FunctionOffset;
}

VOID InlineHook(ULONG64 OriginalFunctionAddress, ULONG64 FakeFunctionAddress, UCHAR* CodeData, ULONG32 CodeLength)
{
	UCHAR PatchCodeData[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";   //InlineHook  Jmp 函数地址

	memcpy(CodeData, (PVOID)OriginalFunctionAddress, CodeLength);   //保存原始函数的指令

	memcpy(PatchCodeData + 6, &FakeFunctionAddress, 8);

	memset((PVOID)OriginalFunctionAddress, 0x90, CodeLength);

	memcpy((PVOID)OriginalFunctionAddress, PatchCodeData, 14);
}

VOID UninlineHook(PVOID OriginalFunctionAddress, UCHAR* CodeData, ULONG32 CodeLength)
{
	memcpy((PVOID)OriginalFunctionAddress, CodeData, CodeLength);
}

NTSTATUS FakeNtTerminateProcess(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus)
{
	return STATUS_ACCESS_DENIED;
}

VOID HookSsdt(PVOID ServiceTableBase, ULONG32 FunctionService, PVOID FakeFunctionAddress, PVOID OriginalFunctionAddress, ULONG32 OriginalFunctionParameterCount, UCHAR* CodeData, ULONG32 CodeLength)
{
	WPOFF();

	//KeBugCheckEx   FakeNtTerminateProcess
	InlineHook(OriginalFunctionParameterCount, (ULONG64)FakeFunctionAddress, CodeData, CodeLength);

	WPON();
	//寻找一个内核不常用的函数(KeBugCheckEx) 计算SSDT中的偏移 进行置换

	ULONG KeBugCheckExAddress = CalcServiceOffsetInSsdt(ServiceTableBase, (PVOID)FunctionService, OriginalFunctionParameterCount);

	WPOFF();
	((PULONG32)ServiceTableBase)[FunctionService] = (ULONG32)KeBugCheckExAddress;
	WPON();

	__IsHook = TRUE;
}

VOID UnhookSsdt(PVOID ServiceTableBase, ULONG32 FunctionService, ULONG32 OriginalFunctionOffset, PVOID OriginalFunctionAddress, UCHAR* CodeData, ULONG32 CodeLength)
{
	WPOFF();
	UninlineHook(OriginalFunctionAddress, CodeData, CodeLength);
	WPON();

	WPOFF();
	((PULONG32)ServiceTableBase)[FunctionService] = (ULONG32)OriginalFunctionOffset;
	WPON();
}

VOID WPOFF()
{
	_disable();
	__writecr0(__readcr0() & (~(0x10000)));

}

VOID WPON()
{
	__writecr0(__readcr0() ^ 0x10000); //异或1就是取反
	_enable();
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("DriverUnload\r\n");

	if (__IsHook)
	{
		UnhookSsdt(__ServiceTableBase, __NtTerminateProcessService, __NtTerminateProcessOffset, KeBugCheckEx, __CodeData, 15);
		__IsHook = FALSE;
	}
}
