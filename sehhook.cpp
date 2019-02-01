#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<Windows.h>
#include<excpt.h>
#include"inlinehook.h"
#include"LDasm.h"
#include<TlHelp32.h>
#include"ntdll\ntdll.h"
#pragma comment(lib,"ntdll\\ntdll_x86.lib")

char *szHook = "hook ok";
BYTE bOriMsgbox;
DWORD AddrMsgBox;

void SetSeh();

typedef VOID (__fastcall *BaseThreadInitThunk)(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);


BaseThreadInitThunk oldBaseThreadInitThunk = NULL;
VOID __fastcall MyBaseThreadInitThunk(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	SetSeh();
	oldBaseThreadInitThunk(LdrReserved,lpStartAddress,lpParameter);
}

VOID WINAPI SetBaseThreadInitThunkHook()
{
	DWORD AddrBaseThreadInitThunk = (DWORD)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "BaseThreadInitThunk");
	if (AddrBaseThreadInitThunk)
	{
		InlineHook((void *)AddrBaseThreadInitThunk, (void *)MyBaseThreadInitThunk, (void **)&oldBaseThreadInitThunk);
	}
}

EXCEPTION_DISPOSITION
__cdecl Seh_Handle(struct _EXCEPTION_RECORD *ExceptionRecord,
	void * EstablisherFrame,
	struct _CONTEXT *ContextRecord,
	void * DispatcherContext)
{
	if (ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		*(PDWORD)(ContextRecord->Esp + 8) = (DWORD)szHook;
		*(PBYTE)AddrMsgBox = bOriMsgbox;
		ContextRecord->EFlags |= 0x100;
	}
	else if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		*(PBYTE)AddrMsgBox = 0xCC;
	}
	return ExceptionContinueExecution;
}

DWORD dwThreadIndex = 1;

DWORD ThreadProc(VOID *)
{
	char szTitle[0x20] = "子线程";
	sprintf(szTitle,"%s%d",szTitle, dwThreadIndex);
	dwThreadIndex++;
	while (true)
	{
		MessageBoxA(0, "no hook", szTitle, 0);
		Sleep(500);
	}
	return 0;
}

DWORD seh_table[2];

void SetSeh()
{
	PDWORD pTeb = (PDWORD)NtCurrentTeb();
	printf("Teb = %08X\n",pTeb);
	NT_TIB32 *pTib = (NT_TIB32 *)pTeb;
	PDWORD StackBase = (PDWORD)pTib->StackBase;
	*(StackBase-1) = (DWORD)Seh_Handle;
	*(StackBase - 2) = *pTeb;
	pTib->ExceptionList = (DWORD)(StackBase - 2);
}

void SetBeforeTheadHook()
{
	DWORD dwCrtPid = GetCurrentProcessId();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwCrtPid);
	THREADENTRY32 th32 = { sizeof(THREADENTRY32) };
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return;
	}

	Thread32First(hSnapshot, &th32);
	do
	{
		if (th32.th32OwnerProcessID == dwCrtPid)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
			_THREAD_BASIC_INFORMATION tbi;
			DWORD dwLen;
			NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), &dwLen);
			if (NT_SUCCESS(status))
			{
				PDWORD pTeb = (PDWORD)tbi.TebBaseAddress;
				NT_TIB32 *pTib = (NT_TIB32 *)tbi.TebBaseAddress;
				PDWORD StackBase = (PDWORD)pTib->StackBase;
				*(StackBase - 1) = (DWORD)Seh_Handle;
				*(StackBase - 2) = *pTeb;
				printf("StackBase = %08X\n", pTib->StackBase);
				printf("StackLimit = %08X\n", pTib->StackLimit);
				pTib->ExceptionList = (DWORD)(StackBase - 2);
			}
		}
	} while (Thread32Next(hSnapshot, &th32));
}

void main()
{
	AddrMsgBox = (DWORD)GetProcAddress(GetModuleHandleA("user32.dll"),"MessageBoxA");
	SetSeh();
	SetBaseThreadInitThunkHook();

	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ThreadProc, 0, 0, 0));

	SetBeforeTheadHook();

	//修改1字节为0xCC
	bOriMsgbox = *(PBYTE)AddrMsgBox;
	DWORD dwOldProtect;
	VirtualProtect((LPVOID)AddrMsgBox,1,PAGE_EXECUTE_READWRITE,&dwOldProtect);
	*(PBYTE)AddrMsgBox = 0xCC;

	MessageBoxA(0,"no hook","主线程",0);

	CloseHandle(CreateThread(0,0, (LPTHREAD_START_ROUTINE)ThreadProc,0,0,0));

	Sleep(INFINITE);
}