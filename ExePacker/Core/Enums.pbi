;--------------------------------------------------------------------------------------------
;  Copyright (c) Ji-Feng Tsai. All rights reserved.
;  Code released under the MIT license.
;--------------------------------------------------------------------------------------------

#APP_NAME    = "ExePacker"
#APP_VERSION = "v1.2"

#MAGIC_LEN   = 8
#MAGIC_STR   = "PBPK2026"

; --- Footer layout (fixed size, written at the very end of the packed file) ---
;   [0..7]   Magic "PBPK2026"          (8 bytes)
;   [8]      FileType (0=EXE,1=DLL)    (1 byte)
;   [9]      ObfuscatedKey             (1 byte)
;   [10]     Compressed (0=no,1=yes)   (1 byte)
;   [11..14] StoredSize  (Long)        (4 bytes) - bytes physically appended after the Stub
;                                                   (post-compression, post-encryption)
;   [15..18] OrigSize    (Long)        (4 bytes) - size of the original, decompressed content
;   [19..22] StoredOffset(Long)        (4 bytes) - == Stub size; where the payload begins
;   [23..26] OrigCRC32   (Long)        (4 bytes) - CRC32 of the original, decompressed content
#FOOTER_SIZE = 27

#FILE_TYPE_EXE = 0
#FILE_TYPE_DLL = 1

; Fixed mask only used so the per-build XOR key is not stored completely in
; the clear in the footer. This is NOT real security - anyone who reads the
; Stub's source/binary can recover #KEY_MASK and thus the real key just as
; easily. It only avoids the most naive "grep the footer bytes" approach and
; ensures every packed build uses a different effective key.
#KEY_MASK = $5A

; Name of the exported function ExeStub looks for when the payload is a DLL.
; Convention: Void ExePackerRun(void) - no parameters, no return value.
#DLL_ENTRY_NAME = "ExePackerRun"

; LZMA compression level: 0 (fastest/worst ratio) .. 9 (slowest/best ratio).
; Packing is an offline, one-off operation, so always use the best ratio.
#COMPRESS_LEVEL = 9

; Hard upper bound on OrigSize that ExeStub will ever trust from its own
; footer before allocating memory for decompression. OrigSize is read from
; data appended to our own file, which could in principle be corrupted or
; hand-edited; without a cap a tiny compressed stream could claim an
; enormous OrigSize and force a huge allocation (a "zip bomb" style attack
; against the Stub itself). 1 GB is far more than any sane EXE/DLL payload.
#MAX_PAYLOAD_SIZE = 1024 * 1024 * 1024

; IDE Options = PureBasic 6.41 (Windows - x64)
; CursorPosition = 48
; Optimizer
; EnableThread
; EnableOnError
; CompileSourceDirectory
; Compiler = PureBasic 6.40 - C Backend (Windows - x64)