;--------------------------------------------------------------------------------------------
;  Copyright (c) Ji-Feng Tsai. All rights reserved.
;  Code released under the MIT license.
;--------------------------------------------------------------------------------------------

#APP_NAME    = "ExePacker"
#APP_VERSION = "v1.1"

#MAGIC_LEN   = 8
#MAGIC_STR   = "PBPK2026"

; --- Footer layout (fixed size, written at the very end of the packed file) ---
;   [0..7]   Magic "PBPK2026"        (8 bytes)
;   [8]      FileType (0=EXE,1=DLL)  (1 byte)
;   [9]      ObfuscatedKey           (1 byte)
;   [10..13] OrigSize   (Long)       (4 bytes)
;   [14..17] OrigOffset (Long)       (4 bytes)
;   [18..21] OrigCRC32  (Long)       (4 bytes)
#FOOTER_SIZE = 22

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

; IDE Options = PureBasic 6.41 (Windows - x64)
; CursorPosition = 11
; Optimizer
; EnableThread
; EnableOnError
; CompileSourceDirectory
; Compiler = PureBasic 6.40 - C Backend (Windows - x64)