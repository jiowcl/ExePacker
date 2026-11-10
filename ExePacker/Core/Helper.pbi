;--------------------------------------------------------------------------------------------
;  Copyright (c) Ji-Feng Tsai. All rights reserved.
;  Code released under the MIT license.
;--------------------------------------------------------------------------------------------

; <summary>
; EncryptBuffer - XOR every byte of the buffer with a single-byte key.
; </summary>
; <param name="*buf">pointer</param>
; <param name="size">integer</param>
; <param name="key">byte</param>
; <returns>Returns void.</returns>
Procedure EncryptBuffer(*buf, size.i, key.b)
  Protected i.i
  
  For i = 0 To size - 1
    PokeB(*buf + i, PeekB(*buf + i) ! key)
  Next
EndProcedure

; <summary>
; DecryptBuffer - XOR is symmetric, so this performs the same operation as
; EncryptBuffer(); it takes the key explicitly because each packed build now
; uses its own randomly generated key instead of a single global constant.
; </summary>
; <param name="*buf">pointer</param>
; <param name="size">integer</param>
; <param name="key">byte</param>
; <returns>Returns void.</returns>
Procedure DecryptBuffer(*buf, size.i, key.b)
  Protected i.i
  
  For i = 0 To size - 1
    PokeB(*buf + i, PeekB(*buf + i) ! key)
  Next
EndProcedure

; <summary>
; IsPEFile
; </summary>
; <param name="*buf">pointer</param>
; <param name="size">integer</param>
; <returns>Returns byte.</returns>
Procedure.b IsPEFile(*buf, size.i)
  If size < 2 : ProcedureReturn #False : EndIf
  If PeekW(*buf) <> $5A4D : ProcedureReturn #False : EndIf  ; 'MZ'
  
  ProcedureReturn #True
EndProcedure

; <summary>
; GetPEType - Reads IMAGE_DOS_HEADER/IMAGE_FILE_HEADER to classify EXE vs DLL.
; e_lfanew is treated as unsigned and range-checked against the buffer size
; before use, so a malformed/crafted header cannot push the read pointer
; out of bounds.
; </summary>
; <param name="*buf">pointer</param>
; <param name="size">integer</param>
; <returns>Returns string.</returns>
Procedure.s GetPEType(*buf, size.i)
  Protected e_lfanew.l, peOffset.q, characteristics.w
  If size < 64 : ProcedureReturn "Unknown" : EndIf
  
  e_lfanew = PeekL(*buf + 60)          ; IMAGE_DOS_HEADER.e_lfanew
  peOffset = e_lfanew & $FFFFFFFF      ; treat as unsigned to avoid negative offsets
  
  If peOffset < 4 Or peOffset + 24 > size : ProcedureReturn "Unknown" : EndIf
  If PeekL(*buf + peOffset) <> $00004550 : ProcedureReturn "Unknown" : EndIf ; 'PE\0\0'
  
  characteristics = PeekW(*buf + peOffset + 22) ; IMAGE_FILE_HEADER.Characteristics
  
  If characteristics & $2000 ; IMAGE_FILE_DLL
    ProcedureReturn "DLL"
  Else
    ProcedureReturn "EXE"
  EndIf
EndProcedure

; <summary>
; SimpleCRC32
; </summary>
; <param name="*buf">pointer</param>
; <param name="size">integer</param>
; <returns>Returns long.</returns>
Procedure.l SimpleCRC32(*buf, size.i)
  Protected crc.l = $FFFFFFFF, i.i, b.b, j.i
  
  For i = 0 To size - 1
    b = PeekB(*buf + i)
    crc ! b
    
    For j = 0 To 7
      If crc & 1
        crc = (crc >> 1) ! $EDB88320
      Else
        crc >> 1
      EndIf
    Next
  Next
  
  ProcedureReturn crc ! $FFFFFFFF
EndProcedure

; <summary>
; ReadWholeFile
; </summary>
; <param name="path">string</param>
; <param name="*outSize">pointer</param>
; <returns>Returns pointer (0 on any failure).</returns>
Procedure ReadWholeFile(path.s, *outSize)
  Protected f.i, sz.i, *buf
  
  f = ReadFile(#PB_Any, path)
  If f = 0 : ProcedureReturn 0 : EndIf
  
  sz = Lof(f)
  
  If sz <= 0
    CloseFile(f)
    ProcedureReturn 0
  EndIf
  
  *buf = AllocateMemory(sz)
  
  If *buf
    If ReadData(f, *buf, sz) <> sz
      FreeMemory(*buf)
      CloseFile(f)
      ProcedureReturn 0
    EndIf
    
    PokeI(*outSize, sz)
  EndIf
  
  CloseFile(f)
  
  ProcedureReturn *buf
EndProcedure

; IDE Options = PureBasic 6.41 (Windows - x64)
; CursorPosition = 137
; FirstLine = 89
; Folding = --
; Optimizer
; EnableThread
; EnableOnError
; CompileSourceDirectory
; Compiler = PureBasic 6.40 - C Backend (Windows - x64)