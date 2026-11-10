;--------------------------------------------------------------------------------------------
;  Copyright (c) Ji-Feng Tsai. All rights reserved.
;  Code released under the MIT license.
;--------------------------------------------------------------------------------------------

EnableExplicit

IncludeFile "Enums.pbi"
IncludeFile "Helper.pbi"

ImportC "kernel32.lib"
  GetTempPathW(nBufferLength.i, lpBuffer.p-unicode)
EndImport

; <summary>
; RunHidden
; </summary>
; <param name="exePath">string</param>
; <param name="params">string</param>
; <returns>Returns integer.</returns>
Procedure.i RunHidden(exePath.s, params.s)
  ProcedureReturn RunProgram(exePath, params, "", #PB_Program_Wait | #PB_Program_Hide)
EndProcedure

; <summary>
; Main
; </summary>
; <returns>Returns integer.</returns>
Procedure.i Main()
  Protected selfPath.s, selfFile.i, fileSize.i
  Protected origSize.i, origOffset.i
  Protected *payload, tempPath.s, tempFile.i
  Protected magicBuf.s{8}, i.i, b.b

  selfPath = ProgramFilename()
  selfFile  = ReadFile(#PB_Any, selfPath)
  
  If selfFile = 0 : ProcedureReturn 1 : EndIf

  fileSize = Lof(selfFile)
  
  If fileSize < 16
    CloseFile(selfFile)
    ProcedureReturn 1
  EndIf

  FileSeek(selfFile, fileSize - 16)
  
  For i = 0 To 7
    b = ReadByte(selfFile)
    PokeB(@magicBuf + i, b)
  Next

  If PeekS(@magicBuf, 8, #PB_Ascii) <> #MAGIC_STR
    CloseFile(selfFile)
    
    ProcedureReturn 1
  EndIf

  origSize   = ReadLong(selfFile)
  origOffset = ReadLong(selfFile)

  *payload = AllocateMemory(origSize)
  
  If *payload = 0
    CloseFile(selfFile)
    
    ProcedureReturn 1
  EndIf

  FileSeek(selfFile, origOffset)
  ReadData(selfFile, *payload, origSize)
  CloseFile(selfFile)

  DecryptBuffer(*payload, origSize)

  tempPath = GetTemporaryDirectory() + "~exepacker_" + Str(ElapsedMilliseconds()) + ".exe"
  tempFile = CreateFile(#PB_Any, tempPath)
  
  If tempFile = 0
    FreeMemory(*payload)
    
    ProcedureReturn 1
  EndIf
  
  WriteData(tempFile, *payload, origSize)
  CloseFile(tempFile)
  FreeMemory(*payload)

  RunHidden(tempPath, "")
  DeleteFile(tempPath)

  ProcedureReturn 0
EndProcedure

Main()
End
; IDE Options = PureBasic 6.41 (Windows - x64)
; CursorPosition = 96
; FirstLine = 47
; Folding = -
; Optimizer
; EnableThread
; EnableOnError
; CompileSourceDirectory
; Compiler = PureBasic 6.40 - C Backend (Windows - x64)