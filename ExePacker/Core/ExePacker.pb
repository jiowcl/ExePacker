;--------------------------------------------------------------------------------------------
;  Copyright (c) Ji-Feng Tsai. All rights reserved.
;  Code released under the MIT license.
;--------------------------------------------------------------------------------------------

EnableExplicit

IncludeFile "Enums.pbi"
IncludeFile "Helper.pbi"

; <summary>
; Main
; </summary>
; <returns>Returns integer.</returns>
Procedure.i Main()
  Protected targetPath.s, stubPath.s, outputPath.s
  Protected *target, targetSize.i
  Protected *stub,   stubSize.i
  Protected *tail,   tailOffset.i
  Protected outFile.i
  Protected peType.s
  Protected crc.l
  Protected i.i
  
  OpenConsole(#APP_NAME)

  If CountProgramParameters() < 1
    PrintN(#APP_NAME + " " + #APP_VERSION + " by Jiowcl")
    PrintN("Usage: ExePacker.exe <Target EXE|DLL> [stub.bin]")
    PrintN("")
    PrintN("Example:")
    PrintN("  ExePacker.exe target.exe")
    PrintN("  ExePacker.exe target.dll stub.bin")
    ProcedureReturn 1
  EndIf

  targetPath = ProgramParameter(0)
  
  If CountProgramParameters() >= 2
    stubPath = ProgramParameter(1)
  Else
    stubPath = GetPathPart(ProgramFilename()) + "stub.bin"
  EndIf

  If FileSize(targetPath) <= 0
    PrintN("[Error] Target File Not Found:" + targetPath)
    ProcedureReturn 1
  EndIf

  *target = ReadWholeFile(targetPath, @targetSize)
  If *target = 0
    PrintN("[Error] Unable to Read Target File")
    ProcedureReturn 1
  EndIf

  If IsPEFile(*target, targetSize) = #False
    PrintN("[Warn] The Target File is Not Invalid PE (MZ) Format, but the Packing Process Continues....")
    peType = "Unknown"
  Else
    peType = GetPEType(*target, targetSize)
  EndIf

  crc = SimpleCRC32(*target, targetSize)
  PrintN("[Info] Target File   : " + targetPath)
  PrintN("[Info] FileType      : " + peType)
  PrintN("[Info] Original Size : " + Str(targetSize) + " bytes")
  PrintN("[Info] Original CRC32: " + Hex(crc, #PB_Long))

  If FileSize(stubPath) <= 0
    PrintN("[Error] Stub File Not Found: " + stubPath)
    PrintN("       Please Compile ExeStub.exe into stub.bin First.")
    FreeMemory(*target)
    ProcedureReturn 1
  EndIf

  *stub = ReadWholeFile(stubPath, @stubSize)
  If *stub = 0
    PrintN("[Error] Unable to Read Stub File")
    FreeMemory(*target)
    ProcedureReturn 1
  EndIf
  
  PrintN("[Info] Stub Size: " + Str(stubSize) + " bytes")
  PrintN("[Process] Encrypting Target Content（XOR 0x" + Hex(#XOR_KEY, #PB_Byte) + ")...")
  EncryptBuffer(*target, targetSize, #XOR_KEY)

  tailOffset = stubSize

  outputPath = GetPathPart(targetPath) + "packed_" + GetFilePart(targetPath)
  outFile = CreateFile(#PB_Any, outputPath)
  
  If outFile = 0
    PrintN("[Error] Unable to Create Output File: " + outputPath)
    FreeMemory(*target)
    FreeMemory(*stub)
    ProcedureReturn 1
  EndIf

  WriteData(outFile, *stub, stubSize)
  WriteData(outFile, *target, targetSize)

  For i = 0 To 7
    WriteByte(outFile, Asc(Mid(#MAGIC_STR, i + 1, 1)))
  Next
  
  WriteLong(outFile, targetSize)
  WriteLong(outFile, tailOffset)

  CloseFile(outFile)
  FreeMemory(*target)
  FreeMemory(*stub)

  PrintN("[Completed] Packing Successful!")
  PrintN("[Output] " + outputPath)
  PrintN("[Info] Output Size: " + Str(stubSize + targetSize + 16) + " bytes")

  ProcedureReturn 0
EndProcedure

Main()
End
; IDE Options = PureBasic 6.41 (Windows - x64)
; CursorPosition = 27
; Folding = -
; Optimizer
; EnableThread
; EnableOnError
; CompileSourceDirectory
; Compiler = PureBasic 6.40 - C Backend (Windows - x64)