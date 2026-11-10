;--------------------------------------------------------------------------------------------
;  Copyright (c) Ji-Feng Tsai. All rights reserved.
;  Code released under the MIT license.
;--------------------------------------------------------------------------------------------

EnableExplicit

IncludeFile "Enums.pbi"
IncludeFile "Helper.pbi"

UseLZMAPacker() ; embeds the LZMA packer/unpacker code into this build

; <summary>
; Main
; </summary>
; <returns>Returns integer.</returns>
Procedure.i Main()
  Protected targetPath.s, stubPath.s, outputPath.s
  Protected *target, targetSize.i
  Protected *stub,   stubSize.i
  Protected tailOffset.i
  Protected outFile.i
  Protected peType.s
  Protected fileType.b
  Protected xorKey.b, obfKey.b
  Protected crc.l
  Protected i.i
  Protected *compBuf, compBufCapacity.i, compressedSize.i
  Protected *storedBuf, storedSize.i, compressed.b
  
  OpenConsole(#APP_NAME)

  If CountProgramParameters() < 1
    PrintN(#APP_NAME + " " + #APP_VERSION + " by Jiowcl")
    PrintN("Usage: ExePacker.exe <Target EXE|DLL> [stub.bin] [output path]")
    PrintN("")
    PrintN("Example:")
    PrintN("  ExePacker.exe target.exe")
    PrintN("  ExePacker.exe target.dll stub.bin")
    PrintN("  ExePacker.exe target.exe stub.bin packed\output.exe")
    ProcedureReturn 1
  EndIf

  targetPath = ProgramParameter(0)
  
  If CountProgramParameters() >= 2
    stubPath = ProgramParameter(1)
  Else
    stubPath = GetPathPart(ProgramFilename()) + "stub.bin"
  EndIf

  If FileSize(targetPath) <= 0
    PrintN("[Error] Target File Not Found: " + targetPath)
    ProcedureReturn 1
  EndIf

  *target = ReadWholeFile(targetPath, @targetSize)
  If *target = 0
    PrintN("[Error] Unable to Read Target File")
    ProcedureReturn 1
  EndIf

  If IsPEFile(*target, targetSize) = #False
    PrintN("[Warn] The Target File is Not a Valid PE (MZ) Format, but the Packing Process Continues....")
    peType = "Unknown"
  Else
    peType = GetPEType(*target, targetSize)
  EndIf

  If peType = "DLL"
    fileType = #FILE_TYPE_DLL
  Else
    fileType = #FILE_TYPE_EXE ; "EXE" and "Unknown" are both treated as best-effort EXE at run time
  EndIf

  ; CRC32 is computed over the ORIGINAL (plaintext, decompressed) content and
  ; is stored in the footer so the Stub can verify, after decrypting AND
  ; decompressing, that it ended up with exactly what was packed.
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

  ; Compression
  ; Compress BEFORE encrypting: LZMA needs to see the real byte patterns of
  ; the original content to find anything to compress; XOR'd data looks like
  ; noise and will not compress at all. Allow some headroom in the output
  ; buffer since compressed data can (rarely) end up slightly larger than
  ; the input for already-dense/incompressible content.
  compBufCapacity = targetSize + (targetSize / 10) + 4096
  *compBuf = AllocateMemory(compBufCapacity)
  
  compressed  = #False
  *storedBuf  = *target
  storedSize  = targetSize
  
  If *compBuf
    compressedSize = CompressMemory(*target, targetSize, *compBuf, compBufCapacity, #PB_PackerPlugin_Lzma, #COMPRESS_LEVEL)
    
    If compressedSize > 0 And compressedSize < targetSize
      compressed = #True
      *storedBuf = *compBuf
      storedSize = compressedSize
    Else
      FreeMemory(*compBuf)
      *compBuf = 0
    EndIf
  EndIf

  If compressed
    PrintN("[Info] Compressed Size: " + Str(storedSize) + " bytes (" + StrD(100.0 * storedSize / targetSize, 1) + "% of original)")
  Else
    PrintN("[Info] Compression Did Not Help - Storing Raw Content")
  EndIf

  ; Each packed build gets its own random key instead of sharing one fixed,
  ; hard-coded key across every build. This is still only a basic XOR cipher
  ; (see Helper.pbi), not real encryption - it stops casual inspection, not a
  ; determined analyst.
  RandomSeed(Date() ! GetCurrentProcessId_() ! ElapsedMilliseconds())
  xorKey = Random(254) + 1 ; 1..255, never 0 (0 would be a no-op XOR)
  obfKey = xorKey ! #KEY_MASK

  PrintN("[Process] Encrypting Content (XOR, per-build random key)...")
  EncryptBuffer(*storedBuf, storedSize, xorKey)

  tailOffset = stubSize

  If CountProgramParameters() >= 3
    outputPath = ProgramParameter(2)
  Else
    outputPath = GetPathPart(targetPath) + "packed_" + GetFilePart(targetPath)
  EndIf

  If FileSize(outputPath) > 0
    PrintN("[Warn] Output File Already Exists and Will Be Overwritten: " + outputPath)
  EndIf

  outFile = CreateFile(#PB_Any, outputPath)
  
  If outFile = 0
    PrintN("[Error] Unable to Create Output File: " + outputPath)
    FreeMemory(*target)
    FreeMemory(*stub)
    
    If *compBuf : FreeMemory(*compBuf) : EndIf
    
    ProcedureReturn 1
  EndIf

  If WriteData(outFile, *stub, stubSize) <> stubSize
    PrintN("[Error] Failed to Write Stub Data (disk full?)")
    CloseFile(outFile)
    FreeMemory(*target)
    FreeMemory(*stub)
    
    If *compBuf : FreeMemory(*compBuf) : EndIf
    
    ProcedureReturn 1
  EndIf

  If WriteData(outFile, *storedBuf, storedSize) <> storedSize
    PrintN("[Error] Failed to Write Payload Data (disk full?)")
    CloseFile(outFile)
    FreeMemory(*target)
    FreeMemory(*stub)
    
    If *compBuf : FreeMemory(*compBuf) : EndIf
    
    ProcedureReturn 1
  EndIf

  For i = 0 To #MAGIC_LEN - 1
    WriteByte(outFile, Asc(Mid(#MAGIC_STR, i + 1, 1)))
  Next
  
  WriteByte(outFile, fileType)
  WriteByte(outFile, obfKey)
  WriteByte(outFile, compressed)
  WriteLong(outFile, storedSize)
  WriteLong(outFile, targetSize)
  WriteLong(outFile, tailOffset)
  WriteLong(outFile, crc)

  CloseFile(outFile)
  FreeMemory(*target)
  FreeMemory(*stub)
  
  If *compBuf : FreeMemory(*compBuf) : EndIf

  PrintN("[Completed] Packing Successful!")
  PrintN("[Output] " + outputPath)
  PrintN("[Info] Output Size: " + Str(stubSize + storedSize + #FOOTER_SIZE) + " bytes")

  ProcedureReturn 0
EndProcedure

End Main()
; IDE Options = PureBasic 6.41 (Windows - x64)
; CursorPosition = 100
; FirstLine = 59
; Folding = -
; Optimizer
; EnableThread
; EnableOnError
; CompileSourceDirectory
; Compiler = PureBasic 6.40 - C Backend (Windows - x64)