;--------------------------------------------------------------------------------------------
;  Copyright (c) Ji-Feng Tsai. All rights reserved.
;  Code released under the MIT license.
;--------------------------------------------------------------------------------------------

EnableExplicit

IncludeFile "Enums.pbi"
IncludeFile "Helper.pbi"

Prototype.i pDllEntryPoint()

ImportC "kernel32.lib"
  LoadLibraryW(lpLibFileName.p-unicode) As "LoadLibraryW"
  GetProcAddress(hModule.i, lpProcName.p-ascii) As "GetProcAddress"
  FreeLibrary(hLibModule.i)
EndImport

; <summary>
; RunHidden - Runs an EXE payload hidden and waits for it to finish.
; </summary>
; <param name="exePath">string</param>
; <param name="params">string</param>
; <returns>Returns the payload's exit code, or -1 if it could not be launched.</returns>
Procedure.i RunHidden(exePath.s, params.s)
  Protected prog.i, exitCode.i
  
  prog = RunProgram(exePath, params, "", #PB_Program_Wait | #PB_Program_Hide)
  
  If prog = 0
    ProcedureReturn -1
  EndIf
  
  exitCode = ProgramExitCode(prog)
  CloseProgram(prog)
  
  ProcedureReturn exitCode
EndProcedure

; <summary>
; RunDll - Loads a DLL payload and, if present, calls its exported
; "ExePackerRun" function (void, no parameters). This is the convention a
; packed DLL must follow for ExeStub to do anything useful with it.
; </summary>
; <param name="dllPath">string</param>
; <returns>Returns 0 on success, non-zero on failure (DLL failed to load).</returns>
Procedure.i RunDll(dllPath.s)
  Protected hLib.i, *proc, entry.pDllEntryPoint
  
  hLib = LoadLibraryW(dllPath)
  If hLib = 0
    ProcedureReturn 1
  EndIf
  
  *proc = GetProcAddress(hLib, #DLL_ENTRY_NAME)
  
  If *proc
    entry = *proc
    entry()
  EndIf
  
  FreeLibrary(hLib)
  
  ProcedureReturn 0
EndProcedure

; <summary>
; BuildTempPath - Generates a temp file path that does not currently exist,
; to avoid collisions between concurrent runs.
; </summary>
; <param name="extension">string</param>
; <returns>Returns string.</returns>
Procedure.s BuildTempPath(extension.s)
  Protected path.s, tries.i
  
  RandomSeed(ElapsedMilliseconds())
  
  For tries = 1 To 20
    path = GetTemporaryDirectory() + "~exepacker_" + Str(ElapsedMilliseconds()) + "_" + Str(Random(999999)) + extension
    If FileSize(path) = -1 ; does not exist yet
      ProcedureReturn path
    EndIf
  Next
  
  ; Extremely unlikely fallback if 20 attempts all collided
  ProcedureReturn GetTemporaryDirectory() + "~exepacker_" + Str(ElapsedMilliseconds()) + "_" + Str(Random(999999999)) + extension
EndProcedure

; <summary>
; Main
; </summary>
; <returns>
; Returns the payload's exit code when the payload is an EXE (or 0 for a
; successfully run DLL). Returns 1 if ExeStub itself could not unpack or
; verify the payload (missing/corrupt footer, CRC mismatch, I/O failure).
; </returns>
Procedure.i Main()
  Protected selfPath.s, selfFile.i, fileSize.i
  Protected fileType.b, obfKey.b, xorKey.b
  Protected origSize.i, origOffset.i, origCRC.l, actualCRC.l
  Protected *payload, tempPath.s, tempFile.i
  Protected magicBuf.s{8}, i.i, b.b
  Protected result.i, params.s

  selfPath = ProgramFilename()
  selfFile = ReadFile(#PB_Any, selfPath)
  
  If selfFile = 0 : ProcedureReturn 1 : EndIf

  fileSize = Lof(selfFile)
  
  If fileSize < #FOOTER_SIZE
    CloseFile(selfFile)
    ProcedureReturn 1
  EndIf

  FileSeek(selfFile, fileSize - #FOOTER_SIZE)
  
  For i = 0 To #MAGIC_LEN - 1
    b = ReadByte(selfFile)
    PokeB(@magicBuf + i, b)
  Next

  If PeekS(@magicBuf, #MAGIC_LEN, #PB_Ascii) <> #MAGIC_STR
    CloseFile(selfFile)
    ProcedureReturn 1
  EndIf

  fileType   = ReadByte(selfFile)
  obfKey     = ReadByte(selfFile)
  origSize   = ReadLong(selfFile)
  origOffset = ReadLong(selfFile)
  origCRC    = ReadLong(selfFile)

  ; Bounds / sanity validation
  ; The footer is just data appended to our own file. A truncated,
  ; corrupted, or hand-edited file must never be able to make us read
  ; or allocate out of bounds.
  If origSize <= 0 Or origOffset < 0 Or origOffset + origSize > fileSize - #FOOTER_SIZE
    CloseFile(selfFile)
    ProcedureReturn 1
  EndIf

  xorKey = obfKey ! #KEY_MASK

  *payload = AllocateMemory(origSize)
  
  If *payload = 0
    CloseFile(selfFile)
    ProcedureReturn 1
  EndIf

  FileSeek(selfFile, origOffset)
  
  If ReadData(selfFile, *payload, origSize) <> origSize
    CloseFile(selfFile)
    FreeMemory(*payload)
    ProcedureReturn 1
  EndIf
  
  CloseFile(selfFile)

  DecryptBuffer(*payload, origSize, xorKey)

  ; Integrity check
  ; Confirms the decrypted payload matches what was packed, instead of
  ; silently running (or trying to run) a corrupted/tampered executable.
  actualCRC = SimpleCRC32(*payload, origSize)
  
  If actualCRC <> origCRC
    FreeMemory(*payload)
    ProcedureReturn 1
  EndIf

  If fileType = #FILE_TYPE_DLL
    tempPath = BuildTempPath(".dll")
  Else
    tempPath = BuildTempPath(".exe")
  EndIf
  
  tempFile = CreateFile(#PB_Any, tempPath)
  
  If tempFile = 0
    FreeMemory(*payload)
    ProcedureReturn 1
  EndIf
  
  If WriteData(tempFile, *payload, origSize) <> origSize
    CloseFile(tempFile)
    FreeMemory(*payload)
    DeleteFile(tempPath)
    ProcedureReturn 1
  EndIf
  
  CloseFile(tempFile)
  FreeMemory(*payload)

  If fileType = #FILE_TYPE_DLL
    result = RunDll(tempPath)
  Else
    ; Forward whatever arguments the packed EXE was given on to the real payload
    params = ""
    
    For i = 0 To CountProgramParameters() - 1
      If i > 0 : params + " " : EndIf
      params + Chr(34) + ProgramParameter(i) + Chr(34)
    Next
    
    result = RunHidden(tempPath, params)
  EndIf

  DeleteFile(tempPath)

  ProcedureReturn result
EndProcedure

Main()
End
; IDE Options = PureBasic 6.41 (Windows - x64)
; CursorPosition = 217
; FirstLine = 168
; Folding = -
; Optimizer
; EnableThread
; EnableOnError
; Executable = ..\Output\ExeStub.exe
; CompileSourceDirectory
; Compiler = PureBasic 6.40 - C Backend (Windows - x64)