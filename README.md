# Founding
![GitHub Logo](/Founding/eren1.png)

## Description
Founding is a tool that receives a Shellcode in ```.bin```, ```.exe``` or ```.dll``` format, Obfuscates or Encrypts this shellcode and then generates a new binary utilizing some execution techniques.

## Features
### Founding has the following features for every compilaion

- **Dynamic API Hashing**
  - Dynamic API Hashing generates unique hash values for API functions at runtime
    
- **IAT Camouflage**
  - Invokes a selection of Windows API functions, elevating the final binary's legitimacy
 
- **Minimal CRT**
  - Removing the CRT Library to have control of what functions are shown on the Import Address Table
 
- **Watermark**
  - Inject custom Watermarks to resulting PE artifacts - in DOS Stub, Checksum, as a standalone PE Section, to file's Overlay
 
- **Resource File**
  - Embed the final binary with set of file property details similar to cleanmgr.exe executable
 
- **Preamble 0xfc 0x48**
  - Each shellcode will be added  the preamble xFCx48 in order to bypass some static analysis
 

### Founding has the following features for Encryption and Obfuscation:

- Supports IPv4/IPv6/MAC/UUID Obfuscation

- Supports XOR/RC4/AES encryption

- Supports payload padding

- Randomly generated encryption keys on every run

### Founding has the following generators types to permit the usage of ```.bin```,```.exe``` and ```.dll```:

- **Raw**
  - Use of .bin payload

- **Donut**
  - Use of donut to create a .bin without amsi bypass

- **Clematis**
  - Use of clematis to create a .bin with garble obfuscation and compression

- **Powershell-donut**
  - Use PS2EXE to create a .exe and then use donut to create a .bin


### Founding has the following features for Executing the Shellcode:
- **APC**
  - Asynchronous Procedure Calls

- **Early-Bird-Debug**
  - Asynchronous Procedure Calls with a Remote Debug Process

- **Early-Bird-Debug**
  - Asynchronous Procedure Calls with a Remote Suspended Process

- **EnumThreadWindows**
  - Callback function EnumThreadWindows

- **Local-Mapping-Inject**
  - Local Mapping and Thread in Suspend State
  
- **Early-Cascade**
  - Early-cascade Hooking ntdll!SE_DllLoaded to execute the payload

- **Fibers**
  - Fibers executes by switching execution contexts without creating new threads

- **Process-Hypnosis**
  - Create child process in debug mode, detach debugger, and execute payload

- **Tp-Alloc**
  - Use Thread Pool API (TpAllocWait/TpSetWait) to queue shellcode execution

- **Local-Hollowing**
  - Duplicates thread to recreate and run the PE in suspended main thread

### Founding has the following optional features:

- **Indirect Syscalls**
  - Hells-Hall - Change all implementation to Indirect Syscalls (HellsHall) including optional flags
  - Syswhispers3 - Change all implementation to Indirect Syscalls (SysWhispers3) including optional flags

- **Compiler**
  - Clang-LLVM - Use clang-LLVM obfuscation to evade static analysis
 
- **Amsi**
  - Amsi-Opensession - Patch AmsiOpenSession to return invalid argument
  - Amsi-Scanbuffer - Patch AmsiScanBuffer to return invalid argument
  - Amsi-Signature - Patch AmsiSignature to return invalid string corrupting the signature value
  - Amsi-Codetrust - Patch WldpQueryDynamicCodeTrust to return invalid argument
 
- **Unhooking**
  - Unhooking-Createfile - Unhook all function from ntdll.dll mapped with CreateFileMappingA
  - Unhooking-Knowndlls -  Unhook all function from ntdll.dll from KnownDlls directory
  - Unhooking-Debug - Unhook all function from ntdll.dll copying the new NTDLL from a new debug process
  - Hookchain - Modifies the IAT to reroute function calls, allowing it to intercept and handle them 
 
- **ETW**
  - Etw-Eventwrite - Patch EtwEventWriteFull, EtwEventWrite and EtwEventWriteEx to blind EDR telemetry
  - Etw-Trace-Event - Patch NtTraceEvent to blind EDR telemetry
  - Etw-pEventWriteFull - Patch private function EtwpEventWriteFull to return invalid parameters to blind EDR telemetry
 
- **Sandbox Bypasses**
  - Api-Hammering - Creates a random file, reads/writes random data, delaying execution for 10 sec
  - Delay-Mwfmoex - Use MsgWaitForMultipleObjectsEx delaying execution for 10 sec
  - Fibonacci - Calculate Fibonacci delaying execution for 10 sec
  - Mouse-Clicks - Logs clicks for 20 seconds, if fewer than 1 click it assumes as sandboxed environment
  - Resolution - Checks resolution for sandbox environments
  - Processes - Checks if the system is running less than 50 processes it assumes as sandboxed environment
  - Hardware - Checks if the system is running less of 2 processors, 2 gb ram and 2 usbs mounted it assumes as sandboxed environment
 
- **Payload Control**
  - Check-Running - Check if the executable is already running, if it is, prevent duplicate execution
  - Self-Delete -  Ensure the payload deletes it self during execution, if deletion fails, deletes file content reducing its size to zero bytes
 
- **Miscellaneous**
  - Dll - Create a DLL with optional export function name (default: runme), this implementation runs rundll32 in background
  - Dll-Stealthy - Create a DLL with optional export function name (default: runme)
  - Service - Create a executable to be run as a service
  - Inflate - Inflate the executable with random portuguese words to increase his size
  - Sign - Sign the final executable with a certificate
  - No-Window - Run without opening a terminal window
  - No-Print - Run without printing any output, remove all printfs from implementation
  - Decoy - Embed a decoy file (e.g. PDF) to be executed alongside the payload

## Usage
### Generator Types
![GitHub Logo](/Founding/generators.png)

### Executions types and Optional flags
![GitHub Logo](/Founding/helper1.png)
![GitHub Logo](/Founding/helper2.png)

### Sintax

```bash
Founding.exe <Generator type> <File.bin/.exe/.dll> <Enc/Obf Option> <Execution type> <Optional flags>
```

### Example Command
```bash
Founding.exe donut mimikatz.exe mac fibers --hells-hall

[+] Running donut
[+] Do you want to include parameters? (Y/N): n

  [ Donut shellcode generator v1 (built Oct 23 2024 07:55:06)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : ".\mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP/ETW : none
  [ PE Headers    : overwrite
  [ Shellcode     : "output\code\Erwin.bin"
  [ Exit          : Thread

[+] Erwin.bin created using donut.
[+] Including EXEC (Fibers) functionality in compilation...
[+] Including INDIRECT SYSCALLS (Initialize Indirect Syscalls) functionality in compilation...
[+] Including INDIRECT SYSCALLS (Hells Hall Fibers) functionality in compilation...
[+] Compiling with GCC...
[+] Compilation successful.
[+] Shinzo wo Sasageyo! Erwin.exe Created.
```

### Notes
- Shellcodes that need an interactive shell like *mimikatz* can't be used with Remote Process techniques.
- Download the zip from releases
- The code from each compilation can be found on \output\code\
- To test newly crafted DLLs, a dedicated executable file, ```dlltest.exe```, has been prepared and can be located within the \founding\misc\dll_test directory.
- Within the \founding\dependencies\ directory, you will find the ```vs_BuildTools.exe``` file, accompanied by a Readme.txt document, both of which are essential for Clang-LLVM compiler.
  
## Demo
### Cobalt Strike Beacon on Falcon Crowd Strike
[![Meterpreter](https://i.imgur.com/hucwlKw.png)](https://youtu.be/YTB3MrO5PiE)

### PowerUp on Cortex Palo Alto
[![Mimikatz](https://i.imgur.com/aJz4aFI.png)](https://youtu.be/l__9zza21V8)
https://youtu.be/zrT6AcZFC1o?si=gkxY7Dj7cI8Lv2s5
## Credits
- Some techniques used learnt from [Maldev Academy](https://maldevacademy.com), it is an awesome course, highly recommend
- Inspired by [HellShell](https://github.com/NUL0x4C/HellShell)



