# Founding 🛠️
![GitHub Logo](/Founding/eren1.png)

## Overview 📖
**Founding** is a powerful tool that processes shellcode in `.bin`, `.exe`, or `.dll` formats, applying advanced **obfuscation** or **encryption** techniques to generate stealthy binaries with sophisticated execution methods. 

## Features ✨
### Core Features (Applied in Every Compilation)

- **Dynamic API Hashing**   
  Generates unique hash values for API functions at runtime to evade detection.
- **IAT Camouflage**   
  Invokes select Windows API functions to enhance binary legitimacy.
- **Minimal CRT**   
  Removes the CRT Library for precise control over the Import Address Table.
- **Watermark**   
  Embeds custom watermarks in DOS Stub, Checksum, PE Section, or file overlay.
- **Resource File**   
  Embeds file properties resembling `cleanmgr.exe` for authenticity.
- **Preamble 0xFC 0x48**   
  Prepends `xFCx48` to shellcode to bypass static analysis.
 
### Encryption and Obfuscation

- Supports **IPv4/IPv6/MAC/UUID** obfuscation.
- Offers **XOR**, **RC4**, and **AES** encryption.
- Includes **payload padding** for extra obfuscation.
- Generates **random encryption keys** per run.

### Generators Types

- **Raw**   
  Directly processes `.bin` payloads.
- **Donut**  
  Uses Donut to create `.bin` without AMSI bypass.
- **Clematis**   
  Employs Clematis for `.bin` with garble obfuscation and compression.
- **Powershell-donut**   
  Converts `.exe` to `.bin` using PS2EXE and Donut.


### Execution types
- **APC**   
  Executes via Asynchronous Procedure Calls.
- **Early-Bird-Debug**   
  Uses APC with a remote debug or suspended process.
- **EnumThreadWindows**  
  Leverages the EnumThreadWindows callback function.
- **Local-Mapping-Inject**   
  Performs local mapping with a suspended thread.
- **Early-Cascade**   
  Hooks `ntdll!SE_DllLoaded` for payload execution.
- **Fibers**   
  Switches execution contexts without new threads.
- **Process-Hypnosis**   
  Runs payload in a debugged child process, then detaches.
- **Tp-Alloc**   
  Queues shellcode using Thread Pool API (`TpAllocWait`/`TpSetWait`).
- **Local-Hollowing**   
  Duplicates and runs PE in a suspended main thread.

### Optional features

#### Indirect Syscalls 
- **Hells-Hall**
  Change all implementation to Indirect Syscalls (HellsHall) including optional flags.
- **Syswhispers3**
  Change all implementation to Indirect Syscalls (SysWhispers3) including optional flags.

#### Compiler 
- **Clang-LLVM**  
  Use Clang-LLVM obfuscation to evade static analysis.

#### AMSI Bypasses 
- **Amsi-Opensession** 
  Patch `AmsiOpenSession` to return invalid argument.
- **Amsi-Scanbuffer** 
  Patch `AmsiScanBuffer` to return invalid argument.
- **Amsi-Signature** 
  Patch `AmsiSignature` to return invalid string corrupting the signature value.
- **Amsi-Codetrust** 
  Patch `WldpQueryDynamicCodeTrust` to return invalid argument.

#### Unhooking 
- **Unhooking-Createfile**   
  Unhook all functions from `ntdll.dll` mapped with `CreateFileMappingA`.
- **Unhooking-Knowndlls**   
  Unhook all functions from `ntdll.dll` from KnownDlls directory.
- **Unhooking-Debug** 
  Unhook all functions from `ntdll.dll` copying the new NTDLL from a new debug process.
- **Hookchain** 
  Modifies the IAT to reroute function calls, allowing it to intercept and handle them.

#### ETW Bypasses 
- **Etw-Eventwrite** 
  Patch `EtwEventWriteFull`, `EtwEventWrite`, and `EtwEventWriteEx` to blind EDR telemetry.
- **Etw-Trace-Event** 
  Patch `NtTraceEvent` to blind EDR telemetry.
- **Etw-pEventWriteFull** 
  Patch private function `EtwpEventWriteFull` to return invalid parameters to blind EDR telemetry.

#### Sandbox Bypasses 
- **Api-Hammering**
  Creates a random file, reads/writes random data, delaying execution for 10 sec.
- **Delay-Mwfmoex** 
  Use `MsgWaitForMultipleObjectsEx` delaying execution for 10 sec.
- **Fibonacci** 
  Calculate Fibonacci delaying execution for 10 sec.
- **Mouse-Clicks** 
  Logs clicks for 20 seconds; if fewer than 1 click, assumes sandboxed environment.
- **Resolution** 
  Checks resolution for sandbox environments.
- **Processes**  
  Checks if the system is running less than 50 processes; assumes sandboxed environment.
- **Hardware**  
  Checks if the system has less than 2 processors, 2 GB RAM, and 2 USBs mounted; assumes sandboxed environment.

#### Payload Control 
- **Check-Running**   
  Check if the executable is already running; if so, prevent duplicate execution.
- **Self-Delete**   
  Ensure the payload deletes itself during execution; if deletion fails, deletes file content reducing its size to zero bytes.

#### Miscellaneous 
- **Dll**   
  Create a DLL with optional export function name (default: `runme`), runs `rundll32` in background.
- **Dll-Stealthy**   
  Create a stealthier DLL with optional export function name (default: `runme`).
- **Service**   
  Create an executable to be run as a service.
- **Inflate**  
  Inflate the executable with random Portuguese words to increase its size.
- **Sign**   
  Sign the final executable with a certificate.
- **No-Window**   
  Run without opening a terminal window.
- **No-Print**   
  Run without printing any output, remove all `printf`s from implementation.
- **Decoy**  
  Embed a decoy file (e.g., PDF) to be executed alongside the payload.

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
[![Cobalt](https://i.imgur.com/ilgUtBA.png)](https://youtu.be/YTB3MrO5PiE)

### PowerUp on Cortex Palo Alto
[![Cortex](https://i.imgur.com/aJz4aFI.png)](https://youtu.be/zrT6AcZFC1o?si=gkxY7Dj7cI8Lv2s5)

## Credits
- Some techniques used learnt from [Maldev Academy](https://maldevacademy.com), it is an awesome course, highly recommend
- Inspired by [HellShell](https://github.com/NUL0x4C/HellShell)
- A special thanks to the researchers and developers whose work has inspired, contributed to, and made this tool possible. All credit goes to the original authors of the techniques and tools:
  - [Clematis](https://github.com/CBLabresearch/Clematis)
  - [Donut](https://github.com/TheWover/donut)
  - [PS2EXE](https://github.com/MScholtes/PS2EXE)
