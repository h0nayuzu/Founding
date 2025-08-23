#pragma once


#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H




// to help identifying user input
#define UUIDFUSCATION		0x444
#define AESENCRYPTION		0x555
#define RC4ENCRYPTION		0x666
#define IPV6FUSCATION		0x111
#define IPV4FUSCATION		0x222
#define MACFUSCATION		0x333
#define XORENCRYPTION		0x777


//// to help identifying user input INJECTION

#define CREATETHREAD			0x888
#define PROCESS_INJECTION		0x999
#define FUNCTIONPOINTER			0x1000
#define APC						0x1100
#define EB_APC_DP				0x1200
#define EB_APC_SP				0x1300
#define CALLBACK_ENUM			0x1400
#define LOCAL_MAPPING			0x1500




// to help working with encryption algorithms
#define RC4KEYSIZE				16

#define AESKEYSIZE				32
#define AESIVSIZE				16

#define XORKEYSIZE				16

//----------------------------------------------------------
//------------


//-------------------------------------------------------------------------------------------------------------------------------
// 
// from IO.c
// 
// exec
void RemoveObjFilesInOutputFolder_pch();
void RemoveObjFilesInOutputFolder_obj();
// 
void Headers(const char* header);

//
BOOL ppl_rtcore(int argc, char* argv[]);


// read file from disk 
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData);
BOOL ReadPayloadFile2(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData);
// write file to disk
BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData);

void compile_gcc(const char* extra_arg);
void compile_llvm(const char* extra_arg);

BOOL CheckAndRemoveFlag(int* argc, char* argv[], const char* flag);

void getfilecontentcomment(const char* content, const char* destination, const char* comment);

BOOL ValidateOptionalFlags(int argc, char* argv[]);
BOOL IsValidOptionalFlag(const char* flag);

void donut(int argc, char* argv[]);

void clematis(int argc, char* argv[]);

BOOL EndsWith(const char* str, const char* suffix);

void watermark(int argc, char* argv[]);
void addResources(int argc, char* argv[]);
void inflate(int argc, char* argv[], int inflations);

void sign(const char* pfxFile, const char* password);


void ReadAndPrintFile(const char* filename);

BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize);

void removePrintfStatements();

void copyFileFromFolder_misc(const char* folderName, const char* filename);
void completeDecoyEmbedding();
void embedDecoy(const char* decoyFile);
BOOL powershell_clematis(int argc, char* argv[]);
BOOL powershell_donut(int argc, char* argv[]);

long get_file_size(FILE* file);


//create files and copy files

void createfile_outputfolder(const char* filename);

void createfile_enc_header();

void copyFileContents_executionFolder(const char* folderName, const char* filenameBase);

void copyFileContents_miscFolder(const char* folderName, const char* filenameBase);

void copyFileContents_evasionFolder(const char* folderName, const char* filenameBase);

void copyFileContents_enc_header(const char* filenameBase);

void copyFileExecutionFromFolder(const char* folderName, const char* filename);

void copyFileContents_executionFolder_filename(const char* folderName, const char* filenameBase);

void copyFileFromFolder(const char* folderName, const char* filename);

char* CheckAndRemoveFlagWithValue(int* argc, char* argv[], const char* flag);

//create files and copy files done

void RemoveAllFilesInOutputFolder();

PBYTE	pPayloadInput;
PVOID	pCipherText;
PBYTE	pAppendedPayload;


int FreeAllocatedMemory();
//-------------------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------------------

//XOR
BOOL XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize);
//-------------------------------------------------------------------------------------------------------------------------------


//-------------------------------------------------------------------------------------------------------------------------------
// 
// from StringFunctions.c
// print the decryption / deobfuscation function (as a string) to the screen
VOID PrintDecodeFunctionality(IN INT TYPE);

VOID PrintInjectionFunctionality(IN INT TYPE);

//-------------------------------------------------------------------------------------------------------------------------------

//Write to a file
void RedirectStdoutToFile(const char* filename);
//
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize);

//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// generate random bytes of size "sSize"
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
// print the input buffer as a hex char array (c syntax)
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
//-------------------------------------------------------------------------------------------------------------------------------

//Print Help
INT PrintHelp(IN CHAR* _Argv0);

INT PrintHelp2(IN CHAR* _Argv0);


//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// wrapper function for InstallAesEncryption that make things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);
// do the rc4 encryption
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Obfuscation.c
// generate the UUid output representation of the shellcode
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the Mac output representation of the shellcode
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv6 output representation of the shellcode
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv4 output representation of the shellcode
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
//-------------------------------------------------------------------------------------------------------------------------------

//color

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"


void printWithColor(const char* message, WORD color);

void RemoveAllFilesInErwinFolder();

#endif // !COMMON_H
