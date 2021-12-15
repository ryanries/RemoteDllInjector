// Joseph Ryan Ries, 2021
// DARK MODE!
// The show where we do sketchy stuff with the Windows API!
// Youtube: https://www.youtube.com/playlist?list=PLlaINRtydtNUwkwdmCBNtkwgVRda8Ya_G
// Github: https://github.com/ryanries/RemoteDllInjector

// Temporarily disable warnings originating from windows.h, over which we have no control.
#pragma warning(push, 0)

#pragma warning(disable: 4668)

#include <Windows.h>

// Restore warning level to /Wall
#pragma warning(pop)

#include <stdio.h>

// Usage: RemoteDllInjector.exe <ProcessID> <PathToDLL>
// This program writes the DLL name, e.g. "C:\temp\mydll.dll", into the memory of the remote
// process of your choosing. It then creates a new thread in that remote process, with the start
// address of the new thread being LoadLibraryW, and the argument being the DLL to load. This
// causes the remote process to load the arbitrary DLL, which will automatically execute DllMain
// of the newly-loaded module.


// Returns TRUE if the given file exists. Returns FALSE if the file does not exist or is a directory.
BOOL FileExistsW(wchar_t* FileName)
{
	DWORD FileAttributes = GetFileAttributesW(FileName);

	return (FileAttributes != INVALID_FILE_ATTRIBUTES && !(FileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}


int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
	UNREFERENCED_PARAMETER(envp);

	DWORD ReturnCode = ERROR_SUCCESS;

	wchar_t* UsageString = L"USAGE: RemoteDllInjector.exe <ProcessID> <PathToDLL>\n";

	// The path to the DLL we want to inject. Must actually exist as a file on disk.
	wchar_t* DllPath = NULL;

	// The process ID (pid) of the process we want to inject into.
	DWORD ProcessID = 0;

	HANDLE RemoteProcessHandle = INVALID_HANDLE_VALUE;

	HANDLE Kernel32ModuleHandle = INVALID_HANDLE_VALUE;

	void* LoadLibraryAddress = NULL;

	void* RemoteMemoryForDllName = NULL;

	if (argc != 3)
	{
		ReturnCode = ERROR_INVALID_PARAMETER;

		wprintf(L"%s", UsageString);

		goto Exit;
	}

	if ((ProcessID = _wtoi(argv[1])) == 0)
	{
		ReturnCode = ERROR_INVALID_PARAMETER;

		wprintf(L"[-] Cannot convert ProcessID!\n");

		wprintf(L"%s", UsageString);

		goto Exit;
	}

	DllPath = argv[2];

	if (FileExistsW(DllPath) == FALSE)
	{
		ReturnCode = ERROR_FILE_NOT_FOUND;

		wprintf(L"[-] Cannot locate DLL!\n");

		wprintf(L"%s", UsageString);

		goto Exit;
	}

	RemoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

	if (RemoteProcessHandle == NULL)
	{
		// If OpenProcess failed with access denied, we can try again after enabling debug
		// privilege. If it failed for some other reason, we need to bail.
		if (GetLastError() != ERROR_ACCESS_DENIED)
		{
			ReturnCode = GetLastError();

			wprintf(L"[-] OpenProcess failed with 0x%08lx!\n", ReturnCode);

			goto Exit;
		}

		HANDLE CurrentProcessTokenHandle = NULL;

		LUID Luid = { 0 };

		TOKEN_PRIVILEGES TokenPrivileges = { 0 };

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentProcessTokenHandle) == 0)
		{
			ReturnCode = GetLastError();

			wprintf(L"[-] OpenProcessToken failed with error 0x%08lx!\n", ReturnCode);

			goto Exit;
		}		

		LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid);

		TokenPrivileges.PrivilegeCount = 1;

		TokenPrivileges.Privileges[0].Luid = Luid;

		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (AdjustTokenPrivileges(
			CurrentProcessTokenHandle,
			FALSE,
			&TokenPrivileges,
			0,
			(PTOKEN_PRIVILEGES)NULL,
			(PDWORD)NULL) == 0)
		{
			ReturnCode = GetLastError();

			wprintf(L"[-] AdjustTokenPrivileges failed with error 0x%08lx!\n", ReturnCode);

			goto Exit;
		}

		wprintf(L"[+] Successfully enabled DEBUG privilege.\n");

		RemoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

		if (RemoteProcessHandle == NULL)
		{
			ReturnCode = GetLastError();

			wprintf(L"[-] OpenProcess failed with error 0x%08lx\n", ReturnCode);

			goto Exit;
		}		
	}

	Kernel32ModuleHandle = GetModuleHandleW(L"kernel32.dll");

	if (Kernel32ModuleHandle == NULL)
	{
		ReturnCode = GetLastError();

		wprintf(L"[-] GetModuleHandleW failed with error 0x%08lx\n", ReturnCode);

		goto Exit;
	}

	LoadLibraryAddress = (LPVOID)GetProcAddress(Kernel32ModuleHandle, "LoadLibraryW");

	if (LoadLibraryAddress == NULL)
	{
		ReturnCode = GetLastError();

		wprintf(L"[-] GetProcAddress failed with error 0x%08lx\n", ReturnCode);

		goto Exit;
	}

	RemoteMemoryForDllName = VirtualAllocEx(
		RemoteProcessHandle,
		NULL,
		wcslen(DllPath) * sizeof(wchar_t),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	if (RemoteMemoryForDllName == NULL)
	{
		ReturnCode = GetLastError();

		wprintf(L"[-] VirtualAllocEx failed with error 0x%08lx\n", ReturnCode);

		goto Exit;
	}

	wprintf(L"[+] Allocated memory in remote process.\n");

	if ((WriteProcessMemory(RemoteProcessHandle, RemoteMemoryForDllName, DllPath, wcslen(DllPath) * sizeof(wchar_t), NULL)) == 0)
	{
		ReturnCode = GetLastError();

		wprintf(L"[-] WriteProcessMemory failed with error 0x%08lx\n", ReturnCode);

		goto Exit;
	}

	if (CreateRemoteThread(
		RemoteProcessHandle,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)LoadLibraryAddress,
		RemoteMemoryForDllName,
		0,
		NULL) == NULL)
	{
		ReturnCode = GetLastError();

		wprintf(L"[-] CreateRemoteThread failed with error 0x%08lx\n", ReturnCode);

		goto Exit;
	}

	wprintf(L"[+] Successfully injected DLL into process with PID %ld!\n", ProcessID);

Exit:

	return(ReturnCode);
}