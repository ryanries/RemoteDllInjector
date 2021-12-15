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


BOOL FileExistsW(wchar_t* FileName)
{
	DWORD FileAttributes = GetFileAttributesW(FileName);

	return (FileAttributes != INVALID_FILE_ATTRIBUTES && !(FileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}


int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
	UNREFERENCED_PARAMETER(envp);

	wchar_t* UsageString = L"USAGE: RemoteDllInjector.exe <ProcessID> <PathToDLL>\n";

	wchar_t* DllPath = NULL;

	DWORD ProcessID = 0;

	HANDLE RemoteProcessHandle = INVALID_HANDLE_VALUE;

	HANDLE Kernel32ModuleHandle = INVALID_HANDLE_VALUE;

	void* LoadLibraryAddress = NULL;

	void* RemoteMemoryForDllName = NULL;

	if (argc != 3)
	{
		wprintf(L"%s", UsageString);

		return(0);
	}

	if ((ProcessID = _wtoi(argv[1])) == 0)
	{
		wprintf(L"Cannot convert ProcessID!\n");

		wprintf(L"%s", UsageString);

		return(0);
	}

	DllPath = argv[2];

	if (FileExistsW(DllPath) == FALSE)
	{
		wprintf(L"Cannot locate DLL!\n");

		wprintf(L"%s", UsageString);

		return(0);
	}

	RemoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

	if (RemoteProcessHandle)
	{
		// TODO: This is dumb to have this empty block. Fix this. I was doing this live on video, forgive me.
	}
	else
	{
		HANDLE CurrentProcessTokenHandle = NULL;

		LUID Luid = { 0 };

		TOKEN_PRIVILEGES TokenPrivileges = { 0 };

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentProcessTokenHandle) == 0)
		{
			wprintf(L"OpenProcessToken failed with error 0x%08lx!\n", GetLastError());

			return(0);
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
			wprintf(L"AdjustTokenPrivileges failed with error 0x%08lx!\n", GetLastError());

			return(0);
		}

		wprintf(L"Successfully enabled DEBUG privilege.\n");

		RemoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

		if (RemoteProcessHandle == NULL)
		{
			wprintf(L"OpenProcess failed with error 0x%08lx\n", GetLastError());

			return(0);
		}		
	}

	Kernel32ModuleHandle = GetModuleHandleW(L"kernel32.dll");

	if (Kernel32ModuleHandle == NULL)
	{
		wprintf(L"GetModuleHandleW failed with error 0x%08lx\n", GetLastError());

		return(0);
	}

	LoadLibraryAddress = (LPVOID)GetProcAddress(Kernel32ModuleHandle, "LoadLibraryW");

	if (LoadLibraryAddress == NULL)
	{
		wprintf(L"GetProcAddress failed with error 0x%08lx\n", GetLastError());

		return(0);
	}

	RemoteMemoryForDllName = VirtualAllocEx(
		RemoteProcessHandle,
		NULL,
		wcslen(DllPath) * sizeof(wchar_t),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	if (RemoteMemoryForDllName == NULL)
	{
		wprintf(L"VirtualAllocEx failed with error 0x%08lx\n", GetLastError());

		return(0);
	}

	if ((WriteProcessMemory(RemoteProcessHandle, RemoteMemoryForDllName, DllPath, wcslen(DllPath) * sizeof(wchar_t), NULL)) == 0)
	{
		wprintf(L"WriteProcessMemory failed with error 0x%08lx\n", GetLastError());

		return(0);
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
		wprintf(L"CreateRemoteThread failed with error 0x%08lx\n", GetLastError());

		return(0);
	}

	wprintf(L"Successfully injected DLL into process with PID %ld!\n", ProcessID);

	return(0);
}