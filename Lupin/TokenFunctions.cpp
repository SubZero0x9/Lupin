
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <stdio.h>
#include <wchar.h>
#include <sddl.h>
#include <tlhelp32.h>
#include "TokenFunctions.h"


#define INFO_BUFFER_SIZE 32767
#define MAX_NAME 256
#pragma comment(lib, "advapi32.lib")


BOOL EnableTokenPrivilege(LPTSTR LPrivilege)
{
	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	DWORD dwSize;

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, LPrivilege, &tp.Privileges[0].Luid))
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
	}
	else
	{
		_tprintf(L"Open Process Token Failed with Error Code: %d\n", GetLastError());
	}

	CloseHandle(hToken);

	return bResult;
}


BOOL CheckTokenPrivilege(LPTSTR LPrivilege)
{

	LUID luid = {};
	PRIVILEGE_SET PrivilegeSet;
	HANDLE hprocess = GetCurrentProcess();
	HANDLE hToken = {};
	BOOL privResult;

	if (!hprocess)
	{
		_tprintf(L"Cannot Open Process Handle. Failed with Error Code: %d\n", GetLastError());
	}

	if (!OpenProcessToken(hprocess, TOKEN_QUERY, &hToken))
	{
		_tprintf(L"Cannot Open Process Token. Failed with Error Code: %d\n", GetLastError());
	}

	if (!LookupPrivilegeValueW(NULL, LPrivilege, &luid))
	{
		_tprintf(L"Cannot Lookup Privilege Value: %d\n", GetLastError());
	}

	PrivilegeSet.PrivilegeCount = 1;
	PrivilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	PrivilegeSet.Privilege[0].Luid = luid;
	PrivilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	PrivilegeCheck(hToken, &PrivilegeSet, &privResult);


	return privResult;

}

BOOL CheckTokenPrivilegeRemoteProcess(LPTSTR LPrivilege, HANDLE hProcess)
{


	LUID luid = {};
	PRIVILEGE_SET PrivilegeSet;
	HANDLE hToken = {};
	BOOL privResult;

	if (!hProcess)
	{
		_tprintf(L"Cannot Open Process Handle. Failed with Error Code: %d\n", GetLastError());
	}

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		_tprintf(L"Cannot Open Process Token. Failed with Error Code: %d\n", GetLastError());
	}

	if (!LookupPrivilegeValueW(NULL, LPrivilege, &luid))
	{
		_tprintf(L"Cannot Lookup Privilege Value: %d\n", GetLastError());
	}

	PrivilegeSet.PrivilegeCount = 1;
	PrivilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	PrivilegeSet.Privilege[0].Luid = luid;
	PrivilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	PrivilegeCheck(hToken, &PrivilegeSet, &privResult);
	
	return privResult;

}


BOOL EnableTokenPrivilegeRemoteProcess(LPTSTR LPrivilege, HANDLE hProcess)
{
	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	DWORD dwSize;

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;

	if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, LPrivilege, &tp.Privileges[0].Luid))
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
	}
	else
	{
		_tprintf(L"Open Process Token Failed with Error Code: %d\n", GetLastError());
	}

	_tprintf(L"[-]Adjusted Token Attribute State: %d\n", tp.Privileges[0].Attributes);
	CloseHandle(hToken);

	return bResult;

}

BOOL PrimaryTokenElevation(HANDLE hProcess, LPCWSTR Application)
{

	HANDLE hToken = NULL;
	HANDLE NewToken = NULL;
	BOOL DuplicateTokenResult = FALSE;
	//| TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE TOKEN_IMPERSONATE 
	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
	{
		_tprintf(L"Cannot Open Process Token. Failed with Error Code:%d\n", GetLastError());
	}

	SECURITY_IMPERSONATION_LEVEL Sec_Imp_Level = SecurityImpersonation;
	TOKEN_TYPE token_type = TokenPrimary;
	DuplicateTokenResult = DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, Sec_Imp_Level, token_type, &NewToken);

	if (!DuplicateTokenResult)
	{
		_tprintf(L"Duplicate Token Failed with Error Code: %d\n", GetLastError());
	}

	STARTUPINFO startup_info = {};
	PROCESS_INFORMATION process_info = {};
	BOOL CreateProcTokenRes = FALSE;

	CreateProcTokenRes = CreateProcessWithTokenW(NewToken, 0, Application, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &startup_info, &process_info);

	if (!CreateProcTokenRes)
	{
		_tprintf(L"Cannot Create Process With Token. Failed with Error Code: %d\n", GetLastError());

		if (!CreateProcessAsUserW(NewToken, Application, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startup_info, &process_info))
		{
			_tprintf(L"Cannot Create Process As User. Failed with Error Code: %d\n", GetLastError());
		}
	}
	   	 
	return CreateProcTokenRes;

}

BOOL ImpersonationTokenElevation(HANDLE hProcess)
{

	HANDLE hToken = NULL;
	HANDLE NewToken = NULL;
	BOOL DuplicateTokenResult = FALSE;
	TCHAR  infoBuf[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &hToken))
	{
		_tprintf(L"Cannot Open Process Token. Failed with Error Code:%d\n", GetLastError());
	}

	SECURITY_IMPERSONATION_LEVEL Sec_Imp_Level = SecurityImpersonation;
	TOKEN_TYPE token_type = TokenImpersonation;

	DuplicateTokenResult = DuplicateToken(hToken, Sec_Imp_Level, &NewToken);

	if (!DuplicateTokenResult)
	{
		_tprintf(L"Duplicate Token Failed with Error Code: %d\n", GetLastError());
	}

	BOOL SetThreadRes = FALSE;
	//Here you can add your code which you want to execute from a different user's context
	//SetThreadRes = SetThreadToken(NULL, NewToken);
	SetThreadRes = ImpersonateLoggedOnUser(NewToken);

	bufCharCount = INFO_BUFFER_SIZE;
	if (!GetUserName(infoBuf, &bufCharCount))
	{
		_tprintf(L"GetUserName Failed With Error Code: %d\n", GetLastError());
	}
	_tprintf(TEXT("[-]Process Elevated With the User Privileges of User : %s\n"), infoBuf);


	return SetThreadRes;
}

BOOL TokenInfo(HANDLE hProcess)
{

	DWORD i, dwSize = 0, dwResult = 0;
	HANDLE hToken;
	PTOKEN_GROUPS pGroupInfo;
	SID_NAME_USE SidType;
	wchar_t lpName[MAX_NAME];
	wchar_t lpDomain[MAX_NAME];
	PSID pSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;



	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken Error %u\n", GetLastError());
		return FALSE;
	}



	if (!GetTokenInformation(hToken, TokenGroups, NULL, dwSize, &dwSize))
	{
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printf("GetTokenInformation Error %u\n", dwResult);
			return FALSE;
		}
	}


	//The Following code is taken from Microsoft Docs

	pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);



	if (!GetTokenInformation(hToken, TokenGroups, pGroupInfo,
		dwSize, &dwSize))
	{
		printf("GetTokenInformation Error %u\n", GetLastError());
		return FALSE;
	}



	if (!AllocateAndInitializeSid(&SIDAuth, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pSID))
	{
		printf("AllocateAndInitializeSid Error %u\n", GetLastError());
		return FALSE;
	}




	for (i = 0; i < pGroupInfo->GroupCount; i++)
	{
		if (EqualSid(pSID, pGroupInfo->Groups[i].Sid))
		{
					   
			dwSize = MAX_NAME;
			if (!LookupAccountSid(NULL, pGroupInfo->Groups[i].Sid,
				lpName, &dwSize, lpDomain,
				&dwSize, &SidType))
			{
				dwResult = GetLastError();
				if (dwResult == ERROR_NONE_MAPPED)
					printf("NONE MAPPED\n");
				//wcscpy_s(lpName, dwSize, "NONE_MAPPED");
				else
				{
					printf("LookupAccountSid Error %u\n", GetLastError());
					return FALSE;
				}
			}
			printf("Current user is a member of the %ws\\%ws group\n",
				lpDomain, lpName);


			if (pGroupInfo->Groups[i].Attributes & SE_GROUP_ENABLED)
				printf("The group SID is enabled.\n");
			else if (pGroupInfo->Groups[i].Attributes &
				SE_GROUP_USE_FOR_DENY_ONLY)
				printf("The group SID is a deny-only SID.\n");
			else
				printf("The group SID is not enabled.\n");
		}
	}

	if (pSID)
		FreeSid(pSID);
	if (pGroupInfo)
		GlobalFree(pGroupInfo);
	return TRUE;
}

BOOL ListPrivileges(HANDLE hProcess)
{
	HANDLE hToken = NULL;
	BOOL LpResult = FALSE;

	PTOKEN_GROUPS_AND_PRIVILEGES tGrpPriv = NULL;
	if (hProcess == NULL)
	{
		_tprintf(L"Cannot Open Process. Failed with Error Code: %d\n", GetLastError());
		return LpResult;
	}
	else
	{
		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		{
			_tprintf(L"Cannot Open Process Token. Failed with Error Code: %d\n", GetLastError());
			return LpResult;
		}

	}

	DWORD dwSize = 0;


	GetTokenInformation(hToken, TokenGroupsAndPrivileges, NULL, 0, &dwSize);


	tGrpPriv = (PTOKEN_GROUPS_AND_PRIVILEGES)GlobalAlloc(GPTR, dwSize);

	if (!GetTokenInformation(hToken, TokenGroupsAndPrivileges, tGrpPriv, dwSize, &dwSize))
	{
		_tprintf(L"GetTokenInformation Failed with Error Code: %d\n", GetLastError());
		return LpResult;
	}

	_tprintf(L"Privileges Enumerated for the given Token: %d\n", tGrpPriv->PrivilegeCount);

	DWORD i = 0;

	//LUID luid = tGrpPriv->Privileges[i].Luid;

	_tprintf(L"Privilege Name\t\t\t\t Enabled\t\n");

	for (i = 0; i < tGrpPriv->PrivilegeCount; i++)
	{
		DWORD cchname = 0;
		TCHAR lpname[INFO_BUFFER_SIZE];
		LUID luid = tGrpPriv->Privileges[i].Luid;


		if (!LookupPrivilegeName(NULL, &luid, NULL, &cchname))
		{


		}
		cchname = sizeof(lpname) + 1;


		if (!LookupPrivilegeName(NULL, &luid, lpname, &cchname))
		{
			_tprintf(L"Lookup Privilege Name 2 Failed with Error Code: %d\n", GetLastError());
		}

		PRIVILEGE_SET privSet;
		privSet.PrivilegeCount = 1;
		privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
		privSet.Privilege->Attributes = tGrpPriv->Privileges[i].Attributes;
		privSet.Privilege->Luid = tGrpPriv->Privileges[i].Luid;
		BOOL result = FALSE;
		if (!PrivilegeCheck(hToken, &privSet, &result))
		{
			_tprintf(L"Privilege Check failed with Error Code: %d", GetLastError());
		}
		_tprintf(L"%s\t\t\t%d\n", lpname, result);
		LpResult = TRUE;

	}


	GlobalFree(tGrpPriv);
	return LpResult;

}

BOOL ListTokenStatistics(HANDLE hProcess)
{
	HANDLE hToken;
	PTOKEN_STATISTICS token_statistics = NULL;
	PTOKEN_USER token_user = NULL;
	DWORD dwSize = 0;
	DWORD dwSidSize = 0;
	LUID tokenID, authenticationID;
	TOKEN_TYPE tokenType;
	SECURITY_IMPERSONATION_LEVEL sec_imp_level;
	DWORD PrivilegeCount;
	BOOL result = FALSE;
	BOOL Sidresult = FALSE;


	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		_tprintf(L"Cannot Open Process Token. Failed with Error Code:%d\n", GetLastError());
	}

	GetTokenInformation(hToken, TokenStatistics, NULL, 0, &dwSize);
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSidSize);

	token_statistics = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, dwSize);
	token_user = (PTOKEN_USER)GlobalAlloc(GPTR, dwSidSize);

	result = GetTokenInformation(hToken, TokenStatistics, token_statistics, dwSize, &dwSize);
	if (!result)
	{
		_tprintf(L"Get Token Stats Information Failed with Error Code: %d\n", GetLastError());
		return result;

	}

	Sidresult = GetTokenInformation(hToken, TokenUser, token_user, dwSidSize, &dwSidSize);
	if (!Sidresult)
	{
		_tprintf(L"Get Token User Information Failed with Error Code: %d\n", GetLastError());
		return result;

	}

	if (result == TRUE)
	{
		tokenID = token_statistics->TokenId;
		authenticationID = token_statistics->AuthenticationId;
		tokenType = token_statistics->TokenType;
		sec_imp_level = token_statistics->ImpersonationLevel;
		PrivilegeCount = token_statistics->PrivilegeCount;


		_tprintf(L"[-]Token ID : %d\n", tokenID);
		_tprintf(L"[-]Authentication ID : %d\n", authenticationID);
		_tprintf(L"[-]Token Type: %d\n", tokenType);
		_tprintf(L"[-]Impersonation Level : %d\n", sec_imp_level);
		_tprintf(L"[-]Privilege Count : %d\n", PrivilegeCount);

	}


	GlobalFree(token_statistics);
	GlobalFree(token_user);
	return result;

}

VOID FindSystemProc()
{

	HANDLE hToken = NULL;
	TOKEN_USER* token_user = NULL;
	DWORD dwSize;
	CHAR pUsername[300], pdomainName[300], tubuf[300];
	BOOL result = FALSE;
	SID_NAME_USE pSid;
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD PidArray[200] = { 0 };
	DWORD i;
	LPTSTR SeDebugPrivilege = (wchar_t*)SE_DEBUG_NAME;


	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		_tprintf(L"CreateToolhelp32Snapshot Failed with Error Code:%d", GetLastError());

	}
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		_tprintf(L"Process32First Failed with Error Code:%d", GetLastError());
		CloseHandle(hProcessSnap);

	}

	i = 0;
	do
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);

		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		{
			_tprintf(L"Process :%d is a Protected Process\n", pe32.th32ProcessID);
			result = FALSE;
		}
		else
		{
			result = TRUE;
		}

		token_user = (TOKEN_USER*)tubuf;
		if (GetTokenInformation(hToken, TokenUser, token_user, 300, &dwSize))
		{
			dwSize = 300;
			if (LookupAccountSidA(0, token_user->User.Sid, pUsername, &dwSize, pdomainName, &dwSize, &pSid))
			{
				if (pUsername != NULL)
				{
					result = TRUE;

				}
			}
			CHAR comparestring[] = "SYSTEM";

			if ((_strcmpi(pUsername, comparestring) == 0) && (result = TRUE))
			{
				_tprintf(L"[-]Process: %d is a SYSTEM process\n", pe32.th32ProcessID);

			}
			
		}
			   
	} while (Process32Next(hProcessSnap, &pe32));
	DWORD pArraysize = sizeof(i);

}