#include <Windows.h>
#include <wchar.h>


BOOL EnableTokenPrivilege(LPTSTR LPrivilege);
BOOL CheckTokenPrivilege(LPTSTR LPrivilege);
BOOL CheckTokenPrivilegeRemoteProcess(LPTSTR LPrivilege, HANDLE hProcess);
BOOL EnableTokenPrivilegeRemoteProcess(LPTSTR LPrivilege, HANDLE hProcess);
BOOL PrimaryTokenElevation(HANDLE hProcess, LPCWSTR Application);
BOOL ImpersonationTokenElevation(HANDLE hProcess);
BOOL TokenInfo(HANDLE hProcess);
BOOL ListPrivileges(HANDLE hProcess);
BOOL ListTokenStatistics(HANDLE hProcess);
VOID FindSystemProc();



