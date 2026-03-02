#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include "beacon.h"

DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetUserNameExA(EXTENDED_NAME_FORMAT, LPSTR, PULONG);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountNameA(LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeDisplayNameA(LPCSTR, LPCSTR, LPSTR, LPDWORD, LPDWORD);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT void* MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void  MSVCRT$free(void*);
DECLSPEC_IMPORT char* MSVCRT$strncat(char*, const char*, size_t);

const char* getSidTypeStr(SID_NAME_USE snu) {
    switch (snu) {
        case SidTypeUser:           return "User";
        case SidTypeGroup:          return "Group";
        case SidTypeDomain:         return "Domain";
        case SidTypeAlias:          return "Alias";
        case SidTypeWellKnownGroup: return "Well-known group";
        case SidTypeDeletedAccount: return "Deleted account";
        case SidTypeInvalid:        return "Invalid";
        case SidTypeUnknown:        return "Unknown";
        case SidTypeComputer:       return "Computer";
        case SidTypeLabel:          return "Label";
        default:                    return "Unknown";
    }
}

void getGroupAttribs(DWORD attrs, char* buf, int bufSize) {
    buf[0] = '\0';
    if (attrs & SE_GROUP_MANDATORY)          { MSVCRT$strncat(buf, "Mandatory group, ", bufSize - 1); }
    if (attrs & SE_GROUP_ENABLED_BY_DEFAULT) { MSVCRT$strncat(buf, "Enabled by default, ", bufSize - 1); }
    if (attrs & SE_GROUP_ENABLED)            { MSVCRT$strncat(buf, "Enabled group, ", bufSize - 1); }
    if (attrs & SE_GROUP_OWNER)              { MSVCRT$strncat(buf, "Group owner, ", bufSize - 1); }
}



void go(char* args, int len) {
    formatp buffer;
    BeaconFormatAlloc(&buffer, 32 * 1024);

    char nameBuffer[512];
    ULONG nameSize = sizeof(nameBuffer);

    if (!SECUR32$GetUserNameExA(NameSamCompatible, nameBuffer, &nameSize)) {
        BeaconPrintf(CALLBACK_ERROR, "GetUserNameExA failed");
        BeaconFormatFree(&buffer);
        return;
    }

    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sid);
    char referencedDomain[256];
    DWORD refDomainSize = sizeof(referencedDomain);
    SID_NAME_USE snu;

    if (!ADVAPI32$LookupAccountNameA(NULL, nameBuffer, sid, &sidSize, referencedDomain, &refDomainSize, &snu)) {
        BeaconPrintf(CALLBACK_ERROR, "LookupAccountNameA failed");
        BeaconFormatFree(&buffer);
        return;
    }

    LPSTR sidString = NULL;
    if (!ADVAPI32$ConvertSidToStringSidA((PSID)sid, &sidString)) {
        BeaconPrintf(CALLBACK_ERROR, "ConvertSidToStringSidA failed");
        BeaconFormatFree(&buffer);
        return;
    }

    /* User info section */
    BeaconFormatPrintf(&buffer, "\nUserName\t\tSID\n");
    BeaconFormatPrintf(&buffer, "====================== ====================================\n");
    BeaconFormatPrintf(&buffer, "%s\t%s\n", nameBuffer, sidString);
    KERNEL32$LocalFree(sidString);

    /* Group info section */
    HANDLE hToken;
    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwSize = 0;
        ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
        PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)MSVCRT$malloc(dwSize);

        if (pGroups && ADVAPI32$GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize)) {
            BeaconFormatPrintf(&buffer, "\n\nGROUP INFORMATION                                 Type                     SID                                          Attributes               \n");
            BeaconFormatPrintf(&buffer, "================================================= ===================== ============================================= ==================================================\n");

            for (DWORD i = 0; i < pGroups->GroupCount; i++) {
                char gName[256], gDom[256];
                DWORD gNameLen = 256, gDomLen = 256;
                SID_NAME_USE gSnu;
                LPSTR gSidStr = NULL;
                char fullName[512];
                char attribs[512];

                if (ADVAPI32$LookupAccountSidA(NULL, pGroups->Groups[i].Sid, gName, &gNameLen, gDom, &gDomLen, &gSnu)) {
                    ADVAPI32$ConvertSidToStringSidA(pGroups->Groups[i].Sid, &gSidStr);

                    /* Build full name */
                    fullName[0] = '\0';
                    if (gDom[0] != '\0') {
                        MSVCRT$strncat(fullName, gDom, sizeof(fullName) - 1);
                        MSVCRT$strncat(fullName, "\\", sizeof(fullName) - 1);
                    }
                    MSVCRT$strncat(fullName, gName, sizeof(fullName) - 1);


                    getGroupAttribs(pGroups->Groups[i].Attributes, attribs, sizeof(attribs));

                    BeaconFormatPrintf(&buffer, "%-50s%-22s %-45s %s\n",
                        fullName,
                        getSidTypeStr(gSnu),
                        gSidStr ? gSidStr : "",
                        attribs);

                    if (gSidStr) KERNEL32$LocalFree(gSidStr);
                }
            }
        }
        if (pGroups) MSVCRT$free(pGroups);

        /* Privileges section */
        DWORD privSize = 0;
        ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &privSize);
        PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)MSVCRT$malloc(privSize);

        if (pPrivs && ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, pPrivs, privSize, &privSize)) {
            BeaconFormatPrintf(&buffer, "\n\nPrivilege Name                Description                                       State                         \n");
            BeaconFormatPrintf(&buffer, "============================= ================================================= ===========================\n");

            for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
                char privName[256];
                DWORD privNameLen = sizeof(privName);
                if (ADVAPI32$LookupPrivilegeNameA(NULL, &pPrivs->Privileges[i].Luid, privName, &privNameLen)) {
                    char dispName[256];
                    DWORD dispNameLen = sizeof(dispName);
                    DWORD langID;
                    ADVAPI32$LookupPrivilegeDisplayNameA(NULL, privName, dispName, &dispNameLen, &langID);
                    const char* state = (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled";
                    BeaconFormatPrintf(&buffer, "%-30s%-50s%s\n", privName, dispName, state);
                }
            }
        }
        if (pPrivs) MSVCRT$free(pPrivs);
        KERNEL32$CloseHandle(hToken);
    }

    int outSize = 0;
    char* outData = BeaconFormatToString(&buffer, &outSize);
    BeaconOutput(CALLBACK_OUTPUT, outData, outSize);
    BeaconFormatFree(&buffer);
}
