#include <windows.h>
#include <stdio.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
int main(){
    char nameBuffer[512];
    ULONG nameSize = sizeof(nameBuffer);
    if (GetUserNameExA(NameSamCompatible, nameBuffer, &nameSize)){
        BYTE sid[SECURITY_MAX_SID_SIZE];
        DWORD sidSize = sizeof(sid);
        char referencedDomain[256];
        DWORD refDomainSize = sizeof(referencedDomain);
        SID_NAME_USE snu;
        if (LookupAccountNameA(NULL, nameBuffer, sid, &sidSize, referencedDomain, &refDomainSize, &snu)){
            LPSTR sidString = NULL;
            if (ConvertSidToStringSidA(sid, &sidString)){
                printf("SID                                           username\n");
                printf("----------------------------------------------------------------------------------------------------------------------------\n");
                printf("%s %s\n", sidString, nameBuffer);
                printf("----------------------------------------------------------------------------------------------------------------------------\n");
                LocalFree(sidString);
            } else {
                fprintf(stderr, "ConvertSidToStringSidA failed: %lu\n", GetLastError());
            }
        } else {
            fprintf(stderr,"LookupAccountNameA failed : %lu\n", GetLastError());
        }
    } else {
        fprintf(stderr, "GetUserNameExA failed : %lu\n", GetLastError());
        return -1;
    }
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)){
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
        PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)malloc(dwSize);
        if (pGroups && GetTokenInformation(hToken, TokenGroups, pGroups, dwSize,&dwSize)){
            for (DWORD i = 0; i < pGroups->GroupCount; i++){
                char gName[256], gDom[256];
                DWORD gNameLen = 256, gDomLen = 256;
                SID_NAME_USE gSnu;
                LPSTR gSidStr = NULL;
                if (LookupAccountSidA(NULL, pGroups->Groups[i].Sid, gName, &gNameLen, gDom, &gDomLen, &gSnu)){
                    ConvertSidToStringSidA(pGroups->Groups[i].Sid, &gSidStr);
                    printf("%s\\%-25s %s\n", gDom,gName, gSidStr);
                    LocalFree(gSidStr);
                }
            }
        }
        if (pGroups) free(pGroups);
        DWORD privSize = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &privSize);
        PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)malloc(privSize);
        if (pPrivs && GetTokenInformation(hToken, TokenPrivileges, pPrivs, privSize, &privSize)){
            printf("\n%-35s %-45s %s\n", "PrivilegeName", "Description", "State");
            printf("----------------------------------------------------------------------------------------------------------------------------\n");
            for (DWORD i = 0; i <pPrivs->PrivilegeCount; i++){
                char privName[256];
                DWORD privNameLen = sizeof(privName);
                if (LookupPrivilegeNameA(NULL, &pPrivs->Privileges[i].Luid, privName, &privNameLen)){
                    char dispName[256];
                    DWORD dispNameLen = sizeof(dispName);
                    DWORD langID;
                    LookupPrivilegeDisplayNameA(NULL, privName, dispName, &dispNameLen, &langID);
                    const char* state = (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled";
                    printf("%-35s %-45s %s\n", privName, dispName, state);
                }
            }
        }
        if (pPrivs) free(pPrivs);
        CloseHandle(hToken);
    }
    return 0;
}
