#include <windows.h>
#include "beacon.h"

// Dynamic Function Resolution (DFR) declarations
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentDirectoryA(DWORD, LPSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT int    WINAPI MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int    WINAPI MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snprintf(char*, size_t, const char*, ...);

#define GetLastError    KERNEL32$GetLastError
#define strcmp           MSVCRT$strcmp
#define strncpy          MSVCRT$strncpy
#define snprintf         MSVCRT$_snprintf

void go(char* args, int len) {
    datap parser;
    char* dirPath = NULL;
    char path[MAX_PATH];
    char searchPath[MAX_PATH];
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    formatp buffer;

    // Parse arguments
    BeaconDataParse(&parser, args, len);
    dirPath = BeaconDataExtract(&parser, NULL);

    // If no argument provided or empty string, use current directory
    if (dirPath == NULL || dirPath[0] == '\0') {
        KERNEL32$GetCurrentDirectoryA(MAX_PATH, path);
    } else {
        strncpy(path, dirPath, MAX_PATH - 1);
        path[MAX_PATH - 1] = '\0';
    }

    snprintf(searchPath, MAX_PATH, "%s\\*", path);

    // Allocate format buffer for output
    BeaconFormatAlloc(&buffer, 16384);

    BeaconFormatPrintf(&buffer, "Directory: %s\n", path);
    BeaconFormatPrintf(&buffer, "----------------------------------------------------------------------\n");
    BeaconFormatPrintf(&buffer, "%-40s %-15s %s\n", "Name", "Type", "Size");
    BeaconFormatPrintf(&buffer, "----------------------------------------------------------------------\n");

    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] FindFirstFileA failed: %lu\n", GetLastError());
        BeaconFormatFree(&buffer);
        return;
    }

    do {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            BeaconFormatPrintf(&buffer, "%-40s %-15s %s\n", findData.cFileName, "<DIR>", "");
        } else {
            ULONGLONG fileSize = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
            char sizeStr[32];
            snprintf(sizeStr, sizeof(sizeStr), "%llu bytes", fileSize);
            BeaconFormatPrintf(&buffer, "%-40s %-15s %s\n", findData.cFileName, "<FILE>", sizeStr);
        }
    } while (KERNEL32$FindNextFileA(hFind, &findData));

    KERNEL32$FindClose(hFind);

    // Send all output to beacon at once
    int outputLen = 0;
    char* outputData = BeaconFormatToString(&buffer, &outputLen);
    BeaconOutput(CALLBACK_OUTPUT, outputData, outputLen);
    BeaconFormatFree(&buffer);
}
