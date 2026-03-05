#include <windows.h>
#include <shlobj.h>
#include "beacon.h"

// Dynamic Function Resolution (DFR) - BOF style
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetComputerNameExA(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentDirectoryA(DWORD, LPSTR);
DECLSPEC_IMPORT void   WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO);
DECLSPEC_IMPORT BOOL   WINAPI SHELL32$IsUserAnAdmin(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetVersionExA(LPOSVERSIONINFOA);
DECLSPEC_IMPORT void * CDECL  MSVCRT$memset(void *, int, size_t);

void go(char * args, int alen){
    formatp buffer;
    BeaconFormatAlloc(&buffer, 2048);

    char username[256];
    DWORD usernamesize = sizeof(username);

    if (ADVAPI32$GetUserNameA(username, &usernamesize)){
        BeaconFormatPrintf(&buffer, "[*] User: %s\n", username);
    }
    char computername[256];
    DWORD computernamesize = sizeof(computername);

    if (KERNEL32$GetComputerNameA(computername, &computernamesize)){
        BeaconFormatPrintf(&buffer, "[*] Hostname: %s\n", computername);
    }
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexa
    char domain[256];
    DWORD domainsize = sizeof(domain);

    if (KERNEL32$GetComputerNameExA(ComputerNameDnsDomain, domain, &domainsize)){
        BeaconFormatPrintf(&buffer, "[*] Domain: %s\n", domain);
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
    DWORD pid = KERNEL32$GetCurrentProcessId();
    BeaconFormatPrintf(&buffer, "[*] PID: %u\n", pid);

    char directory[256];
    DWORD directorysize = sizeof(directory);

    if (KERNEL32$GetCurrentDirectoryA(directorysize, directory)){
        BeaconFormatPrintf(&buffer, "[*] CWD: %s\n", directory);
    }

    SYSTEM_INFO si;
    KERNEL32$GetSystemInfo(&si);

    BeaconFormatPrintf(&buffer, "[*] Number of Processors: %u\n", si.dwNumberOfProcessors);

    switch(si.wProcessorArchitecture){
        case PROCESSOR_ARCHITECTURE_AMD64:
            BeaconFormatPrintf(&buffer, "[*] Architecture: x64 (64-bit)\n");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            BeaconFormatPrintf(&buffer, "[*] Architecture: x86 (32-bit)\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            BeaconFormatPrintf(&buffer, "[*] Architecture: ARM\n");
            break;
        default:
            BeaconFormatPrintf(&buffer, "[*] Architecture: Unknown (%u)\n", si.wProcessorArchitecture);
            break;
    }
    if (SHELL32$IsUserAnAdmin()){
        BeaconFormatPrintf(&buffer, "[*] Admin: YES\n");
    }else {
        BeaconFormatPrintf(&buffer, "[*] Admin: NO\n");
    }
    OSVERSIONINFOA osvi;

    MSVCRT$memset(&osvi, 0, sizeof(OSVERSIONINFOA));

    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);

    if(KERNEL32$GetVersionExA(&osvi)){
        BeaconFormatPrintf(&buffer, "[*] OS Major: %u\n", osvi.dwMajorVersion);
        BeaconFormatPrintf(&buffer, "[*] OS Minor: %u\n", osvi.dwMinorVersion);
        BeaconFormatPrintf(&buffer, "[*] Build Number: %u\n", osvi.dwBuildNumber);
    }

    int outsize;
    char * outdata = BeaconFormatToString(&buffer, &outsize);
    BeaconOutput(CALLBACK_OUTPUT, outdata, outsize);
    BeaconFormatFree(&buffer);
}
