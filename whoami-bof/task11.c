#include <windows.h>
#include <stdio.h>
#include <shlobj.h> // if u wannan use IsUserAdmin u jave to give this first

int main(){
    char username[256];
    DWORD usernamesize = sizeof(username);

    if (GetUserNameA(username, &usernamesize)){
        printf("[*] User: %s\n", username);
    }
    char computername[256];
    DWORD computernamesize = sizeof(computername);

    if (GetComputerNameA(computername, &computernamesize)){
        printf("[*] Hostname: %s\n", computername);
    }
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexa
    char domain[256];
    DWORD domainsize = sizeof(domain);

    if (GetComputerNameExA(ComputerNameDnsDomain, domain, &domainsize)){
        printf("[*] Domain: %s\n", domain);
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
    DWORD pid = GetCurrentProcessId();
    printf("[*] PID: %u\n", pid); // the reason stop using & &, you told the program: "Give me the value of the PID," instead of "Give me the memory address where the PID is sitting."

    char directory[256];
    DWORD directorysize = sizeof(directory);

    if (GetCurrentDirectoryA(directorysize, directory)){
        printf("[*] CWD: %s\n", directory);
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    printf("[*] Number of Processors: %u\n", si.dwNumberOfProcessors);

    printf("[*] Architecture: ");

    switch(si.wProcessorArchitecture){
        case PROCESSOR_ARCHITECTURE_AMD64:
            printf("x64 (64-bit)\n");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            printf("x86 (32-bit)\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            printf("ARM");
            break;
        default:
            printf("Uknown (%u)\n", si.wProcessorArchitecture);
            break;
    }
    if (IsUserAnAdmin()){
        printf("[*] Admin : YES\n");
    }else {
        printf("[*] Admin: NO\n");
    }
    OSVERSIONINFOA osvi;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));

    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);

    if(GetVersionExA(&osvi)){
        printf("[*] OS Major: %u\n", osvi.dwMajorVersion);
        printf("[*] OS Minor: %u\n", osvi.dwMinorVersion);
        printf("[*] Build Number: %u\n", osvi.dwBuildNumber);
    }


    return 0;
}
