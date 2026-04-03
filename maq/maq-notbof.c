#include <stdio.h>
#include <windows.h>
#include <winldap.h>
#include <string.h>

#pragma comment(lib, "wldap32.lib")

int main(int argc, char* argv[]){
    char* domain = NULL;
    char * dc = NULL;
    for (int i = 1; i < argc; i++){
        if (strcmp(argv[i], "--domain") == 0) domain = argv[i+1];
        else if (strcmp(argv[i], "--dc") == 0) dc = argv[i+1];
    }

    if (!domain || !dc){
        printf("Usage maq-notbof.exe --domain <domain> --dc <dc>\n");
        return -1;
    }

    LDAP* ld = ldap_init(dc, LDAP_PORT);
    if (ld == NULL){
        printf("Connection failed with error: 0x%lx\n", LdapGetLastError());
        return -1;
    }
    ULONG res = ldap_connect(ld, NULL);
    if (res != LDAP_SUCCESS){
        printf("Connection Failed: 0x%lx\n", res);
        ldap_unbind(ld);
        return -1;
    }

    res = ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (res != LDAP_SUCCESS){
        printf("Bind Failed: 0x%lx\n", res);
        ldap_unbind(ld);
        return -1;
    }

    printf("Connection sucessfull to %s\n", dc);

    // char domainDN[256] = { 0 };
    // char domainCopy[256];
    // strcpy(domainCopy, domain);

    // char* token = strtok(domain, ".");
    // while (token){
        // strcat(domainDN, "DC=");
        // strcat(domainDN, token);
        // token = strtok(NULL, ".");
        //if (token) strcat(domainDN, ",");
    //}

    // char baseDN[256];

    // snprintf(baseDN, sizeof(baseDN), "%s", domainDN);

    LDAPMessage* rootResult = NULL;
    char* rootAttrs[] = {"defaultNamingContext", NULL};

    res = ldap_search_s(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", rootAttrs, 0, &rootResult);

    if (res != LDAP_SUCCESS){
        printf("Failed to get machine account quota: 0x%lx\n", res);
        ldap_unbind(ld);
        return -1;
    }
    char* defaultNC = NULL;
    LDAPMessage* rootEntry = ldap_first_entry(ld, rootResult);
    if (rootEntry){
        char** ncValues = ldap_get_values(ld, rootEntry, "defaultNamingContext");
        if (ncValues && ncValues[0]){
            defaultNC = _strdup(ncValues[0]);
            printf("Default naming context : %s\n", defaultNC);
            ldap_value_free(ncValues);
        }
    }
    ldap_msgfree(rootResult);

    if (!defaultNC){
        printf("Could not get ....\n");
        ldap_unbind(ld);
        return -1;
    }


    LDAPMessage* maqResult = NULL;
    char* maqAttrs[] = { "ms-DS-MachineAccountQuota", NULL };

    res = ldap_search_s(ld, defaultNC, LDAP_SCOPE_BASE, "(objectClass=*)", maqAttrs, 0, &maqResult);

    if (res != LDAP_SUCCESS){
        printf("Maq query failed 0x%lx\n", res);
        free(defaultNC);
        ldap_unbind(ld);
        return -1;
    }

    LDAPMessage* maqEntry = ldap_first_entry(ld, maqResult);
    if (maqEntry){
        char** maqValues = ldap_get_values(ld, maqEntry, "ms-DS-MachineAccountQuota");
        if (maqValues && maqValues[0]){
            printf("[+] Machine Account Quota: %s\n", maqValues[0]);
            ldap_value_free(maqValues);

        } else {
            printf("[*] Maq attributes not found\n");
        }
    }

    ldap_msgfree(maqResult);
    free(defaultNC);
    ldap_unbind(ld);
    return 0;
}
