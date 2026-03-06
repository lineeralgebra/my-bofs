#include <windows.h>
#include <winldap.h>
#include <stdio.h>
#include <string.h> // if u used strcmp u have to include that abe

int main(int argc, char* argv[]){
    char* domain = NULL;
    char* dc = NULL;

    for (int i = 1; i < argc; i++){
        if (strcmp(argv[i], "--domain") == 0) domain = argv[i+1];
        else if (strcmp(argv[i], "--dc") == 0) dc = argv[i+1];
    }

    if (!domain || !dc){
        printf("Usage enum_users.exe --domain <domain> --dc <dc>\n");
        return -1;
    }

    LDAP* ld = ldap_initA(dc, LDAP_PORT);
    if (ld == NULL){
        printf("Connection Failed with error: 0x%lx\n", LdapGetLastError());
        return -1;
    }
    ULONG version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG res = ldap_connect(ld, NULL);
    if (res != LDAP_SUCCESS){
        printf("Connect Failed: 0x%lx\n", res);
        ldap_unbind(ld);
        return -1;
    }
    /*auth */
    res = ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (res != LDAP_SUCCESS){
        printf("Bind Failed: 0x%lx\n", res);
        ldap_unbind(ld);
        return -1;
    }

    printf("Connection successful to %s\n", dc);

    char domainDN[256] = {0};
    char domainCopy[256];
    strcmp(domainCopy, domain);

    char* token = strtok(domain, ".");
    while (token) {
        strcat(domainDN, "DC=");
        strcat(domainDN, token);
        token = strtok(NULL, ".");
        if (token) strcat(domainDN, ",");
    }
    char baseDN[256];

    //snprintf(baseDN, sizeof(baseDN), "CN=Users,%s", domainDN);
    snprintf(baseDN, sizeof(baseDN), "%s", domainDN);

    LDAPMessage* searchResult = NULL;
    char* attributes[] = {"sAMAccountName", "displayName", "description", NULL};

    res = ldap_search_s(ld, baseDN, LDAP_SCOPE_SUBTREE, "(objectClass=user)", attributes, 0, &searchResult);

    if (res != LDAP_SUCCESS){
        printf("Search Failed: 0x%lx\n", res);
        ldap_unbind(ld);
        return -1;
    }

    int count = ldap_count_entries(ld, searchResult);
    printf("Found %d users:\n\n", count);

    printf("%-25s | %-40s\n", "Username", "Description");
    printf("----------------------------------------------\n");
    LDAPMessage* entry = ldap_first_entry(ld, searchResult);
    while (entry != NULL){
        char** user_vals = ldap_get_values(ld, entry, "sAMAccountName");
        char** desc_vals = ldap_get_values(ld, entry, "description");
        if (user_vals != NULL){
            printf("%-20s | %-30s\n", user_vals[0], (desc_vals != NULL) ? desc_vals[0] : "");
        }
        if (user_vals) ldap_value_free(user_vals);
        if (desc_vals) ldap_value_free(desc_vals);

        entry = ldap_next_entry(ld, entry);
    }

    ldap_msgfree(searchResult);

    ldap_unbind(ld);
    return 0;

}
