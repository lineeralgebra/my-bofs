#include <windows.h>
#include <winldap.h>
#include "beacon.h"

/* Wldap32.dll - Wide (W) versions for auto-discovery */
DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, PVOID);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_connect(LDAP*, struct l_timeval*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_ext_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, PLDAPControlW*, PLDAPControlW*, struct l_timeval*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_entries(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR* WINAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);

/* MSVCRT.dll */
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char*);

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    /* optional domain argument */
    char* domain_a = BeaconDataExtract(&parser, NULL);
    wchar_t domain_w[256];
    wchar_t* pDomain = NULL;

    if (domain_a && MSVCRT$strlen(domain_a) > 0) {
        if (toWideChar(domain_a, domain_w, 256)) {
            pDomain = domain_w;
        }
    }

    LDAP* ld = WLDAP32$ldap_initW(pDomain, 389);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_init failed");
        return;
    }

    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG res = WLDAP32$ldap_connect(ld, NULL);
    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_connect failed: 0x%x", res);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    res = WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_bind_s failed: 0x%x", res);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    /* Query RootDSE for defaultNamingContext (auto-discover base DN) */
    LDAPMessage* rootResult = NULL;
    PWSTR rootAttrs[] = { L"defaultNamingContext", NULL };
    PWSTR baseDN = NULL;

    res = WLDAP32$ldap_search_ext_sW(ld, L"", LDAP_SCOPE_BASE, L"(objectClass=*)", rootAttrs, 0, NULL, NULL, NULL, 0, &rootResult);
    if (res == LDAP_SUCCESS) {
        LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, rootResult);
        if (entry) {
            PWSTR* values = WLDAP32$ldap_get_valuesW(ld, entry, L"defaultNamingContext");
            if (values) {
                baseDN = values[0];
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Using Base DN: %ls\n", baseDN);
                /* NOTE: don't free values yet — baseDN points into it */
            }
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query RootDSE: 0x%x", res);
        if (rootResult) WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    /* Search for all groups */
    LDAPMessage* searchResult = NULL;
    PWSTR attrs[] = { L"cn", L"member", L"description", NULL };

    res = WLDAP32$ldap_search_ext_sW(ld, baseDN, LDAP_SCOPE_SUBTREE, L"(objectClass=group)", attrs, 0, NULL, NULL, NULL, 0, &searchResult);

    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_search failed: 0x%x", res);
        if (rootResult) WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    int count = WLDAP32$ldap_count_entries(ld, searchResult);

    formatp buffer;
    BeaconFormatAlloc(&buffer, 64 * 1024);
    BeaconFormatPrintf(&buffer, "[+] Found %d group(s)\n\n", count);

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    while (entry) {
        /* Group name (cn) */
        PWSTR* cn = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        if (cn && cn[0]) {
            BeaconFormatPrintf(&buffer, "Group: %ls\n", cn[0]);
        }

        /* Description */
        PWSTR* desc = WLDAP32$ldap_get_valuesW(ld, entry, L"description");
        if (desc && desc[0]) {
            BeaconFormatPrintf(&buffer, "  Description: %ls\n", desc[0]);
        }

        /* Members */
        PWSTR* members = WLDAP32$ldap_get_valuesW(ld, entry, L"member");
        if (members) {
            for (int i = 0; members[i] != NULL; i++) {
                BeaconFormatPrintf(&buffer, "    - %ls\n", members[i]);
            }
            WLDAP32$ldap_value_freeW(members);
        }

        if (desc) WLDAP32$ldap_value_freeW(desc);
        if (cn) WLDAP32$ldap_value_freeW(cn);

        BeaconFormatPrintf(&buffer, "\n");
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    int outputSize = 0;
    char* outputData = BeaconFormatToString(&buffer, &outputSize);
    BeaconOutput(CALLBACK_OUTPUT, outputData, outputSize);
    BeaconFormatFree(&buffer);

    if (searchResult) WLDAP32$ldap_msgfree(searchResult);
    if (rootResult) WLDAP32$ldap_msgfree(rootResult);
    WLDAP32$ldap_unbind(ld);
}
