#include <windows.h>
#include <winldap.h>
#include <string.h>
#include "beacon.h"

DECLSPEC_IMPORT LDAP * WINAPI WLDAP32$ldap_initA(const PCHAR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$LdapGetLastError(void);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_connect(LDAP *ld, LDAP_TIMEVAL *timeout);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP *ld);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sA(LDAP *ld, PCHAR dn, PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sA(LDAP *ld, PCHAR base, ULONG scope, PCHAR filter, PCHAR * attrs, ULONG attrsonly, PLDAPMessage *res);
DECLSPEC_IMPORT LDAPMessage * WINAPI WLDAP32$ldap_first_entry(LDAP *ld, LDAPMessage *res);
DECLSPEC_IMPORT PCHAR * WINAPI WLDAP32$ldap_get_valuesA(LDAP *ld, LDAPMessage *entry, PCHAR attr);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_freeA(PCHAR *vals);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage *res);

DECLSPEC_IMPORT char * WINAPI MSVCRT$_strdup(const char *strSource);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void *memblock);

#define ldap_initA WLDAP32$ldap_initA
#define LdapGetLastError WLDAP32$LdapGetLastError
#define ldap_connect WLDAP32$ldap_connect
#define ldap_unbind WLDAP32$ldap_unbind
#define ldap_bind_sA WLDAP32$ldap_bind_sA
#define ldap_search_sA WLDAP32$ldap_search_sA
#define ldap_first_entry WLDAP32$ldap_first_entry
#define ldap_get_valuesA WLDAP32$ldap_get_valuesA
#define ldap_value_freeA WLDAP32$ldap_value_freeA
#define ldap_msgfree WLDAP32$ldap_msgfree
#define _strdup MSVCRT$_strdup
#define free MSVCRT$free

void go(char* args, int length) {
    datap parser;
    char *domain = NULL;
    char *dc = NULL;

    BeaconDataParse(&parser, args, length);
    domain = BeaconDataExtract(&parser, NULL);
    dc = BeaconDataExtract(&parser, NULL);

    if (!domain || !dc) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: maq <domain> <dc>");
        return;
    }

    LDAP* ld = ldap_initA(dc, LDAP_PORT);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Connection failed with error: 0x%lx", LdapGetLastError());
        return;
    }

    ULONG res = ldap_connect(ld, NULL);
    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Connection Failed: 0x%lx", res);
        ldap_unbind(ld);
        return;
    }

    res = ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Bind Failed: 0x%lx", res);
        ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Connection successful to %s", dc);

    LDAPMessage* rootResult = NULL;
    char* rootAttrs[] = {"defaultNamingContext", NULL};

    res = ldap_search_sA(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", rootAttrs, 0, &rootResult);

    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get default naming context: 0x%lx", res);
        ldap_unbind(ld);
        return;
    }

    char* defaultNC = NULL;
    LDAPMessage* rootEntry = ldap_first_entry(ld, rootResult);
    if (rootEntry) {
        char** ncValues = ldap_get_valuesA(ld, rootEntry, "defaultNamingContext");
        if (ncValues && ncValues[0]) {
            defaultNC = _strdup(ncValues[0]);
            BeaconPrintf(CALLBACK_OUTPUT, "Default naming context : %s", defaultNC);
            ldap_value_freeA(ncValues);
        }
    }
    ldap_msgfree(rootResult);

    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "Could not get defaultNamingContext");
        ldap_unbind(ld);
        return;
    }

    LDAPMessage* maqResult = NULL;
    char* maqAttrs[] = { "ms-DS-MachineAccountQuota", NULL };

    res = ldap_search_sA(ld, defaultNC, LDAP_SCOPE_BASE, "(objectClass=*)", maqAttrs, 0, &maqResult);

    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Maq query failed 0x%lx", res);
        free(defaultNC);
        ldap_unbind(ld);
        return;
    }

    LDAPMessage* maqEntry = ldap_first_entry(ld, maqResult);
    if (maqEntry) {
        char** maqValues = ldap_get_valuesA(ld, maqEntry, "ms-DS-MachineAccountQuota");
        if (maqValues && maqValues[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Machine Account Quota: %s", maqValues[0]);
            ldap_value_freeA(maqValues);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Maq attributes not found");
        }
    }

    ldap_msgfree(maqResult);
    free(defaultNC);
    ldap_unbind(ld);
}
