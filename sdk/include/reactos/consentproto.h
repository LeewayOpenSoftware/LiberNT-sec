/*
 * PROJECT:     LiberNT
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     What consent.exe and the secondary logon service exchange in the credentials mode
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 *
 * The service starts consent.exe with two anonymous pipes inherited by that process alone:
 * consent writes one CONSENT_CREDENTIAL_RECORD per try on the record pipe and reads one
 * CONSENT_VERDICT on the verdict pipe; the service does the logon and counts the tries.
 * Command line: consent.exe <hwnd> "<account>" "<path>" /cred:<record handle>,<verdict handle> <command line>
 */

#pragma once

#define CONSENT_RECORD_MAGIC     0x44455243  /* 'CRED' */
#define CONSENT_MAX_USER         256
#define CONSENT_MAX_DOMAIN       256
#define CONSENT_MAX_PASSWORD     256

typedef struct _CONSENT_CREDENTIAL_RECORD
{
    ULONG Magic;
    ULONG Answer;           /* IDYES with credentials, IDNO when the user declined */
    ULONG UserLength;       /* characters, without the terminator */
    ULONG DomainLength;
    ULONG PasswordLength;
    WCHAR User[CONSENT_MAX_USER];
    WCHAR Domain[CONSENT_MAX_DOMAIN];
    WCHAR Password[CONSENT_MAX_PASSWORD];
} CONSENT_CREDENTIAL_RECORD, *PCONSENT_CREDENTIAL_RECORD;

typedef enum _CONSENT_VERDICT
{
    ConsentVerdictOk = 1,            /* the logon is an administrator: the request goes on */
    ConsentVerdictWrongPassword = 2, /* ask again */
    ConsentVerdictCannotApprove = 3, /* a valid logon that is no administrator: ask again */
    ConsentVerdictRefused = 4        /* no more tries: the prompt closes */
} CONSENT_VERDICT;
