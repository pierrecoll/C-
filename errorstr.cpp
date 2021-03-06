#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "time.h"


/*++

ErrorString:

    This routine does it's very best to translate a given error code into a
    text message.  Any trailing non-printable characters are striped from the
    end of the text message, such as carriage returns and line feeds.

Arguments:

    dwErrorCode supplies the error code to be translated.

Return Value:

    The address of a freshly allocated text string.  Use FreeErrorString to
    dispose of it.

Throws:

    Errors are thrown as DWORD status codes.

Remarks:




--*/
LPCTSTR ErrorString(DWORD dwErrorCode);

void print_time(void)
{
	struct tm newtime;
	char am_pm[] = "AM";
	__time64_t long_time;
	char timebuf[26];
	errno_t err;

	// Get time as 64-bit integer.
	_time64(&long_time);
	// Convert to local time.
	err = _localtime64_s(&newtime, &long_time);
	if (err)
	{
		printf("Invalid argument to _localtime64_s.");
		exit(1);
	}
	if (newtime.tm_hour > 12)        // Set up extension. 
		strcpy_s(am_pm, sizeof(am_pm), "PM");
	if (newtime.tm_hour > 12)        // Convert from 24-hour 
		newtime.tm_hour -= 12;    // to 12-hour clock. 
	if (newtime.tm_hour == 0)        // Set hour to 12 if midnight.
		newtime.tm_hour = 12;

	// Convert to an ASCII representation. 
	err = asctime_s(timebuf, 26, &newtime);
	if (err)
	{
		printf("Invalid argument to asctime_s.");
		exit(1);
	}
	printf("\n(%.19s %s)\n", timebuf, am_pm);
}

void ErrorPrint()
{
	ErrorString(GetLastError());
	return;
}

LPCTSTR
ErrorString(DWORD dwErrorCode)
{
    LPTSTR szErrorString = NULL;
    DWORD dwLen;

    dwLen = FormatMessage(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                dwErrorCode,
                LANG_NEUTRAL,
                (LPTSTR)&szErrorString,
                0,
                NULL);
	
	if ((0 == dwLen) || (szErrorString == NULL))
    {
        //ASSERT(NULL == szErrorString);
        dwLen = FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_HMODULE,
                    GetModuleHandle(L"winhttp"),
                    dwErrorCode,
                    LANG_NEUTRAL,
					//MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),  
					//LANG_INVARIANT,
					//GetSystemDefaultLangID(),
                    (LPTSTR)&szErrorString,
                    0,
                    NULL);
		//printf("dwLen 2:%d %X \n", dwLen, szErrorString);
        if (0 == dwLen)
        {
            //ASSERT(NULL == szErrorString);
			if (szErrorString != NULL)
			{
				printf("Assertion failure: szErrorString should be NULL as FormatMessage failed\n");
			}
        }
    }

	//Required for localization !!!
	if (szErrorString != NULL)
	{
		char OEMString[256];
		CharToOemBuff(szErrorString, (LPSTR)OEMString, wcslen(szErrorString));
		OEMString[wcslen(szErrorString)] = '\0';
		printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, OEMString);
	}
	else
	{
		/*
		C:\Temp>err 2f92
		# for hex 0x2f92 / decimal 12178
		ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR                         winhttp.h
		# 1 matches found for "2f92"*/
		if (dwErrorCode == 0x2F92)
		{
			printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, "ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR");
		}
		else
		{
			printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, "Unable to get error message");
		}


	}
	//SetConsoleCP(863);
	//printf("%d\n",GetConsoleCP());
	return szErrorString;
}




/*++

FreeErrorString:

    This routine frees the Error String allocated by the ErrorString service.

Arguments:

    szErrorString supplies the error string to be deallocated.

Return Value:

    None

Throws:

    None

Remarks:




--*/

void
FreeErrorString(
    LPCTSTR szErrorString)
{
    if (NULL != szErrorString)
        LocalFree((LPVOID)szErrorString);
}

