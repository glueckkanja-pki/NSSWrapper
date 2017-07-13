#include "StdAfx.h"
#include "NSSDatabase.h"

#include <nss.h>
#include <secmod.h>
#include <ssl.h>
#include <p12plcy.h>

#if NSSWRAPPER_INCLUDE_DYNAMICS
extern "C"
{
#define BOOL int
extern BOOL _pr_use_static_tls;  /* defined in ntthread.c */
}
#endif // NSSWRAPPER_INCLUDE_DYNAMICS

using namespace System;

namespace GK
{
namespace NSSWrapper
{

// region "copied from pk12util.c"
static SECStatus
p12u_SwapUnicodeBytes(SECItem *uniItem)
{
    unsigned int i;
    unsigned char a;
    if((uniItem == NULL) || (uniItem->len % 2)) {
		return SECFailure;
    }
    for(i = 0; i < uniItem->len; i += 2) {
		a = uniItem->data[i];
		uniItem->data[i] = uniItem->data[i+1];
		uniItem->data[i+1] = a;
    }
    return SECSuccess;
}

static PRBool
p12u_ucs2_ascii_conversion_function(PRBool	   toUnicode,
				    unsigned char *inBuf,
				    unsigned int   inBufLen,
				    unsigned char *outBuf,
				    unsigned int   maxOutBufLen,
				    unsigned int  *outBufLen,
				    PRBool	   swapBytes)
{
    SECItem it = { siBuffer };
    SECItem *dup = NULL;
    PRBool ret;

#ifdef DEBUG_CONVERSION
    if (pk12_debugging) {
	int i;
	printf("Converted from:\n");
	for (i=0; i<inBufLen; i++) {
	    printf("%2x ", inBuf[i]);
	    /*if (i%60 == 0) printf("\n");*/
	}
	printf("\n");
    }
#endif
    it.data = inBuf;
    it.len = inBufLen;
    dup = SECITEM_DupItem(&it);
    /* If converting Unicode to ASCII, swap bytes before conversion
     * as neccessary.
     */
    if (!toUnicode && swapBytes) {
	if (p12u_SwapUnicodeBytes(dup) != SECSuccess) {
	    SECITEM_ZfreeItem(dup, PR_TRUE);
	    return PR_FALSE;
	}
    }
    /* Perform the conversion. */
    ret = PORT_UCS2_UTF8Conversion(toUnicode, dup->data, dup->len,
                                   outBuf, maxOutBufLen, outBufLen);
    if (dup)
	SECITEM_ZfreeItem(dup, PR_TRUE);

#ifdef DEBUG_CONVERSION
    if (pk12_debugging) {
	int i;
	printf("Converted to:\n");
	for (i=0; i<*outBufLen; i++) {
	    printf("%2x ", outBuf[i]);
	    /*if (i%60 == 0) printf("\n");*/
	}
	printf("\n");
    }
#endif
    return ret;
}
// endregion "copied from pk12util.c"


	void NSSDatabase::initialize()
	{
		if (nullptr == strDbPath)
			throw gcnew InvalidOperationException("NSSDatabase.strDbPath must be set before using any NSSWrapper functions.");

		if (!isInitialized)
		{
			System::Threading::Monitor::Enter(nssInitLock);
			try
			{
				if (!isInitialized)
				{
					char *caDbPath = NULL;
					SECStatus res = SECFailure;
					
#if NSSWRAPPER_INCLUDE_DYNAMICS
						// this must be set to false if LoadLibrary was used to load this DLL
						// (which will happen: NSSWrapper loads itself dynamically through
						// the NSS code multiple times, for example as a PKCS#10 module)
						// Anyway, it seems not to cause a problem on systems >= Vista.
						// On XP and 2003, the program fails with a memory access error
						// in NSS_InitReadWrite(caDbPath) a couple of lines below.
						// The use of _pr_use_static_tls = true is faster, so perhaps
						// the code here should check for the Windows version and use
						// _pr_use_static_tls = true for systems >= Vista
					_pr_use_static_tls = false;
						// I added CHANN_NSS_setSoftokenLibName to NSS so that instead of
						// the default softokn.dll, another DLL could be loaded.
					CHANN_NSS_setSoftokenLibName("NSSWrapper.dll");
#endif

					NETSTRING_2_CHARSTRING(strDbPath,caDbPath)
					res = NSS_InitReadWrite(caDbPath);
					delete[] caDbPath;
					ASSERT_NSS_SUCCESS(res, "NSS initialization failed on opening key database");

					res = NSS_SetExportPolicy();
					if (SECFailure == res)
						throw gcnew System::Runtime::InteropServices::ExternalException("Export Policy could not be set",PR_GetError());
					
					int pkcs12Ciphers[] = { PKCS12_RC2_CBC_40, PKCS12_RC2_CBC_128, PKCS12_RC4_40, PKCS12_RC4_128, PKCS12_DES_56, PKCS12_DES_EDE3_168 };
					for (int i = 0; i < sizeof(pkcs12Ciphers) / sizeof(int);++i)
					{
						res = SEC_PKCS12EnableCipher(pkcs12Ciphers[i], true);
						if (SECFailure == res)
							throw gcnew System::Runtime::InteropServices::ExternalException(
								String::Concat("Cipher #0x", pkcs12Ciphers[i].ToString("X"), " could not be enabled"),
								PR_GetError());
					}

					PORT_SetUCS2_ASCIIConversionFunction(p12u_ucs2_ascii_conversion_function);
				}
			}
			finally
			{
				System::Threading::Monitor::Exit(nssInitLock);
			}
		}
	}

	void NSSDatabase::strDbPath::set(System::String ^strValue)
	{
		if (isInitialized)
			throw gcnew InvalidOperationException("The path for the NSS Database can't be changed after initialization of NSSDatabase");
		else
			_strDbPath = strValue->TrimEnd(gcnew array<wchar_t>{ '\\' }); // TODO: Give a good error message Exception, if this value is empty
	}

	static NSSDatabase::NSSDatabase()
	{
		nssInitLock = gcnew Object();
		isInitialized = false;
		_strDbPath = nullptr;
	}
}
}