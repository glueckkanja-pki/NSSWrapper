#include "StdAfx.h"
#include "X509NSSCRLEntry.h"

#include <nss.h>
#include <ssl.h>
#include <keyhi.h>
#include <cryptohi.h>
#include <p12.h>
#include <p12plcy.h>
#include <pk11pub.h>
#include <secmod.h>
#include <secerr.h>
#include <secder.h>

namespace GK
{
namespace NSSWrapper
{
	CERTCrlEntry *X509NSSCRLEntry::createNSSStructure()
	{
		CERTCrlEntry *entry = new CERTCrlEntry();
		char **caSerial = NULL;
		try
		{
			entry->extensions = NULL;

			TimeSpan timeDiff = dateRevocation.Subtract( System::DateTime(1970,01,01));	
			__int64 unixTime = timeDiff.Ticks / 10;	// unixTime here seems to be the number of microseconds since 1970-01-01
			SECStatus stat = DER_TimeToUTCTime(&entry->revocationDate, unixTime);
			ASSERT_NSS_SUCCESS(stat, String::Concat("Could not encode revocation date ", dateRevocation.ToString()));

			caSerial = reinterpret_cast<char**>(&entry->serialNumber.data);
			NETBYTEARRAY_2_CHARSTRING(serialNumber, *caSerial);
			entry->serialNumber.len = serialNumber->Length;

			return entry;
		}
		catch(...)
		{		// on error, free local variables before escalating the exception
			CHECK_NULL_AND_FREE(delete[]*, caSerial);
			if (NULL != entry && NULL != entry->revocationDate.data)
				SECITEM_FreeItem(&entry->revocationDate, PR_FALSE);	// Wasn't allocated in an arena
			CHECK_NULL_AND_FREE(delete, entry);
			throw;
		}
	}
}
}