#include "StdAfx.h"
#include "X509NSSCRL.h"
#include "NSSDatabase.h"
#include "X509NSSAuthorityKeyIdentifierExtension.h"

#include <nss.h>
#include <ssl.h>
#include <keyhi.h>
#include <cryptohi.h>
#include <p12.h>
#include <p12plcy.h>
#include <pk11pub.h>
#include <secmod.h>
#include <certdb.h>

#include "NSSInlineFunctions.h"

using namespace System::Runtime::InteropServices;

namespace GK
{
namespace NSSWrapper
{
	// It is difficult to create a new CRL with NSS.
	// Therefore, this random CRL is opened instead and afterwards,
	// all properties are changed to the desired values.
	#define SAMPLE_CRL \
	"MIIDejCCAWICAQEwDQYJKoZIhvcNAQEEBQAwdzETMBEGCgmSJomT8ixkARkWA29y" \
	"ZzEbMBkGCgmSJomT8ixkARkWC1RydXN0ZWRyb290MUMwQQYDVQQDEzpUcnVzdGVk" \
	"cm9vdCBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y" \
	"aXR5Fw0wNzA5MTkxMjUyMjJaFw0wODA5MTgxMjUyMjJaoIG2MIGzMIGwBgNVHSME" \
	"gagwgaWAFLrQUxKaO39f2Qi3DwTKEO+UR3ykoXukeTB3MRMwEQYKCZImiZPyLGQB" \
	"GRYDb3JnMRswGQYKCZImiZPyLGQBGRYLVHJ1c3RlZHJvb3QxQzBBBgNVBAMTOlRy" \
	"dXN0ZWRyb290IENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBB" \
	"dXRob3JpdHmCEHRydXN0ZWRyb290Lm9yZwAwDQYJKoZIhvcNAQEEBQADggIBAAIh" \
	"yXfxNTZgduF9qzcfPFcXVAj5QlFFScZVlrMQHxWabjsT9ZsTJ7AyDTwEMZlsSQBc" \
	"7zyO+cRovDlozwG8G7D3PRqITBmZCHf7vgXsHYz6mskfSHSH8Zgk5xEn3qUsXyuO" \
	"SopXe5WLLKnH4Ck9Mpx5c2ZCfhx796GmSYdVVqBVjlOX4IHPidkODQ5H4J60a+M4" \
	"kgjkl/sAb8wXeyBQmdtFv1OtaK+/14324+0juBcKqOBkn3cHxf8h9ZjZzbwNF3v0" \
	"3AH+e66ARWGrl3KJvp912lQvFW8Q13ONqJHEKyQrqNWU/6wD8SH6sofyFJdBcGa6" \
	"4AZzxVcrix2Fpxzida8zIjjNg9FQte6kUMJo2x49PJaTgdYXMdvFSn45acYF3m3+" \
	"t07y+4BTADVBYNUUifk+TQBIOuN7u/n9Sb7Eyivr7MQCeUiHmmvpHy95rU514duA" \
	"mTfBbRr2/ugpEvM2hIgwRclOXUhlb7OB9BDpS3fUS9U6yaJS9AYTLk5vztIC/rfs" \
	"HOGd2A78GnbEFefjAzxt6oOf3/3x+QUWtUIzHV9MEKt71U1d5+IMHL7Z8XDBQYeT" \
	"N4+APbzL33IQA5twPJ069xiLPnky/PHH4LNYWprHMAkDrazY6e+8aVAEd1Mf+saw" \
	"GKcha0xx7SRk7m/jcoVgxX3C9XQHovJrqB7uomFg"

	void changeGeneralizedTime(SECItem *siDate, DateTime dateSrc)
	{
		System::String ^strTime = dateSrc.ToString("yyMMddHHmmss");	// Trailing Z for Zulu will be added later (by replacing the 0 terminator)

		if (siDate->len != strTime->Length + 1)
			throw gcnew ArgumentException("SECItem siDate doesn't contain a date value", "siDate");

		System::IntPtr bString = System::Runtime::InteropServices::Marshal::StringToBSTR(strTime);
		wchar_t *tempString = reinterpret_cast<wchar_t*>(bString.ToPointer());
		sprintf_s(reinterpret_cast<char*>(siDate->data), siDate->len, "%S", tempString);
		System::Runtime::InteropServices::Marshal::FreeBSTR(bString);

		//char **cpDate = reinterpret_cast<char **>(&siDate->data);
		//NETSTRING_2_CHARSTRING(strTime, *cpDate)
		//siDate->len = strTime->Length + 1;
		//siDate->type = siGeneralizedTime;
		siDate->data[strTime->Length] = 'Z';	// This is the 0 terminator's replacement
	}

	DateTime readGeneralizedTime(SECItem *siDate)
	{
		int iTest = sizeof("yyMMddHHmmss");
		if (siDate->len != sizeof("yyMMddHHmmss"))
			throw gcnew ArgumentException("SECItem siDate doesn't contain a date value", "siDate");

		array<Byte> ^baDate;
		CHARARRAY_2_NETBYTEARRAY(siDate->data, siDate->len - 1, baDate);
		
		return
			DateTime::ParseExact(
				System::Text::Encoding::Default->GetString(baDate),
				"yyMMddHHmmss",
				System::Globalization::CultureInfo::InvariantCulture
			);
	}

	X509NSSCRL::X509NSSCRL(void)
		: _entries(nullptr)
	{
			// Open CRL Template
		binCRL = Convert::FromBase64String(SAMPLE_CRL);
	}

	X509NSSCRL::X509NSSCRL(array<System::Byte> ^binCRL)
		: _entries(nullptr)
	{
		NSSDatabase::initialize();

		// Detect Base64/PEM encoded CRLs
		if(binCRL->Length > 19 && binCRL[0] == '-' && binCRL[4] == '-' && binCRL[5] == 'B' && binCRL[17] == 'R' && binCRL[19] == '-')
		{
			String ^strCRL = System::Text::Encoding::ASCII->GetString(binCRL);

			array<Char> ^splitChars = gcnew array<Char>(2);
			splitChars[0] = '\n';
			splitChars[1] = '\r';
			array<String^> ^strCertLines = strCRL->Split(splitChars, StringSplitOptions::RemoveEmptyEntries);
            String ^strB64Cert = String::Join("\n", strCertLines, 1, strCertLines->Length - 2);
            this->binCRL = Convert::FromBase64String(strB64Cert);
		}
		else
			this->binCRL = binCRL;

		CERTSignedCrl *nssCRL = NULL;		// NSS data structure of the CRL 2 be parsed
		PLArenaPool *arenaCRL = NULL;		// The CRL needs its own arena, because the SEC_DestroyCRL frees the whole arena

		SECItem derCRL;						// binary data of the template CRL
		char **caCRLValue = reinterpret_cast<char **>(&derCRL.data);
		try
		{
			NETBYTEARRAY_2_CHARSTRING(this->binCRL, *caCRLValue)
			derCRL.len = this->binCRL->Length;

			arenaCRL = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
			nssCRL = CERT_DecodeDERCrl(arenaCRL, &derCRL, SEC_CRL_TYPE);

			dateStartTime = readGeneralizedTime(&nssCRL->crl.lastUpdate);
			dateEndTime = readGeneralizedTime(&nssCRL->crl.nextUpdate);
		}
		finally
		{
			CHECK_NULL_AND_FREE(delete[], *caCRLValue);
			CHECK_NULL_AND_FREE(delete[], derCRL.data);	// Same as *caCRLValue, so this is redundant
			if (nssCRL)
			{
				CERT_DestroyName(&nssCRL->crl.name);
				CHECK_NULL_AND_FREE(SEC_DestroyCrl, nssCRL);
				arenaCRL = NULL;		// this has just been freed by SEC_DestroyCrl
			}
			else if (arenaCRL)
			{
				PORT_FreeArena(reinterpret_cast<PLArenaPool *>(arenaCRL), false);
				arenaCRL = NULL;
			}
		}
	}

	array<Byte> ^X509NSSCRL::sign(X509NSSCertificate ^signingCert)
	{
		if (!signingCert->HasPrivateKey)
			throw gcnew ArgumentException("A certificate signing a CRL must have a private key!", "signingCert");

		NSSDatabase::initialize();

		SECItem *siUnsignedNewCRL = NULL;	// binary data of the unsigned CRL 2 be created
		CERTSignedCrl *nssCRL = NULL;		// NSS data structure of the CRL 2 be created
		SECItem siSignedNewCRL;				// binary data of the signed CRL 2 be created
		siSignedNewCRL.data = NULL;
		siSignedNewCRL.len = 0;
		PLArenaPool *arenaCRL = NULL;		// The CRL needs its own arena, because the SEC_DestroyCRL frees the whole arena
		CERTCrlEntry **nssEntryList = NULL;
		SECStatus stat = SECFailure;

		SECItem derCRL;						// binary data of the template CRL
		char **caCRLValue = reinterpret_cast<char **>(&derCRL.data);
		try
		{
			NETBYTEARRAY_2_CHARSTRING(binCRL, *caCRLValue)
			derCRL.len = binCRL->Length;

			arenaCRL = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
			nssCRL = CERT_DecodeDERCrl(arenaCRL, &derCRL, SEC_CRL_TYPE);
				// Set CRL attributes
					// Add revoked certificates
			nssEntryList = new CERTCrlEntry*[entries->Count + 1];
			nssEntryList[entries->Count] = NULL;	// NULL terminator
			for (int i =0; i < entries->Count; ++i)
				try
				{
					nssEntryList[i] = entries[i]->createNSSStructure();
				}
				catch(...)	// if an error occurs inside the loop, we have to free the halb-baked data structure
				{
					for (int j = 0;j < i; ++j)	// maybe nssEntryList[i] leaks, but maybe that's the price... ;-)
					{
						delete[] nssEntryList[j]->serialNumber.data;
						SECITEM_FreeItem(&nssEntryList[j]->revocationDate, PR_FALSE);	// Wasn't allocated in an arena
						delete nssEntryList[j];
					}
					delete[] nssEntryList;
					nssEntryList = NULL;
					throw;
				}
			nssCRL->crl.entries = nssEntryList;

			//CERT_DestroyName(&nssCRL->crl.name);
			char *ascIssuer;
			NETSTRING_2_CHARSTRING(signingCert->Subject,ascIssuer);
			nssCRL->crl.name = *CERT_AsciiToName(ascIssuer);
			delete[] ascIssuer;

					// Set validity dates
			changeGeneralizedTime(&nssCRL->crl.lastUpdate, dateStartTime);
			changeGeneralizedTime(&nssCRL->crl.nextUpdate, dateEndTime);
			
			nssCRL->crl.extensions = NULL;
			if (nullptr != authorityKeyIdentifier)
			{
				void *handleCRLExt = CERT_StartCRLExtensions(&nssCRL->crl);

				X509NSSAuthorityKeyIdentifierExtension ^authIdentifierExt = gcnew X509NSSAuthorityKeyIdentifierExtension();
				authIdentifierExt->keyIdentifier = authorityKeyIdentifier;
				authIdentifierExt->add2OpaqueHandle(arenaCRL, handleCRLExt);
				//addAKI2Handle(arenaCRL, handleCRLExt, authorityKeyIdentifier);

				CERT_FinishExtensions(handleCRLExt);
				handleCRLExt = NULL;
			}

				// ASN.1 encode CRL
			siUnsignedNewCRL = new SECItem();
			siUnsignedNewCRL->len = 0;
			siUnsignedNewCRL->data = NULL;
			const SEC_ASN1Template *unsignedCRLASN1 = SEC_ASN1_GET(CERT_CrlTemplate);
			SECItem *siTest = SEC_ASN1EncodeItem(arenaCRL, siUnsignedNewCRL, &nssCRL->crl, unsignedCRLASN1);
			ASSERT_NSS_NOTNULL(siTest, "Could not encode CRL!");		

				// sign CRL
			stat = SEC_DerSignData(
				arenaCRL,									// memory arena
				&siSignedNewCRL,							// signed target data buffer (space will be allocated in arena)
				siUnsignedNewCRL->data,						// source data buffer 2 be signed
				siUnsignedNewCRL->len,						// length of source data buffer
				signingCert->nssPrivateKey,					// signature key
					// TODO: This private key leaks away!
				SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION);	// signature algorithm
			ASSERT_NSS_SUCCESS(stat, "CRL could not be signed");

				// Convert binary CRL from char array to .NET byte array
			array<Byte> ^baNewCRL;
			CHARARRAY_2_NETBYTEARRAY(siSignedNewCRL.data,siSignedNewCRL.len,baNewCRL)

			return baNewCRL;
		}
		finally
		{
			CERT_DestroyName(&nssCRL->crl.name);
			CHECK_NULL_AND_FREE(delete[], *caCRLValue);
			CHECK_NULL_AND_FREE(delete[], derCRL.data);	// Same as *caCRLValue, so this is redundant
			if (nssCRL)
			{
				CHECK_NULL_AND_FREE(SEC_DestroyCrl, nssCRL);
				arenaCRL = NULL;		// this has just been freed by SEC_DestroyCrl
			}
			else if (arenaCRL)
			{
				PORT_FreeArena(reinterpret_cast<PLArenaPool *>(arenaCRL), false);
				arenaCRL = NULL;
			}
			if (NULL != nssEntryList)
			{
				for (int i = 0; NULL != nssEntryList[i]; ++i)
				{
					delete[] nssEntryList[i]->serialNumber.data;
					SECITEM_FreeItem(&nssEntryList[i]->revocationDate, PR_FALSE);	// Wasn't allocated in an arena
					delete nssEntryList[i];
				}
				delete[] nssEntryList;
				nssEntryList = NULL;
			}
//			if (NULL != siUnsignedNewCRL && NULL != siUnsignedNewCRL->data)
//				SECITEM_FreeItem(siUnsignedNewCRL, PR_FALSE);
			CHECK_NULL_AND_FREE(delete, siUnsignedNewCRL);
//			SECITEM_FreeItem(&siSignedNewCRL, PR_FALSE);
		}

	}
}
}