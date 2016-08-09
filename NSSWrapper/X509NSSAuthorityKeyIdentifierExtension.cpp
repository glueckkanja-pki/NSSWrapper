#include "StdAfx.h"
#include "X509NSSAuthorityKeyIdentifierExtension.h"

#include <ssl.h>

using namespace System;

namespace GK
{
namespace NSSWrapper
{
	X509NSSAuthorityKeyIdentifierExtension::X509NSSAuthorityKeyIdentifierExtension(void)
	{
		keyIdentifier = nullptr;
		serialNumber = nullptr;
	}

	void X509NSSAuthorityKeyIdentifierExtension::add2OpaqueHandle(PLArenaPool *nssArena, void *opaqueCertHandle)
	{
		if (nullptr == keyIdentifier && nullptr == issuerDN)
			throw gcnew InvalidOperationException("An Authority Key Identifier could not be added to a certificate/CRL because neither a KeyID nor an Issuer DN was given");

		if (nullptr == issuerDN && nullptr != serialNumber)
			throw gcnew InvalidOperationException("An Authority Key Identifier could not be added to a certificate/CRL because a serial was given but no Issuer DN, which is required in this case");

		CERTAuthKeyID cakID;
		cakID.keyID.data = NULL;
		cakID.keyID.len = 0;
		cakID.authCertIssuer = NULL;
		cakID.DERAuthCertIssuer = NULL;
		cakID.authCertSerialNumber.data = NULL;
		cakID.authCertSerialNumber.len = 0;

		try
		{
			if (nullptr != keyIdentifier)
			{
				char **caKeyIDData = reinterpret_cast<char **>(&cakID.keyID.data);
				NETBYTEARRAY_2_CHARSTRING(keyIdentifier, *caKeyIDData);
				cakID.keyID.len = keyIdentifier->Length;
			}

			if (nullptr != issuerDN)
			{
				cakID.authCertIssuer = PORT_ArenaZNew(nssArena, CERTGeneralName);
				cakID.authCertIssuer->type = certDirectoryName;
				cakID.authCertIssuer->l.prev = cakID.authCertIssuer->l.next = &cakID.authCertIssuer->l;

				cakID.authCertIssuer->name.directoryName.arena = NULL;
				cakID.authCertIssuer->name.directoryName.rdns = NULL;

				SECItem siIssuer;
				siIssuer.data = NULL;
				siIssuer.len = 0;

				SECITEM_AllocItem(nssArena, &siIssuer, issuerDN->RawData->Length);
				System::Runtime::InteropServices::Marshal::Copy(issuerDN->RawData, 0, System::IntPtr(siIssuer.data), issuerDN->RawData->Length);
				SEC_ASN1DecodeItem(nssArena, &cakID.authCertIssuer->name.directoryName, CERT_NameTemplate, &siIssuer);
			}

			if (nullptr != serialNumber)
			{
				char **caSerialNumberData = reinterpret_cast<char **>(&cakID.authCertSerialNumber.data);
				NETBYTEARRAY_2_CHARSTRING(serialNumber, *caSerialNumberData);
				cakID.authCertSerialNumber.len = serialNumber->Length;
			}

			SECItem siAuthorityKeyID;
			siAuthorityKeyID.data = NULL;
			siAuthorityKeyID.len = 0;

			SECStatus stat = CERT_EncodeAuthKeyID(nssArena, &cakID , &siAuthorityKeyID);
			ASSERT_NSS_SUCCESS(stat, "Error encoding Authority Key Identifier");

			stat = CERT_AddExtension(opaqueCertHandle, SEC_OID_X509_AUTH_KEY_ID, &siAuthorityKeyID, PR_FALSE, PR_TRUE);
			ASSERT_NSS_SUCCESS(stat, "Error adding Authority Key Identifier Extension to certificate/CRL");
		}
		finally
		{
				if (NULL != cakID.keyID.data)
				{
					delete[] cakID.keyID.data;
					cakID.keyID.data = NULL;
				}

				if (NULL != cakID.authCertSerialNumber.data)
				{
					delete[] cakID.authCertSerialNumber.data;
					cakID.authCertSerialNumber.data = NULL;
				}
		}
	}
}
}