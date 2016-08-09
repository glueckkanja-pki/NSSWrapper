#pragma once

#include <certdb.h>
#include <secerr.h>
#include "X509NSSCertificate.h"

using namespace System::Runtime::InteropServices;
using namespace System::Security::Cryptography::X509Certificates;

#define DEFAULT_PKCS12_PASSWORD "password"
#define DEFAULT_PKCS12_PASSWORD_UNICODE L"password"

//delegate void DelegatePKCS12Output(void *arg, const char *buf, unsigned long len);

inline void append2Buffer_callback(void *arg, const char *buf, unsigned long len)
{
	array<Byte> ^baTemp;
	CHARARRAY_2_NETBYTEARRAY( const_cast<char *>(buf), len, baTemp);
	GK::NSSWrapper::X509NSSCertificate::dictOutputBuffers[*reinterpret_cast<Guid*>(arg)]->Write(baTemp, 0, len);
}

inline PRTime DateTime2PRTime(DateTime time2Convert)
{
	TimeSpan x = time2Convert.ToUniversalTime() - DateTime(1970,1,1,0,0,0,DateTimeKind::Utc);
	return x.Ticks / 10;	// PRTime wants the number of microsesonds since 01.01.1970 in UTC
}

inline CERTGeneralName *createOtherGeneralName(PLArenaPool *arena, CERTGeneralNameType type, String ^strText)
{
    CERTGeneralName *name = arena 
                            ? PORT_ArenaZNew(arena, CERTGeneralName)
	                    : PORT_ZNew(CERTGeneralName);
	name->type = type;
	name->l.prev = name->l.next = &name->l;

	char **caGeneralText = reinterpret_cast<char**>(&name->name.other.data);
	NETSTRING_2_CHARSTRING(strText, *caGeneralText);
	name->name.other.len = strText->Length;
	
	return name;
}

inline void freeOtherGeneralName(CERTGeneralName *name)
{
	delete[] name->name.other.data;
	//PORT_Free(name);		// doesn't work, as it was allocated in an arena
}

	// this function will be called, if there are two certificates with the same
	// nickname. As we work only with databases, if we have to, this should never
	// happen.
inline SECItem * PR_CALLBACK resolveNicknameCollision(SECItem *strOldNickname, PRBool *fCancel, void *arenaPool)
{
	String ^strNewNickname = System::Guid::NewGuid().ToString();
	char *caNewNickname;
	NETSTRING_2_CHARSTRING(strNewNickname,caNewNickname)

	SECItem *siNewNickname = SECITEM_AllocItem(NULL,NULL,strNewNickname->Length);
	siNewNickname->type = siAsciiString;
	strcpy_s(reinterpret_cast<char*>(siNewNickname->data),siNewNickname->len,caNewNickname);

	delete[] caNewNickname;

	return siNewNickname;
}

inline void switchUnicodeEndian(wchar_t *strUnicodeString)
{
	for(int i = wcslen(strUnicodeString)-1;i>=0;--i)
	{
		char firstChar = reinterpret_cast<char*>(&strUnicodeString[i])[0];
		reinterpret_cast<char*>(&strUnicodeString[i])[0] = reinterpret_cast<char*>(&strUnicodeString[i])[1];
		reinterpret_cast<char*>(&strUnicodeString[i])[1] = firstChar;
	}
}

inline void addCDP2Handle(PLArenaPool *nssArena, void *opaqueCertHandle, IList<System::String ^> ^colCDPs)
{
	SECItem siCDP;
	siCDP.data = NULL;
	siCDP.len = 0;
	CERTCrlDistributionPoints ccdp;
	ccdp.distPoints = new CRLDistributionPoint*[colCDPs->Count + 1];

	for (int i = 0; i<colCDPs->Count; ++i)
	{
		ccdp.distPoints[i] = new CRLDistributionPoint();
		memset(ccdp.distPoints[i],0,sizeof(CRLDistributionPoint));
		ccdp.distPoints[i]->distPointType = generalName;
		ccdp.distPoints[i]->distPoint.fullName = createOtherGeneralName(nssArena, certURI, colCDPs[i]);
	}
	ccdp.distPoints[colCDPs->Count] = NULL;	// Terminator
	SECStatus stat = CERT_EncodeCRLDistributionPoints(nssArena,&ccdp,&siCDP);
	stat = CERT_AddExtension(opaqueCertHandle, SEC_OID_X509_CRL_DIST_POINTS, &siCDP, PR_FALSE, PR_TRUE);
	// TODO: check stat

		// Memory Access error on the following line. Will be freed with arena instead
	// SECITEM_FreeItem(&siCDP, PR_FALSE);
	for (int i = 0; i<colCDPs->Count; ++i)
	{
		freeOtherGeneralName(ccdp.distPoints[i]->distPoint.fullName);
		ccdp.distPoints[i]->distPoint.fullName = NULL;
		delete ccdp.distPoints[i];
		ccdp.distPoints[i] = NULL;
	}
	delete[] ccdp.distPoints;
	ccdp.distPoints = NULL;
}

inline void addAIA2Handle(PLArenaPool *nssArena, void *opaqueCertHandle, IList<System::String ^> ^colAIAs)
{
	SECItem siAIA;
	siAIA.data = NULL;
	siAIA.len = 0;
	CERTAuthInfoAccess **caia = new CERTAuthInfoAccess*[colAIAs->Count + 1];
	for (int i = 0; i < colAIAs->Count; ++i)
	{
		caia[i] = new CERTAuthInfoAccess();
		caia[i]->location = createOtherGeneralName(nssArena, certURI, colAIAs[i]);
		caia[i]->method = SECOID_FindOIDByTag(SEC_OID_PKIX_CA_ISSUERS)->oid;
	}
	caia[colAIAs->Count] = NULL;	// Terminator
	SECStatus stat = CERT_EncodeInfoAccessExtension(nssArena,caia,&siAIA);
	stat = CERT_AddExtension(opaqueCertHandle, SEC_OID_X509_AUTH_INFO_ACCESS, &siAIA, PR_FALSE, PR_TRUE);
	// TODO: check stat

	for (int i = 0; i < colAIAs->Count; ++i)
	{
		freeOtherGeneralName(caia[i]->location);
		caia[i]->location = NULL;
		delete caia[i];
	}
	delete[] caia;
}

inline array<Byte> ^signCertificate(PRArenaPool *arena, CERTCertificate *cert, SECKEYPrivateKey *keyCAPrivate)
{
	if (NULL == arena)
		throw gcnew ArgumentNullException("arena", "Certificate signatures are only possible with a memory arena");

	SECOID_SetAlgorithmID(arena, &cert->signature, SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION, NULL);

	SECItem unsignedNewCert;
	unsignedNewCert.len = 0;
	unsignedNewCert.data = NULL;

	SECItem siSignedNewCertificate;
	siSignedNewCertificate.len = 0;
	siSignedNewCertificate.data = NULL;

		// ASN.1 encode unsigned certificate
	const SEC_ASN1Template *unsignedCertASN1 = SEC_ASN1_GET(CERT_CertificateTemplate);
	SEC_ASN1EncodeItem(arena, &unsignedNewCert, cert, unsignedCertASN1);

	SECStatus stat = SEC_DerSignData(
		arena,										// NSSArena in which the signed data will be allocated
		&siSignedNewCertificate,					// binary signed certificate as SECItem
		unsignedNewCert.data,						// binary unsigned certificate
		unsignedNewCert.len,						// length of unsigned binary certificate
		keyCAPrivate,								// private Key of CA
		SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION);	// Which algorithm will be used for signing? (also set in SECOID_SetAlgorithmID above!)
	
		// Convert binary certificate from char array to .NET byte array
	IntPtr ^binaryNewCertificate = gcnew IntPtr(reinterpret_cast<void *>(siSignedNewCertificate.data));
	array<Byte> ^baNewCertificate = gcnew array<Byte>(siSignedNewCertificate.len);
	Marshal::Copy(*binaryNewCertificate,baNewCertificate,0,siSignedNewCertificate.len);
	delete binaryNewCertificate;	// speeds up GC

	return baNewCertificate;
}

inline CERTCertificate *createNssCertificate(
	PRArenaPool *arena,
	System::Security::Cryptography::X509Certificates::X500DistinguishedName ^subjectName, 
	System::Security::Cryptography::X509Certificates::X500DistinguishedName ^issuerName, 
	DateTime notBefore, 
	DateTime notAfter, 
	SECKEYPublicKey *keyPublic)
{
	if (DateTime::Compare(notBefore, notAfter) >= 0)	// negative timespan, notBefore is not earlier than notAfter
		throw gcnew ArgumentOutOfRangeException("notAfter", notAfter, "Certificate expires before or at its start of validity (notBefore is later or equal to notAfter)");

	CERTCertificateRequest *certReq = NULL;
	CERTSubjectPublicKeyInfo *spkiPubKey = NULL;
	CERTName nameSubject;
	nameSubject.arena = NULL;
	nameSubject.rdns = NULL;
	CERTName nameIssuer;
	nameIssuer.arena = NULL;
	nameIssuer.rdns = NULL;

	CERTValidity *validity = NULL;

	try
	{
		SECItem siSubject;		// this is not deallocated as it causes Arena <-> Memory errors
		siSubject.data = NULL;
		siSubject.len = 0;

		SECITEM_AllocItem(arena, &siSubject, subjectName->RawData->Length);
		System::Runtime::InteropServices::Marshal::Copy(subjectName->RawData, 0, System::IntPtr(siSubject.data), subjectName->RawData->Length);
		SEC_ASN1DecodeItem(arena, &nameSubject, CERT_NameTemplate, &siSubject);

		SECItem siIssuer;		// this is not deallocated as it causes Arena <-> Memory errors
		siIssuer.data = NULL;
		siIssuer.len = 0;

		SECITEM_AllocItem(arena, &siIssuer, issuerName->RawData->Length);
		System::Runtime::InteropServices::Marshal::Copy(issuerName->RawData, 0, System::IntPtr(siIssuer.data), issuerName->RawData->Length);
		SEC_ASN1DecodeItem(arena, &nameIssuer, CERT_NameTemplate, &siIssuer);

		validity = CERT_CreateValidity(DateTime2PRTime(notBefore),DateTime2PRTime(notAfter));
		ASSERT_NSS_NOTNULL(validity, "Could not create validity for certificate");
		spkiPubKey = SECKEY_CreateSubjectPublicKeyInfo(keyPublic);

		certReq = CERT_CreateCertificateRequest(&nameSubject,spkiPubKey,NULL);
//		*(certReq->version.data) = (unsigned char)0x02;

					// Random Serial will be overriden afterwards, because the function
					// CERT_CreateCertificate expects a long int as a parameter
					// and that's too short in many cases.
		CERTCertificate *certNew = CERT_CreateCertificate(System::Random::Random().Next(), &nameIssuer, validity, certReq);
		*(certNew->version.data) = (unsigned char)0x02;
		return certNew;
	}
	finally
	{
		CHECK_NULL_AND_FREE(CERT_DestroyCertificateRequest, certReq);
		CHECK_NULL_AND_FREE(CERT_DestroyValidity, validity);
		CHECK_NULL_AND_FREE(SECKEY_DestroySubjectPublicKeyInfo, spkiPubKey);
	}
}

inline CERTCertificate *forceImportCertificate(PRArenaPool *arena, unsigned char *bufCert, int lenBufCert, CERTCertificate *certUnimportedClone)
{
	SECItem siCertificate;
	siCertificate.data = bufCert;
	siCertificate.len = lenBufCert;

	PRArenaPool *arenaLocal = arena;
	if (NULL == arenaLocal)
		arenaLocal = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	try
	{
		CERTCertificate *nssCert = CERT_DecodeCertFromPackage(reinterpret_cast<char *>(siCertificate.data), siCertificate.len);
		if (NULL == nssCert)	// An error occurred
		{
			int iPortError = PR_GetError();
			if (SEC_ERROR_REUSED_ISSUER_AND_SERIAL == iPortError)	// Same cert already exists from a previous operation,
			{														// the old certificate will be deleted before continuing
				CERTIssuerAndSN *iasDummyCa = CERT_GetCertIssuerAndSN(arena, certUnimportedClone);		// Freed by arena
				SECStatus stat = CERT_IssuerNameFromDERCert(&siCertificate, &iasDummyCa->derIssuer);	// derIssuer is empty usually :-(
				ASSERT_NSS_SUCCESS(stat, "Issuer could not be retrieved from temporary certificate");
				PK11SlotInfo *slotTemp = NULL;
				CERTCertificate *oldCert = PK11_FindCertByIssuerAndSN(&slotTemp, iasDummyCa, NULL);
				CHECK_NULL_AND_FREE(PK11_FreeSlot, slotTemp);
				ASSERT_NSS_NOTNULL(oldCert, "Certificate could not be imported because a certificate with same issuer/serial already exists in the temporary store. Still, this certificate could not be found for deletion");
				SEC_DeletePermCertificate(oldCert);
				//PK11_DeleteTokenCertAndKey(oldCert, NULL);
				nssCert = CERT_DecodeCertFromPackage(reinterpret_cast<char *>(siCertificate.data), siCertificate.len);
			}
		}
		return nssCert;
	}
	finally
	{
		if (NULL == arena && NULL != arenaLocal)
		{
			PORT_FreeArena(arenaLocal, false);
			arenaLocal = NULL;
		}
	}
}

static void append2Buffer_pkcs12callback(void *arg, const char *buf, unsigned long len)
{
	
}

inline array<Byte> ^savePFX(CERTCertificate *cert, PK11SlotInfo *slot, CERTCertDBHandle *handleCertDB)
{
	SEC_PKCS12ExportContext *p12ExportCtx = NULL;
	SEC_PKCS12SafeInfo *p12SafeUnencrypted = NULL, *p12SafeEncrypted = NULL;

	Guid idOutput = Guid::Empty;

	SECStatus stat = SECFailure;

	SECItem itemPassword;
	itemPassword.data = NULL;
	itemPassword.len = 0;

	try
	{
				// package to PKCS#12
		stat = PK11_ImportCert(slot, cert, NULL, NULL, PR_FALSE);
		ASSERT_NSS_SUCCESS(stat, "Could not import unedited certificate into key slot");
		p12ExportCtx = SEC_PKCS12CreateExportContext(NULL, NULL, slot, NULL);
		ASSERT_NSS_NOTNULL(p12ExportCtx, "Could not create NSS export context");
		
		itemPassword.data = reinterpret_cast<unsigned char*>( strdup(DEFAULT_PKCS12_PASSWORD) );
		itemPassword.len = sizeof(DEFAULT_PKCS12_PASSWORD);

		stat = SEC_PKCS12AddPasswordIntegrity(p12ExportCtx, &itemPassword, SEC_OID_SHA1);
		ASSERT_NSS_SUCCESS(stat, "NSS could not encrypt inner PKCS#12 safebag");
		p12SafeUnencrypted = SEC_PKCS12CreateUnencryptedSafe(p12ExportCtx);
		ASSERT_NSS_NOTNULL(p12SafeUnencrypted, "NSS error: The unencrypted PKCS#12 safebag could not be created");
		p12SafeEncrypted = SEC_PKCS12CreatePasswordPrivSafe(p12ExportCtx, &itemPassword, SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC);
		ASSERT_NSS_NOTNULL(p12SafeEncrypted, "NSS error: The encrypted PKCS#12 safebag could not be created");
		stat = SEC_PKCS12AddCertAndKey(
			p12ExportCtx,												// Export context
			p12SafeUnencrypted,											// unencrypted Safebag
			NULL,
			cert,										// Certificate
			handleCertDB,
			p12SafeEncrypted,											// encrypted Safebag
			NULL,
			PR_TRUE,
			&itemPassword,												// Again the password
			SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC);	// Algorithm for the password encryption, nothing better seems to be available in NSS
		ASSERT_NSS_SUCCESS(stat, "NSS could not add a certificate + private to the PKCS#12 package");

		idOutput = Guid::NewGuid();
		GK::NSSWrapper::X509NSSCertificate::dictOutputBuffers[idOutput] = gcnew System::IO::MemoryStream(500);
//		IntPtr callback = System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(gcnew DelegatePKCS12Output(&GK::NSSWrapper::X509NSSCertificate::append2Buffer_callback));
		stat = SEC_PKCS12Encode(
			p12ExportCtx,				// data context for the PKCS#12
										// this function will be called several times to save all data chunks
			//reinterpret_cast<SEC_PKCS12EncoderOutputCallback>(callback.ToPointer()),
			append2Buffer_callback,
			&idOutput);					// a parameter for the callback
		ASSERT_NSS_SUCCESS(stat, "NSS problem when encoding PKCS12");

		return ((System::IO::MemoryStream^)GK::NSSWrapper::X509NSSCertificate::dictOutputBuffers[idOutput])->GetBuffer();
	}
	finally
	{
			if (Guid::Empty != idOutput)
			{
				GK::NSSWrapper::X509NSSCertificate::dictOutputBuffers->Remove(idOutput);
				idOutput = Guid::Empty;
			}
			CHECK_NULL_AND_FREE(SEC_PKCS12DestroyExportContext, p12ExportCtx);
			CHECK_NULL_AND_FREE(delete[], itemPassword.data);
	}
}

inline PK11SlotInfo *getDefaultSlot()
{
	SECStatus stat = SECFailure;
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();

	if(PK11_NeedLogin(slot))			// Either a password is set on the database or it hasn't been used before
		if(PK11_NeedUserInit(slot))
		{
			stat = PK11_InitPin(slot, NULL, NULL);		// First time use: Set password to nothing
			ASSERT_NSS_SUCCESS(stat, "Error initializing database with an empty password");
		}
		else
			ASSERT_NSS_SUCCESS(SECFailure, "Mozilla Cert DB has a password set on it. This doesn't work. Use a DB without password.");

	return slot;
}

