#include "StdAfx.h"
#include "X509NSSCertificate.h"

#include "NSSDatabase.h"

#include <nss.h>
#include <ssl.h>
#include <keyhi.h>
#include <cryptohi.h>
#include <p12.h>
#include <p12plcy.h>
#include <pk11pub.h>
#include <secmod.h>
#include <secerr.h>

#include "NSSInlineFunctions.h"
#include "ASN\ASNObject.h"
#include "ASN\DERSequence.h"
#include "ASN\DEROid.h"

struct PK11SlotInfoStr {};				// not linked with NSS libs, only used as pointer
struct SEC_PKCS12SafeInfoStr {};		// not linked with NSS libs, only used as pointer
struct SEC_PKCS12DecoderContextStr {};	// not linked with NSS libs, only used as pointer
struct SEC_PKCS12ExportContextStr {};	// not linked with NSS libs, only used as pointer
struct NSSTrustDomainStr {};			// not linked with NSS libs, only used as pointer

static const SEC_ASN1Template CERTSubjectKeyIDTemplate[] = {
    { SEC_ASN1_OCTET_STRING }
};

using namespace System::Runtime::InteropServices;
using namespace System::Security::Cryptography::X509Certificates;
using namespace GK::NSSWrapper::ASN;

namespace GK
{
namespace NSSWrapper
{
	X509NSSCertificate::X509NSSCertificate(int iKeyLength)
		: X509Certificate2(generateCertificate(iKeyLength), DEFAULT_PKCS12_PASSWORD_UNICODE, X509KeyStorageFlags::Exportable),
		_nssArena(NULL)
	{
		StorageFlags = X509KeyStorageFlags::Exportable;
		initValues();
	}

	X509NSSCertificate::X509NSSCertificate(int iKeyLength, X509KeyStorageFlags flags)
		: X509Certificate2(generateCertificate(iKeyLength), DEFAULT_PKCS12_PASSWORD_UNICODE, flags),
		_nssArena(NULL)
	{
		StorageFlags = flags;
		initValues();
	}

	X509NSSCertificate::X509NSSCertificate(array<Byte> ^binaryData)
		: X509Certificate2(binaryData), _nssArena(NULL)
	{
		StorageFlags = X509KeyStorageFlags::Exportable;
		initValues();
	}

	X509NSSCertificate::X509NSSCertificate(array<Byte> ^binaryData, System::String ^password)
	: X509Certificate2(binaryData, password, X509KeyStorageFlags::Exportable), _nssArena(NULL)
	{
		StorageFlags = X509KeyStorageFlags::Exportable;
		initValues();
	}

	X509NSSCertificate::~X509NSSCertificate()
	{
		this->!X509NSSCertificate();
	}

	X509NSSCertificate::!X509NSSCertificate()
	{
		if (_nssArena)
		{
			System::Threading::Monitor::Enter(objDestructionLock);
			if (_nssArena)
			{
				PORT_FreeArena(_nssArena, false);
				_nssArena = NULL;
				PL_ArenaFinish();
			}
			System::Threading::Monitor::Exit(objDestructionLock);
		}
	}

	void X509NSSCertificate::initValues()
	{
		objDestructionLock = gcnew Object();

		_SubjectName = nullptr;
		_IssuerName = nullptr;
		_SerialNumber = nullptr;
		_NotBefore = DateTime::MinValue;
		_NotAfter = DateTime::MinValue;

		basicConstraints = nullptr;
		_authorityKeyIdentifier = nullptr;
		fIsChangedSubjectKeyIdentifier = false;
		fIsChangedSMIMECapabilities = false;

		_colCDPs = gcnew System::Collections::Generic::List<String ^>();
		_colAIAs = gcnew System::Collections::Generic::List<String ^>();
		_colSANs = gcnew System::Collections::Generic::List<String ^>();
		_colSMIMECapabilities = gcnew System::Collections::Generic::List<SMIMECapability ^>();
	}

	array<Byte> ^X509NSSCertificate::subjectKeyIdentifier::get()
	{
		if (!fIsChangedSubjectKeyIdentifier)
		{
			_subjectKeyIdentifier = nullptr;
			for each(X509Extension ^extCurrent in Extensions)
				if (extCurrent->GetType() == X509SubjectKeyIdentifierExtension::typeid)
				{
						// we can get the Subject Key Identifier only ASN.1 encoded (RawData property) or
						// as a hexadecadic string. Therefore we must convert it to binary
					System::String ^hexstringSKI = safe_cast<X509SubjectKeyIdentifierExtension^>(extCurrent)->SubjectKeyIdentifier;
					_subjectKeyIdentifier = gcnew array<Byte> (hexstringSKI->Length / 2);	// hex takes twice the space
					for (int i = 0; i < hexstringSKI->Length / 2; ++i)
						_subjectKeyIdentifier[i] = Byte::Parse(hexstringSKI->Substring(i*2,2), 
							System::Globalization::NumberStyles::AllowHexSpecifier);
					break;
				}
			fIsChangedSubjectKeyIdentifier = true;
		}

		return _subjectKeyIdentifier;
	}

	IList<X509NSSCertificate::SMIMECapability ^> ^X509NSSCertificate::colSMIMECapabilities::get()
	{
		if (!fIsChangedSMIMECapabilities)
		{
			_colSMIMECapabilities = nullptr;
			for each(X509Extension ^extCurrent in Extensions)
				if (extCurrent->Oid->Value == "1.2.840.113549.1.9.15")	// this is the smimeCapabilities OBJECT IDENTIFIER
				{
					char *rawSMIMECapabilitiesData;
					NETBYTEARRAY_2_CHARSTRING(extCurrent->RawData, rawSMIMECapabilitiesData);
					DERSequence ^asnSequenceSMIMECaps = dynamic_cast<DERSequence ^>(
						ASNObject::parse(rawSMIMECapabilitiesData, extCurrent->RawData->Length)
					);

					_colSMIMECapabilities = gcnew List<X509NSSCertificate::SMIMECapability ^>(4);

					for each(ASNObject ^asnSmimeCapability in asnSequenceSMIMECaps)
					{
						DERSequence ^seqSmimeCapability = dynamic_cast<DERSequence ^>(asnSmimeCapability);
						if (nullptr == seqSmimeCapability)
							throw gcnew ArgumentException("Could not parse S/MIME Capabilities extension, wrong ASN.1 tag");

						IList<ASNObject^> ^listSmimeCapabilityContent = gcnew List<ASNObject^>(2);
						for each (ASNObject ^asnTemp in seqSmimeCapability)
							listSmimeCapabilityContent->Add(asnTemp);

						SMIMECapability ^currentCapability = gcnew SMIMECapability();

						DEROid ^oidCapability = dynamic_cast<DEROid ^>(listSmimeCapabilityContent[0]);
						currentCapability->oid = gcnew System::Security::Cryptography::Oid(oidCapability->strOidValue);
						if (listSmimeCapabilityContent->Count > 1)	// there are parameters
						{
							unsigned long long lngParameterDataLength = listSmimeCapabilityContent[1]->overallLength;
							if (lngParameterDataLength > static_cast<unsigned long long>(int::MaxValue))
								throw gcnew ArgumentOutOfRangeException("The parameters data in the SMIMECapability extension is much too large to process, its length must fit into an Int32");
							CHARARRAY_2_NETBYTEARRAY(listSmimeCapabilityContent[1]->rawData, static_cast<int>(lngParameterDataLength), currentCapability->parameters);
						}
						else
							currentCapability->parameters = nullptr;

						_colSMIMECapabilities->Add(currentCapability);
					}
					break;
				}
			fIsChangedSMIMECapabilities = true;
		}

		return _colSMIMECapabilities;
	}

	typedef struct {
		SECItem capabilityID;
		SECItem parameters;
	} NSSSMIMECapability;

	static const SEC_ASN1Template NSSSMIMECapabilityTemplate[] = {
		{ SEC_ASN1_SEQUENCE,
		  0, NULL, sizeof(NSSSMIMECapability) },
		{ SEC_ASN1_OBJECT_ID,
		  offsetof(NSSSMIMECapability,capabilityID), },
		{ SEC_ASN1_OPTIONAL | SEC_ASN1_ANY,
		  offsetof(NSSSMIMECapability,parameters), },
		{ 0, }
	};

	static const SEC_ASN1Template NSSSMIMECapabilitiesTemplate[] = {
		{ SEC_ASN1_SEQUENCE_OF, 0, NSSSMIMECapabilityTemplate }
	};

	array<Byte> ^X509NSSCertificate::encodeSMIMECapabilities()
	{
		if (nullptr == colSMIMECapabilities)
			return nullptr;

	    NSSSMIMECapability **aSMIMECapabilities = new NSSSMIMECapability*[colSMIMECapabilities->Count + 1];
		if (NULL == aSMIMECapabilities)
			throw gcnew OutOfMemoryException("Not enough memory when encoding SMIME Capabilities Extension");
		memset(aSMIMECapabilities, NULL, sizeof(NSSSMIMECapability*) * (colSMIMECapabilities->Count + 1));

		try
		{
			for(int capIndex = 0; capIndex < colSMIMECapabilities->Count; ++capIndex)
			{
				aSMIMECapabilities[capIndex] = new NSSSMIMECapability();

				DEROid ^oidCapability = gcnew DEROid(colSMIMECapabilities[capIndex]->oid->Value);
				unsigned long long lngOidDataLength = oidCapability->overallLength;
				if (lngOidDataLength > UInt32::MaxValue)
					throw gcnew ArgumentOutOfRangeException("The SMIMECapability OID to be encoded is larger than UInt32::MaxValue. I refuse to encode that.");
				unsigned int iOidDataLength = static_cast<unsigned int>(lngOidDataLength);

				aSMIMECapabilities[capIndex]->capabilityID.len  = iOidDataLength;
				aSMIMECapabilities[capIndex]->capabilityID.data = new unsigned char[aSMIMECapabilities[capIndex]->capabilityID.len];
				errno_t retError = memcpy_s(
					aSMIMECapabilities[capIndex]->capabilityID.data,		// destination
					aSMIMECapabilities[capIndex]->capabilityID.len,			// destination size
					oidCapability->rawData,									// source
					iOidDataLength);										// number of characters to copy
				if (NULL != retError)
					throw gcnew ExternalException("Could not copy SMIME Capabilities", retError);

				if(nullptr != colSMIMECapabilities[capIndex]->parameters)
				{
					char **bufParameters = reinterpret_cast<char**>(&aSMIMECapabilities[capIndex]->parameters.data);
					NETBYTEARRAY_2_CHARSTRING(colSMIMECapabilities[capIndex]->parameters, *bufParameters);
					aSMIMECapabilities[capIndex]->parameters.len = colSMIMECapabilities[capIndex]->parameters->Length;
				}
				else
				{
					aSMIMECapabilities[capIndex]->parameters.data = NULL;
					aSMIMECapabilities[capIndex]->parameters.len = 0;
				}
			}

			aSMIMECapabilities[colSMIMECapabilities->Count] = NULL;	// Terminator

			SECItem siSMIMECapabilities;
			siSMIMECapabilities.data = NULL;
			siSMIMECapabilities.len = 0;
			SECItem *siDummy = SEC_ASN1EncodeItem(nssArena, &siSMIMECapabilities, &aSMIMECapabilities, NSSSMIMECapabilitiesTemplate);

			ASSERT_NSS_NOTNULL(siDummy, "Could not encode SMIME Capabilities extension");

			array<Byte> ^baSMIMECapabilities;
			CHARARRAY_2_NETBYTEARRAY(siSMIMECapabilities.data, siSMIMECapabilities.len, baSMIMECapabilities);
			return baSMIMECapabilities;
		}
		finally
		{
			for (int capIndex = 0; capIndex < colSMIMECapabilities->Count; ++capIndex)
				if (NULL != aSMIMECapabilities[capIndex])
				{
					CHECK_NULL_AND_FREE(delete[], aSMIMECapabilities[capIndex]->capabilityID.data);
					CHECK_NULL_AND_FREE(delete[], aSMIMECapabilities[capIndex]->parameters.data);

					CHECK_NULL_AND_FREE(delete, aSMIMECapabilities[capIndex]);
				}
			CHECK_NULL_AND_FREE(delete[], aSMIMECapabilities);
		}
	}

	X509NSSAuthorityKeyIdentifierExtension ^X509NSSCertificate::authorityKeyIdentifier::get()
	{
		if (nullptr != _authorityKeyIdentifier)
			return _authorityKeyIdentifier;

		throw gcnew InvalidOperationException("Currently, it is not possible to parse the Authority Key Identifier from a certificate");
	}

	array<Byte> ^X509NSSCertificate::generateCertificate(int iKeyLength)
	{
		NSSDatabase::initialize();

		PRArenaPool *arena = NULL;
		PK11SlotInfo *slot = NULL;
		SECKEYPublicKey *keyPublic = NULL;
		SECKEYPrivateKey *keyPrivate = NULL;
		CERTCertificate *nssUnsignedCertificate = NULL;
		CERTCertificate *nssSignedCertificate = NULL;
		CERTCertDBHandle *handleCertDB = NULL;		// Not necessary to be freed (?)
		SECStatus stat = SECFailure;

		SECItem siSignedCertificate;
		siSignedCertificate.data = NULL;
		siSignedCertificate.len = 0;

		PK11RSAGenParams paramsRSA;
		paramsRSA.keySizeInBits = iKeyLength;
		paramsRSA.pe = 0x10001;

		try
		{
			arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE); 

			handleCertDB = CERT_GetDefaultCertDB();
			slot = getDefaultSlot();

				// Generate RSA key pair
			keyPrivate = PK11_GenerateKeyPair(
				slot,							// Where will the key pair be saved?
				CKM_RSA_PKCS_KEY_PAIR_GEN,		// What kind of key will be generated?
				&paramsRSA,						// Key size
				&keyPublic,						// The public part will be written here
				PR_TRUE,						// Must be permanent, otherwise it can't be exported later :-(
				PR_FALSE,
				NULL);

			if (NULL == keyPublic || NULL == keyPrivate)
				throw gcnew ExternalException("The RSA key pair could not be generated", PR_GetError());

				// Sign a certificate				
			nssUnsignedCertificate = createNssCertificate(
				arena,
				gcnew System::Security::Cryptography::X509Certificates::X500DistinguishedName("CN=Dummy Cert"), 
				gcnew System::Security::Cryptography::X509Certificates::X500DistinguishedName("CN=Dummy CA - Will be deleted"), 
				DateTime::Now, 
				DateTime::Now.AddSeconds(1), 
				keyPublic);
			array<Byte> ^baCertificate = signCertificate(arena, nssUnsignedCertificate, keyPrivate);
			char **bufSignedCertificate = reinterpret_cast<char**>(&siSignedCertificate.data);
			NETBYTEARRAY_2_CHARSTRING(baCertificate, *bufSignedCertificate);
			siSignedCertificate.len = baCertificate->Length;

			nssSignedCertificate = forceImportCertificate(arena, siSignedCertificate.data, siSignedCertificate.len, nssUnsignedCertificate);
			ASSERT_NSS_NOTNULL(nssSignedCertificate, "NSS could not decode newly generated certificate");

			return savePFX(nssSignedCertificate,slot,handleCertDB);
		}
		finally
		{
			if (NULL != nssSignedCertificate)
			{
				PK11_DeleteTokenCertAndKey(nssSignedCertificate, NULL);
				nssSignedCertificate = NULL;
			}
			if (NULL != keyPrivate)	// this is probably redundant, the previous function deletes the private, too
			{
				PK11_DeleteTokenPrivateKey(keyPrivate, PR_TRUE);
				keyPrivate = NULL;
			}
			CHECK_NULL_AND_FREE(PK11_FreeSlot, slot);
			CHECK_NULL_AND_FREE(CERT_DestroyCertificate, nssUnsignedCertificate);
			CHECK_NULL_AND_FREE(delete[], siSignedCertificate.data);
			CHECK_NULL_AND_FREE(SECKEY_DestroyPublicKey, keyPublic);
			if (arena)
			{
				PORT_FreeArena(arena, false);
				arena = NULL;
			}
		}
	}

	array<Byte> ^X509NSSCertificate::exportAsPKCS10()
	{
		CERTCertificate *certOriginal = NULL;
		CERTCertificateRequest *certReq = NULL;

		try
		{
			certOriginal = nssCertificate;

				// create PKCS#10
			certReq = CERT_CreateCertificateRequest(&certOriginal->subject,&certOriginal->subjectPublicKeyInfo,NULL);
			ASSERT_NSS_NOTNULL(certReq,"Could not generate certificate request with NSS");

			//	// add email addresses as subject alternative names
			//void *extHandle = cert_StartExtensions(certReq);
			//SECITEM rfc822Name;
			//SECITEM_AllocItem(NULL,&rfc822Name,0);
			//stat = CERT_EncodeAltNameExtension(NULL, CERTGeneralName *value, &rfc822Name);
			//stat = CERT_AddExtension(extHandle,SEC_OID_X509_SUBJECT_ALT_NAME,&rfc822Name,PR_FALSE,PR_FALSE);
			//stat = CERT_FinishCertificateRequestAttributes(certReq);

			SECItem unsignedRequest;
			unsignedRequest.len = 0;
			unsignedRequest.data = NULL;
			const SEC_ASN1Template *pkcs10ASN1 = SEC_ASN1_GET(CERT_CertificateRequestTemplate);
			SEC_ASN1EncodeItem(nssArena, &unsignedRequest, certReq, pkcs10ASN1);

				// sign the PKCS#10
			SECItem signedRequest;
			signedRequest.len = 0;
			signedRequest.data = NULL;
			SECStatus stat = SEC_DerSignData(nssArena, &signedRequest, unsignedRequest.data, unsignedRequest.len, nssPrivateKey, SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION);
			ASSERT_NSS_SUCCESS(stat, "Could not sign certificate request with NSS");

				// Convert C binary data (NSS represenatation) to .NET string in Base64 with headers
//			String ^pkcs10Start = gcnew String(L"-----BEGIN CERTIFICATE REQUEST-----\n");
			IntPtr ^signedReqData = gcnew IntPtr(reinterpret_cast<void *>(signedRequest.data));
			array<Byte> ^managedRequest = gcnew array<Byte>(signedRequest.len);
			Marshal::Copy(*signedReqData,managedRequest,0,signedRequest.len);
			return managedRequest;
			//return String::Concat(pkcs10Start, Convert::ToBase64String(managedRequest), L"\n-----END CERTIFICATE REQUEST-----");
		}
		finally
		{
			CHECK_NULL_AND_FREE(CERT_DestroyCertificateRequest, certReq)
			// TODO: Free unsignedRequest and signedRequest
		}
	}

	void X509NSSCertificate::generateSKIFromPublicKey()
	{
			// Compute Subject Key Identifier as described in RFC 3280, section 4.2.1.2, method (1):
			// 160-bit SHA1 hash of the subjectPublicKey
		subjectKeyIdentifier =
			(gcnew System::Security::Cryptography::SHA1Managed())->ComputeHash(
			this->PublicKey->EncodedKeyValue->RawData);
	}

	void X509NSSCertificate::reCertify(X509NSSCertificate ^caCert)
	{
		if (!caCert->HasPrivateKey)
			throw gcnew ArgumentException("No private key available for the CA certificate. Certification not possible...","caCert");

		NSSDatabase::initialize();

		CERTCertificate *certPublic = NULL;
		SECKEYPrivateKey *privCA = NULL;

		try
		{
			certPublic = nssCertificate;
			privCA = caCert->nssPrivateKey;

				// sign certificate
			array<Byte> ^baNewCertificate = signCertificate(nssArena, certPublic, privCA);

				// update this object to reflect changes
			if (!this->HasPrivateKey)
				this->Import(baNewCertificate);
			else
				this->mergeChangedCertificate(baNewCertificate);
		}
		finally
		{
			CHECK_NULL_AND_FREE(CERT_DestroyCertificate, certPublic);
			CHECK_NULL_AND_FREE(SECKEY_DestroyPrivateKey,privCA);
		}
	}

	void X509NSSCertificate::mergeChangedCertificate(array<Byte> ^baNewCertificate)
	{
		NSSDatabase::initialize();

		PK11SlotInfo *slot = NULL;
		CERTCertificate *nssCert = NULL;
		CERTCertDBHandle *handleCertDB = NULL;		// Not necessary to be freed (?)
		SECKEYPrivateKey *keyPrivate = NULL;

		try
		{
			handleCertDB = CERT_GetDefaultCertDB();
			slot = getDefaultSlot();
			keyPrivate = this->nssPrivateKey;		// this is only used for storing the private in the NSS slot

			char *bufCert;
			NETBYTEARRAY_2_CHARSTRING(baNewCertificate, bufCert);
			nssCert = forceImportCertificate(
				NULL,										// NSS arena
				reinterpret_cast<unsigned char*>(bufCert),	// certificate binary data
				baNewCertificate->Length,					// certificate binary data length
				nssCertificate);							// CERTCertificate with same issuer/serial
			delete[] bufCert;
			ASSERT_NSS_NOTNULL(nssCert, "NSS could not decode newly recertified certificate");

			this->Import(
				savePFX(nssCert,slot,handleCertDB),
				DEFAULT_PKCS12_PASSWORD,
				StorageFlags);

			initValues();
		}
		finally
		{
			if (NULL != nssCert)
			{
				PK11_DeleteTokenCertAndKey(nssCert, NULL);
				nssCert = NULL;
			}
			//else if (NULL != keyPrivate)
			//{
			//	PK11_DeleteTokenPrivateKey(keyPrivate, PR_TRUE);
			//	keyPrivate = NULL;
			//}
			CHECK_NULL_AND_FREE(SECKEY_DestroyPrivateKey,keyPrivate);
			CHECK_NULL_AND_FREE(PK11_FreeSlot, slot);
		}
	}

	CERTCertificate *X509NSSCertificate::nssCertificate::get()
	{
		NSSDatabase::initialize();

		CERTCertificate *oldCert = NULL, *newCert = NULL;
		SECKEYPublicKey *pubKey = NULL;
		SECItem *siSerial = NULL;

		try
		{
				// Open this (unchanged) certificate with NSS
			array<Byte> ^binCert = GetRawCertData();
			char *bufCert;
			NETBYTEARRAY_2_CHARSTRING(binCert, bufCert);
			oldCert = CERT_DecodeCertFromPackage(bufCert,binCert->Length);
			delete[] bufCert;
			ASSERT_NSS_NOTNULL(oldCert, "Could not decode certificate");

				// create new CERTCertificate and copy important values
			pubKey = CERT_ExtractPublicKey(oldCert);

			newCert = createNssCertificate(nssArena, SubjectName, IssuerName, NotBefore, NotAfter, pubKey);

					// set v3 extensions
			void *extHandler = CERT_StartCertExtensions(newCert);
			SECStatus stat = SECFailure;

			if (nullptr != subjectKeyIdentifier)
			{
					// Create SECItem siPublicKeyHash from .NET value subjectKeyIdentifier
				SECItem siPublicKeyHash;
				siPublicKeyHash.data = NULL;
				siPublicKeyHash.len = 0;
				char **ptrSecItem = reinterpret_cast<char **>(&siPublicKeyHash.data);
				NETBYTEARRAY_2_CHARSTRING(subjectKeyIdentifier, *ptrSecItem);
				siPublicKeyHash.len = subjectKeyIdentifier->Length;

					// Create SECItem siSubjectKeyID with encoded Subject Key Identifier
				SECItem siSubjectKeyID;
				siSubjectKeyID.data = NULL;
				siSubjectKeyID.len = 0;
				void *ptrResult = SEC_ASN1EncodeItem(nssArena, &siSubjectKeyID, &siPublicKeyHash, CERTSubjectKeyIDTemplate);
				
				delete[] siPublicKeyHash.data;
				siPublicKeyHash.data = NULL;
				siPublicKeyHash.len = 0;

				ASSERT_NSS_NOTNULL(ptrResult, "Could not encode Subject Key Identifier");
				stat = CERT_AddExtension(extHandler,SEC_OID_X509_SUBJECT_KEY_ID,&siSubjectKeyID,PR_FALSE,PR_TRUE);
			}

						// Set Authority Key Identifier
			if (nullptr != _authorityKeyIdentifier)
				_authorityKeyIdentifier->add2OpaqueHandle(nssArena, extHandler);

						// Set CDP
			if (colCDPs->Count > 0)
				addCDP2Handle(nssArena, extHandler, colCDPs);

						// Set AIA
			if (colAIAs->Count > 0)
				addAIA2Handle(nssArena, extHandler, colAIAs);

						// Set Subject Alternative Name
			if (colSANs->Count > 0)
			{
				SECItem siSAN;
				siSAN.data = NULL;
				siSAN.len = 0;
					
					// create an array of CERTGeneralNames
				CERTGeneralName **nameUnconcatSANs = new CERTGeneralName*[colSANs->Count];
				for (int i = 0; i < colSANs->Count; ++i)
					nameUnconcatSANs[i] = createOtherGeneralName(nssArena, certRFC822Name, colSANs[i]);
						// Link names together in their contained double linked ring-list
				for (int i = 0; i < colSANs->Count; ++i)
				{
					nameUnconcatSANs[i]->l.next = &nameUnconcatSANs[(i+1) % colSANs->Count]->l;
					nameUnconcatSANs[i]->l.prev = &nameUnconcatSANs[(i==0)?colSANs->Count-1:i-1]->l;
				}
						// define a linked list of CERTGeneralNames
				CERTGeneralName *cgnSAN = nameUnconcatSANs[0];

					// Encode the list of CERTGeneralNames as AltName siSAN
				stat = CERT_EncodeAltNameExtension(nssArena,cgnSAN,&siSAN);
				
					// free CERTGeneralNames structure
				for (int i = 0; i < colSANs->Count; ++i)
					freeOtherGeneralName(nameUnconcatSANs[i]);
				delete[] nameUnconcatSANs;

					// Add AltName siSAN to the list of extensions
				stat = CERT_AddExtension(extHandler, SEC_OID_X509_SUBJECT_ALT_NAME, &siSAN, PR_FALSE, PR_TRUE);

					// free encoded AltName
				//SECITEM_FreeItem(&siSAN, false);
			}

			if (nullptr != basicConstraints)
			{
				SECItem siBasicConstraints;
				siBasicConstraints.data = NULL;
				siBasicConstraints.len = 0;

				CERTBasicConstraints bcVal;
				bcVal.pathLenConstraint = basicConstraints->pathLen<0?CERT_UNLIMITED_PATH_CONSTRAINT:basicConstraints->pathLen;
				bcVal.isCA = basicConstraints->fIsCA;

				CERT_EncodeBasicConstraintValue(nssArena, &bcVal, &siBasicConstraints);
				stat = CERT_AddExtension(extHandler, SEC_OID_X509_BASIC_CONSTRAINTS, &siBasicConstraints, PR_TRUE, PR_TRUE);
			
					// SECITEM_FreeItem, again, triggers a memory access error. This is not as bad as it seems, as the memory
					// was allocated via an arena and therefore is freed anyway at some time
				//SECITEM_FreeItem(&siBasicConstraints, false);
			}

			if (nullptr != colSMIMECapabilities)
			{
				SECItem siSMIMECaps;
				siSMIMECaps.data = NULL;
				siSMIMECaps.len = 0;

				array<Byte> ^encodedSmimeCaps = encodeSMIMECapabilities();
				char **ptrSecItem = reinterpret_cast<char **>(&siSMIMECaps.data);
				NETBYTEARRAY_2_CHARSTRING(encodedSmimeCaps, *ptrSecItem);
				siSMIMECaps.len = encodedSmimeCaps->Length;

				stat = CERT_AddExtension(extHandler, SEC_OID_PKCS9_SMIME_CAPABILITIES, &siSMIMECaps, PR_FALSE, PR_TRUE);
			}

			//if (nullptr != )
			//{
			//	SECItem siKeyUsage;
			//	siKeyUsage.data = NULL;
			//	siKeyUsage.len = 0;
			//
			// int intKeyUsage = 17;
			// stat = CERT_EncodeAndAddExtension(extHandler, SEC_OID_X509_KEY_USAGE, &intKeyUsage, PR_TRUE, 
			//	stat = CERT_AddExtension(extHandler, , &siKeyUsage, PR_TRUE, PR_TRUE);
			//}

						// TODO: Set Key Usage, Extended Key Usage

			stat = CERT_FinishExtensions(extHandler);

			if (nullptr != SerialNumber)
			{
				siSerial = new SECItem();
				siSerial->len = SerialNumber->Length / 2;
				siSerial->data = new unsigned char[siSerial->len];
					// SerialNumber is a hex string that will be decoded to siSerial->data
				for (unsigned int i = 0; i < siSerial->len; ++i)
					siSerial->data[i] = Convert::ToByte(SerialNumber->Substring(2*i,2), 16);

					// editing the cert directly with SECITEM_CopyItem is evil as it is meant as a reference, not a pointer.
					// The old data probably just leaks away
				SECITEM_CopyItem(nssArena, &newCert->serialNumber, siSerial);
			}
			else
					// editing the cert directly with SECITEM_CopyItem is evil as it is meant as a reference, not a pointer.
					// The old data probably just leaks away
				SECITEM_CopyItem(nssArena, &newCert->serialNumber, &oldCert->serialNumber);

			return newCert;
		}
		finally
		{
			CHECK_NULL_AND_FREE(CERT_DestroyCertificate, oldCert);
			CHECK_NULL_AND_FREE(SECKEY_DestroyPublicKey, pubKey);
			if (NULL != siSerial)
			{
				CHECK_NULL_AND_FREE(delete[], siSerial->data);
			}
			CHECK_NULL_AND_FREE(delete, siSerial);
		}
	}

	SECKEYPrivateKey *X509NSSCertificate::nssPrivateKey::get()
	{
		if (!HasPrivateKey)
			throw gcnew InvalidOperationException("This certificate doesn't have a private key that could be converted to NSS format");

		NSSDatabase::initialize();

		array<System::Byte> ^binCert;
		char *bufCert = NULL;
		SECStatus stat;

		SECItem *siPassword = NULL;
		PK11SlotInfo *slot = NULL;
		SEC_PKCS12DecoderContext *decoderPkcs12 = NULL;
		CERTCertList *listCerts = NULL;

			// These passwords are used only within the function. A PKCS#12 file
			// will be temporarily created and encrypted with the following password
		String ^netPkcs12Password = DEFAULT_PKCS12_PASSWORD;
		wchar_t *pkcs12Password = DEFAULT_PKCS12_PASSWORD_UNICODE;

			// create PKCS#12 binary data
		binCert = Export(X509ContentType::Pkcs12, netPkcs12Password);
		NETBYTEARRAY_2_CHARSTRING(binCert, bufCert);
		try
		{
				// prepare Password structure
			int lenPW = wcslen(pkcs12Password) + 1;	// include NULL terminator
			siPassword = SECITEM_AllocItem(nssArena, NULL, sizeof(wchar_t) * lenPW);
			wcscpy_s(reinterpret_cast<wchar_t *>(siPassword->data), lenPW, pkcs12Password);
			switchUnicodeEndian(reinterpret_cast<wchar_t*>(siPassword->data));

				// decode keys in NSS to database
			slot = getDefaultSlot();

			decoderPkcs12 = SEC_PKCS12DecoderStart(siPassword,slot,NULL,NULL,NULL,NULL,NULL,NULL);
			stat = SEC_PKCS12DecoderUpdate(decoderPkcs12,reinterpret_cast<unsigned char*>(bufCert),binCert->Length);
			ASSERT_NSS_SUCCESS(stat, "SEC_PKCS12DecoderUpdate failed");
			stat = SEC_PKCS12DecoderVerify(decoderPkcs12);
			ASSERT_NSS_SUCCESS(stat, "SEC_PKCS12DecoderVerify failed");
			stat = SEC_PKCS12DecoderValidateBags(decoderPkcs12, resolveNicknameCollision);
			ASSERT_NSS_SUCCESS(stat, "SEC_PKCS12DecoderValidateBags failed");
			stat = SEC_PKCS12DecoderImportBags(decoderPkcs12);
			ASSERT_NSS_SUCCESS(stat, "SEC_PKCS12DecoderImportBags failed");

				// extract private key of first certificate from PKCS#12
			listCerts = SEC_PKCS12DecoderGetCerts(decoderPkcs12);
			CERTCertificate *certTop = CERT_LIST_HEAD(listCerts)->cert;
			SECKEYPrivateKey *nssPrivKey = PK11_FindPrivateKeyFromCert(slot, certTop, NULL);

			return nssPrivKey;
		}
		finally
		{
			CHECK_NULL_AND_FREE(delete[], bufCert);
				// doesn't seem to work. The function uses free from MSVCRT (never MSVCRT-debug), which might be related
				// to the problem, although the exception occurs even in release builds.
			/* CHECK_NULL_AND_FREE(SECITEM_FreeItem, siPassword); */
			CHECK_NULL_AND_FREE(CERT_DestroyCertList, listCerts);
			CHECK_NULL_AND_FREE(SEC_PKCS12DecoderFinish, decoderPkcs12);
			CHECK_NULL_AND_FREE(PK11_FreeSlot, slot);
		}
	}

	PLArenaPool *X509NSSCertificate::nssArena::get()
	{
		if (_nssArena == NULL)
		{
			NSSDatabase::initialize();

			_nssArena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
		}

		return _nssArena;
	}
}
}