#pragma once

#include "X509NSSAuthorityKeyIdentifierExtension.h"

using namespace System;
using namespace System::Collections::Generic;

// Defined in NSS headers
typedef struct SECItemStr SECItem;
typedef struct CERTCertificateStr CERTCertificate;
typedef struct SECKEYPrivateKeyStr SECKEYPrivateKey;

//struct SECItem;
struct PLArenaPool;
//struct SECKEYPrivateKey;

namespace GK
{
namespace NSSWrapper
{
	#define BASEPROPERTY_WRITEABLE(PropName, PropType, NullValue)		\
	public:																\
		property PropType PropName {									\
			PropType get() {											\
			if (NullValue == _##PropName)								\
					return X509Certificate2::##PropName;				\
				else													\
					return _##PropName;									\
			}															\
			void set(PropType value) {									\
				_##PropName = value;									\
			}															\
		}																\
	private:															\
		PropType _##PropName;

	/// <summary>
	/// Adds some operations to the X509Certificate2 class, that can't be done (easily) with the .NET framework.
	/// The "dirty work" is done by the Network Security Services (NSS) hosted by the Mozilla foundation.
	/// Certificates represented by this class can issue other certs and can be recertified by CAs
	/// also represented as X509NSSCertificate
	/// </summary>
	public ref class X509NSSCertificate :
	public System::Security::Cryptography::X509Certificates::X509Certificate2
	{
		property String^ Subject { String ^get() { return SubjectName->Name; } }
		property String^ Issuer { String ^get() { return IssuerName->Name; } }
		BASEPROPERTY_WRITEABLE(NotBefore, DateTime, DateTime::MinValue);
		BASEPROPERTY_WRITEABLE(NotAfter, DateTime, DateTime::MinValue);
		BASEPROPERTY_WRITEABLE(SubjectName, System::Security::Cryptography::X509Certificates::X500DistinguishedName^, nullptr);
		BASEPROPERTY_WRITEABLE(IssuerName, System::Security::Cryptography::X509Certificates::X500DistinguishedName^, nullptr);
		BASEPROPERTY_WRITEABLE(SerialNumber, String^, nullptr);

	public:
		/// <summary>
		/// This class represents the PKIX "Basic Constraints" extension, which defines whether a certificate
		/// can be used as a CA or not, and, if it is a CA, how many sub CAs there may be in a chain below
		/// this certificate.
		/// </summary>
		ref class BasicConstraintsExtension
		{
		public:
			/// <summary>
			/// How many certificates may there be in the chain below this one? 1 means, that this is an
			/// issuing CA, 0 means, it is no CA at all. A pathLen of 2 implies, that this CA may issue
			/// CA certificates (with a pathlen of 1 at most), and so on.
			/// </summary>
			int pathLen;	// pathlen < 0 is infinite

			/// <summary>
			/// Must be true for CAs and false for user certificates
			/// </summary>
			bool fIsCA;
		};

		/// <summary>
		/// Must be set, if the issued certificate is a CA certificate.
		/// </summary>
		property BasicConstraintsExtension ^basicConstraints;
		//{
		//	void set (BasicConstraintsExtension ^value) { _basicConstraints = value; }
		//	BasicConstraintsExtension ^get() { return _basicConstraints; }
		//}

		property X509NSSAuthorityKeyIdentifierExtension ^authorityKeyIdentifier {
			void set (X509NSSAuthorityKeyIdentifierExtension ^value) { _authorityKeyIdentifier = value; }
			X509NSSAuthorityKeyIdentifierExtension ^get();
		}

		property array<Byte> ^subjectKeyIdentifier
		{
			void set (array<Byte> ^value) { _subjectKeyIdentifier = value; fIsChangedSubjectKeyIdentifier = true; }
			array<Byte> ^get();
		}

		property IList<String ^> ^colCDPs {
			IList<String ^> ^get () { return _colCDPs; }
		}

		property IList<String ^> ^colAIAs {
			IList<String ^> ^get () { return _colAIAs; }
		}

		property IList<String ^> ^colSANs {
			IList<String ^> ^get () { return _colSANs; }
		}

		property System::Security::Cryptography::X509Certificates::X509KeyStorageFlags StorageFlags;

		ref class SMIMECapability
		{
		public:
			System::Security::Cryptography::Oid ^oid;
			array<Byte> ^parameters;
		};

		property IList<SMIMECapability ^> ^colSMIMECapabilities {
			void set (IList<SMIMECapability ^> ^value) { _colSMIMECapabilities = value; fIsChangedSMIMECapabilities = true; }
			IList<SMIMECapability ^> ^get ();
		}
	private:
		array<Byte> ^encodeSMIMECapabilities();

	public:
		/// <summary>
		/// Generates a new public/private key pair. It is strongly recommended to use the Exportable flag
		/// </summary>
		X509NSSCertificate(int iKeyLength, System::Security::Cryptography::X509Certificates::X509KeyStorageFlags flags);
		/// <summary>
		/// generates a new public/private key pair
		/// </summary>
		X509NSSCertificate(int iKeyLength);
		/// <summary>
		/// new certificate based on the binary data provided as parameter
		/// </summary>
		X509NSSCertificate(array<Byte> ^binaryData);
		/// <summary>
		/// new certificate as PKCS#12 with corresponding password to unpack the cert
		/// </summary>
		X509NSSCertificate(array<Byte> ^binaryData, System::String ^password);

		static X509NSSCertificate()
		{
			dictOutputBuffers = gcnew System::Collections::Generic::Dictionary<Guid, System::IO::Stream^> (5);
		}
		/// <summary>
		/// destructor for cleaning all resources
		/// </summary>
		~X509NSSCertificate();
		/// <summary>
		/// finalizer for cleaning unmanaged resources
		/// </summary>
		!X509NSSCertificate();
		/// <summary>
		/// exchanges the certificates signature. Nothing else will be changed
		/// automatically, especially issuer and authority key identifier should be
		/// set beforehand
		/// </summary>
		void reCertify(X509NSSCertificate ^caCert);

		/// <summary>
		/// creates a PKCS#10 request based on this certificate
		/// </summary>
		array<Byte> ^exportAsPKCS10();

		/// <summary>
		/// Exchanges this certificate with a new one while preserving the private key.
		/// </summary>
		void mergeChangedCertificate(array<Byte> ^baNewCertificate);

		void generateSKIFromPublicKey();
	protected:
		/// <summary>
		/// Generates a new RSA key pair and stuffs X.509 metadata around it to create a self-signed certificate
		/// </summary>
		static array<Byte> ^generateCertificate(int iKeyLength);

		property CERTCertificate *nssCertificate
		{
			CERTCertificate *get();
		}

		/// <summary>
		/// Every instance of X509NSSCertificate shall have its own memory arena to prevent
		/// leaks
		/// </summary>
		PLArenaPool *_nssArena;
		property PLArenaPool *nssArena {
			PLArenaPool *get();
		}

	internal:
		/// <summary>
		/// Returns the private key associated to this certificate as NSS structure
		/// </summary>
		property SECKEYPrivateKey *nssPrivateKey
		{
			SECKEYPrivateKey *get();
		}

		static System::Collections::Generic::Dictionary<System::Guid, System::IO::Stream ^> ^dictOutputBuffers;
//		static void append2Buffer_callback(void *arg, const char *buf, unsigned long len);

	private:
			// used for locking in the finalizer
		Object ^objDestructionLock;

		void initValues();

		//BasicConstraintsExtension ^_basicConstraints;
		X509NSSAuthorityKeyIdentifierExtension ^_authorityKeyIdentifier;
		bool fIsChangedSubjectKeyIdentifier;
		array<Byte> ^_subjectKeyIdentifier;
		IList<String ^> ^_colCDPs;
		IList<String ^> ^_colAIAs;
		IList<String ^> ^_colSANs;
		bool fIsChangedSMIMECapabilities;
		IList<SMIMECapability ^> ^_colSMIMECapabilities;
	};
}
}