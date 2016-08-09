#pragma once

// Defined in NSS headers
struct PLArenaPool;

namespace GK
{
namespace NSSWrapper
{
	public ref class X509NSSAuthorityKeyIdentifierExtension
	// : public System::Security::Cryptography::X509Certificates::X509Extension
	{
	public:
		X509NSSAuthorityKeyIdentifierExtension(void);

		property array<System::Byte> ^keyIdentifier;
		property array<System::Byte> ^serialNumber;
		property System::Security::Cryptography::X509Certificates::X500DistinguishedName ^issuerDN;

		void add2OpaqueHandle(PLArenaPool *nssArena, void *opaqueCertHandle);
	};
}
}