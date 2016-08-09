#pragma once

#include "X509NSSCRLEntry.h"
#include "X509NSSCertificate.h"

namespace GK
{
namespace NSSWrapper
{
	public ref class X509NSSCRL
	{
	public:
		X509NSSCRL(void);
		X509NSSCRL(array<System::Byte> ^binCRL);
		property DateTime dateStartTime;
		property DateTime dateEndTime;
		property array<Byte> ^authorityKeyIdentifier;

		property System::Collections::Generic::IList<X509NSSCRLEntry ^> ^entries {
			System::Collections::Generic::IList<X509NSSCRLEntry ^> ^get()
			{
				if (nullptr == _entries)
					_entries = gcnew System::Collections::Generic::List<X509NSSCRLEntry ^>();
				return _entries;
			}
		}
		array<Byte> ^sign(X509NSSCertificate ^signingCert);
	protected:
		System::Collections::Generic::IList<X509NSSCRLEntry ^> ^_entries;
		array<System::Byte> ^binCRL;
	};
}
}