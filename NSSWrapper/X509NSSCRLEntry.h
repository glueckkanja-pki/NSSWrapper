#pragma once

using namespace System;

// Defined in NSS headers
typedef struct CERTCrlEntryStr	CERTCrlEntry; 

namespace GK
{
namespace NSSWrapper
{
	public ref class X509NSSCRLEntry
	{
	public:
		X509NSSCRLEntry(DateTime dateRevocation, array<Byte> ^serialNumber)
		{
			this->dateRevocation = dateRevocation;
			this->serialNumber = serialNumber;
		}
		
		property DateTime dateRevocation;
		property array<Byte> ^serialNumber;

	internal:
		CERTCrlEntry *createNSSStructure();
	};
}
}