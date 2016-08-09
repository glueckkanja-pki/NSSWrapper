#pragma once

#include "ASNObject.h"

using namespace System;
using namespace System::IO;

namespace GK
{
namespace NSSWrapper
{
namespace ASN
{

ref class DEROid : ASNObject
{
public:
	DEROid(char *rawData, long long length)
		: ASNObject(rawData, length)
	{
	}

	DEROid(String ^strOidValue)
		: ASNObject()
	{
		array<String ^> ^saOidComponents = strOidValue->Split('.');
		if (saOidComponents->Length < 2)
			throw gcnew ArgumentException("strOidValue does not look like an OID with at least two components");

		MemoryStream ^msResult = gcnew MemoryStream(strOidValue->Length/2);

			// encode the first special subidentifier
		encodeSubidentifier(
			UInt64::Parse(saOidComponents[0]) * 40 + UInt64::Parse(saOidComponents[1]),
			msResult
		);
		
			// encode the rest of those subidentifiers
		for (int i = 2; i < saOidComponents->Length; ++i)
			encodeSubidentifier(
				UInt64::Parse(saOidComponents[i]),
				msResult
			);

		array<Byte> ^bufOutput = msResult->ToArray();
		array<Byte> ^baLengthEncoding = encodeLength(bufOutput->Length);
	
		lBufferLength = 1 + baLengthEncoding->Length + bufOutput->Length;
		_rawData = new char[static_cast<unsigned int>(lBufferLength)];
		_rawData[0] = DER_OBJECT_ID;
		System::Runtime::InteropServices::Marshal::Copy(baLengthEncoding,0,static_cast<IntPtr>(&_rawData[1]),baLengthEncoding->Length);
		System::Runtime::InteropServices::Marshal::Copy(bufOutput,0,static_cast<IntPtr>(&_rawData[baLengthEncoding->Length + 1]),bufOutput->Length);
	}

	property String ^strOidValue
	{
		String ^get()
		{
			System::Text::StringBuilder ^strParsedOid = gcnew System::Text::StringBuilder(String::Empty);
			posCurrent = 0;
				// the first Subidentifier is special, as described in ITU-T Rec. X.690 8.19.4
			long long lngFirstSubidentifier = parseNextSubidentifier();
			strParsedOid->Append((lngFirstSubidentifier/40).ToString());
			strParsedOid->Append(".");
			strParsedOid->Append((lngFirstSubidentifier%40).ToString());

			while(posCurrent<contentLength)
			{
				strParsedOid->Append(".");
				strParsedOid->Append(parseNextSubidentifier().ToString());
			}

			return strParsedOid->ToString();
		}
	}

private:
	unsigned long long posCurrent;
	/// <summary>
	/// decode as specified in X.690 8.19.2
	/// </summary>
	long long parseNextSubidentifier()
	{
		long long idValue = 0;
		do
		{
			idValue <<= 7;
			idValue += content[posCurrent] & 0x7F;
		}
		while (0x80 == (content[posCurrent++] & 0x80));

		return idValue;
	}

	/// <summary>
	/// encode as specified in X.690 8.19.2
	/// </summary>
	void encodeSubidentifier(long long lngSubidentifier, Stream ^streamResults)
	{
		array<Byte> ^baLittleEndian = gcnew array<Byte>(9);
		int usedBytes = 0;
		for (; lngSubidentifier != 0; ++usedBytes)
		{
			baLittleEndian[usedBytes] = lngSubidentifier & 0x7F;
			if (0 != usedBytes)
				baLittleEndian[usedBytes] |= 0x80;	// this indicates to the decoder that there are still bytes left
			lngSubidentifier >>= 7;
		}

		for (int i = usedBytes - 1; i >= 0; --i)
			streamResults->WriteByte(baLittleEndian[i]);
	}
};

}
}
}