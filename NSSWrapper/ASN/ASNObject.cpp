#include "StdAfx.h"
#include "ASNObject.h"
#include "DERSequence.h"
#include "DEROid.h"
#include "DERInteger.h"

#ifndef NULL
#define NULL (0)
#endif

namespace GK
{
namespace NSSWrapper
{
namespace ASN
{
	ASNObject ^ASNObject::parse(char *rawData, unsigned long long lBufferLength)
	{
		unsigned long long posLength;
		unsigned long long tagNumber = parseTagNumber(rawData, lBufferLength, &posLength);
		switch(tagNumber)
		{
		case DER_SEQUENCE:
		case DER_SET:
			return gcnew DERSequence(rawData, lBufferLength);
		case DER_OBJECT_ID:
			return gcnew DEROid(rawData, lBufferLength);
		case DER_INTEGER:
			return gcnew DERInteger(rawData, lBufferLength);
		default:
			throw gcnew NotImplementedException(String::Concat("Unknown tag number ", tagNumber.ToString()));
		}
	}

	ASNObject::ASNObject(char *rawData, unsigned long long lBufferLength)
	{
		this->_rawData = rawData;
		this->lBufferLength = lBufferLength;
		fDataIsSelfAllocated = false;

		if (lBufferLength < 2)
			throw gcnew ArgumentException("An ASNObject has at least two bytes (short tag and short length of zero)");

		_tagnumber = UInt64::MaxValue;
		_contentLength = UInt64::MaxValue;
		posLength = UInt64::MaxValue;
		posContent = UInt64::MaxValue;
	}

	long long ASNObject::parseTagNumber(const char *rawData, unsigned long long lBufferLength, unsigned long long *posLength)
	{
		if (0 >= lBufferLength || NULL == rawData)
			throw gcnew ArgumentException("Cannot parse empty buffer");

		if ((rawData[0] & 0x1F) < 0x1F)	// this is the short form
		{
			if (NULL != posLength)
				*posLength = 1;
			return rawData[0] & 0x1F;
		}
		else
		{								// this is the long form of a tag
			long long tagNumber = 0;
			unsigned long long *i = posLength;
			if (NULL == i)
				i = new unsigned long long;
			*i = 1;
			do
			{
				tagNumber <<= 7;
				tagNumber += rawData[*i] & 0x7F;
			}
			while (0x80 == (rawData[(*i)++] & 0x80));
			if (*i >= lBufferLength)
				throw gcnew ArgumentException("The ASN tag is larger than the length of the ASN object");
			if (NULL == posLength)
				delete i;

			return tagNumber;
		}
	}

	void ASNObject::parseLength()
	{
		if (UInt64::MaxValue == _contentLength)
		{
			parseTagNumber();	// this makes sure posLength is set
			if ((rawData[posLength] & 0x80) == 0x00)	// this is the short form
			{
				_contentLength = rawData[posLength] & 0x7F;
				posContent = posLength + 1;
			}
			else
			{					// now the long form
				int iLengthOfLength = rawData[posLength] & 0x7F;
				if (8 < iLengthOfLength)
					throw gcnew NotImplementedException("This DER decoder cannot parse these large petabytes of data");
				if (0 == iLengthOfLength)
					throw gcnew NotImplementedException("This BER decoder cannot parse contents with indefinite length");
				//if (0x7F == iLengthOfLength)
				//	throw gcnew IndexOutOfRangeException("Length value shall not be 0xFF according to X.690 8.1.3.5 c)");

				_contentLength = 0;
				for (int i = 0; i < iLengthOfLength; ++i)
				{
					_contentLength <<= 8;
					_contentLength += rawData[posLength + i];
				}

				posContent = posLength + 1 + iLengthOfLength;

				if (_contentLength + posContent > lBufferLength)
					throw gcnew ArgumentException("The length of the ASN content is larger than the data actually available");
			}
		}
	}

	/// <summary>
	/// encode length of the content as specified in ITU-T X.690 8.1.3
	/// </summary>
	array<Byte> ^ASNObject::encodeLength(unsigned long long length)
	{
		if (length < 128)		// use short encoding form
		{
			return gcnew array<Byte>(1) { static_cast<unsigned char>(length) };
		}
		else					// use long encoding form
		{
			int iBytesCount = 8;
			for (unsigned long long mask=0xFF00000000000000; (mask&length) == 0; mask >>= 8, --iBytesCount);	// mask will shift to the MSB
			array<Byte> ^baReturn = gcnew array<Byte>(iBytesCount + 1);
			baReturn[0] = 0x80 | iBytesCount;
			for (int i = 1; i <= iBytesCount; ++i)
			{
				baReturn[i] = length & 0xFF;
				length >>= 8;
			}
			return baReturn;
		}
	}
}
}
}