#pragma once

#include "ASNObject.h"

using namespace System;

namespace GK
{
namespace NSSWrapper
{
namespace ASN
{

ref class DERInteger : ASNObject
{
public:
	DERInteger(char *rawData, long long length)
		: ASNObject(rawData, length)
	{
	}

	property long long value
	{
		long long get ()
		{
			long long retVal = content[0];
			if (0x80 == (retVal & 0x80))
				throw gcnew NotImplementedException("This DER parser does not support negative integer values");

			for (int i = 1; i < contentLength; ++i)
			{
				retVal <<= 8;
				retVal += content[i];
			}

			return retVal;
		}
	}
};

}
}
}