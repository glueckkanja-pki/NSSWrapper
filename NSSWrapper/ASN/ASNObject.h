#pragma once

using namespace System;

#define DER_BOOLEAN		0x01
#define DER_INTEGER		0x02
#define DER_BIT_STRING		0x03
#define DER_OCTET_STRING	0x04
#define DER_NULL		0x05
#define DER_OBJECT_ID		0x06
#define DER_SEQUENCE		0x10
#define DER_SET			0x11
#define DER_PRINTABLE_STRING	0x13
#define DER_T61_STRING		0x14
#define DER_IA5_STRING		0x16
#define DER_UTC_TIME		0x17
#define DER_VISIBLE_STRING	0x1a
#define DER_HIGH_TAG_NUMBER	0x1f

#ifndef NULL
#define NULL (0)
#endif

namespace GK
{
namespace NSSWrapper
{
namespace ASN
{

ref class ASNObject
{
protected:
	char *_rawData;
	unsigned long long lBufferLength;
	bool fDataIsSelfAllocated;
	ASNObject(char *rawData, unsigned long long lBufferLength);
	ASNObject()
	{
		_rawData = NULL;
		lBufferLength = 0;
		fDataIsSelfAllocated = true;
	}
public:
	static ASNObject ^parse(char *rawData, unsigned long long lBufferLength);

	~ASNObject()
	{
		if (fDataIsSelfAllocated)
		{
			CHECK_NULL_AND_FREE(delete[], _rawData);
		}
	}

	property UInt64 tagnumber
	{
		UInt64 get ()
		{
			parseTagNumber();
			return _tagnumber;
		}
	}

	property UInt64 contentLength
	{
		UInt64 get ()
		{
			parseLength();
			return _contentLength;
		}
	}

	property UInt64 overallLength
	{
		UInt64 get ()
		{
			parseLength();
			return contentLength + posContent;
		}
	}

	property const char *rawData
	{
		const char *get ()
		{
			return _rawData;
		}
	}
protected:
	UInt64 posContent;
	property char *content
	{
		char * get ()
		{
			parseLength();
			return &_rawData[posContent];
		}
	}

private:
	UInt64 _tagnumber;
	UInt64 _contentLength;

	unsigned long long posLength;

	static long long parseTagNumber(const char *rawData, unsigned long long lBufferLength, unsigned long long *posLength);

	void parseTagNumber()
	{
		if (UInt64::MaxValue == _tagnumber)
		{
			pin_ptr<unsigned long long> pinnedPosLength = &posLength;
			_tagnumber = parseTagNumber(rawData, lBufferLength, pinnedPosLength);
		}
	}

	void parseLength();
protected:
	array<Byte> ^encodeLength(unsigned long long length);		// TODO: Template Method Pattern
};

}
}
}