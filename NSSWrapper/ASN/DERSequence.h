#pragma once

#include "ASNObject.h"

using namespace System::Collections::Generic;
using namespace System;

namespace GK
{
namespace NSSWrapper
{
namespace ASN
{

ref class DERSequence : IEnumerable<ASNObject ^>, IEnumerator<ASNObject ^>, ASNObject
{
public:
	DERSequence(char *rawData, long long length)
		: ASNObject(rawData, length)
	{
	}

	~DERSequence() {}

	// start of IEnumerator interface
private:
	long long iCurrentPosition;
public:
	virtual bool MoveNext()
	{
		if (-1 >= iCurrentPosition)
			iCurrentPosition = 0;
		else
			iCurrentPosition += Current->overallLength; 

		return static_cast<unsigned long long>(iCurrentPosition) < contentLength; 
	};
	virtual void Reset() { iCurrentPosition = -1; };

	virtual property ASNObject ^Current
	{ 
		ASNObject ^get()
		{ 
			return ASNObject::parse( &content[iCurrentPosition], contentLength - iCurrentPosition); 
		}
	}
	property Object ^Current2 {
		virtual Object ^get() = System::Collections::IEnumerator::Current::get { 
			return Current;
		} }
	// end of IEnumerator interface

	// start of IEnumerable interface
	virtual IEnumerator<ASNObject ^> ^GetEnumerator()
		{ Reset(); return this; };
	virtual System::Collections::IEnumerator ^GetEnumerator2() = System::Collections::IEnumerable::GetEnumerator {
		return GetEnumerator();
	};
	// end of IEnumerable interface
};

}
}
}