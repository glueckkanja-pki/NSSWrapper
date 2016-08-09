// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once

	// Marshals a .NET string to a Unicode char array
#define NETSTRING_2_UNISTRING(netString, uniString) { \
	System::IntPtr bString = System::Runtime::InteropServices::Marshal::StringToBSTR(netString); \
	uniString = reinterpret_cast<wchar_t*>(bString.ToPointer()); \
	}

	// Marshals a .NET string to an ASCII char array
#define NETSTRING_2_CHARSTRING(netString, charString) { \
	System::IntPtr bString = System::Runtime::InteropServices::Marshal::StringToBSTR(netString); \
	wchar_t *tempString = reinterpret_cast<wchar_t*>(bString.ToPointer()); \
	int iLen = wcslen(tempString) + 1; \
	charString = new char[iLen]; \
	sprintf_s(charString, iLen, "%S", tempString); \
	System::Runtime::InteropServices::Marshal::FreeBSTR(bString); \
	}

	// Marshals an ASCII char array to a .NET string
#define CHARSTRING_2_NETSTRING(charString, netString) \
	netString = System::Runtime::InteropServices::Marshal::PtrToStringAnsi(static_cast<System::IntPtr>(charString));

	// Marshals a .NET Byte[] into a binary string, represented as a char *
#define NETBYTEARRAY_2_CHARSTRING(netByteArray, charString) \
	charString = new char[netByteArray->Length]; \
	System::Runtime::InteropServices::Marshal::Copy(netByteArray,0,static_cast<IntPtr>(charString),netByteArray->Length);

#define CHARARRAY_2_NETBYTEARRAY(charArray, length, netByteArray) { \
	IntPtr ^binaryPointer = gcnew IntPtr(const_cast<void *>(reinterpret_cast<const void *>(charArray))); \
	netByteArray = gcnew array<Byte>(length); \
	System::Runtime::InteropServices::Marshal::Copy(*binaryPointer,netByteArray,0,length); \
	}

#define CHECK_NULL_AND_FREE(funcFree, variable) \
	if (NULL != variable) \
	{ \
		funcFree( variable ); \
		variable = NULL; \
	}

#define ASSERT_NSS_NOTNULL(pointer, message) \
	if (0 == pointer) \
		throw gcnew System::Runtime::InteropServices::ExternalException(	\
			message, PR_GetError());

#define ASSERT_NSS_SUCCESS(stat, message) \
	if (stat == SECFailure) \
		throw gcnew System::Runtime::InteropServices::ExternalException(	\
			message, PR_GetError());