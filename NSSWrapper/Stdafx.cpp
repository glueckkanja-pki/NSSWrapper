// stdafx.cpp : source file that includes just the standard includes
// NSSWrapper.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "stdafx.h"

#ifdef NSSWRAPPER_LINK_NSS_STATIC
	// link NSS .lib files:
#pragma comment(lib, "libnspr4_s")
#pragma comment(lib, "libplc4_s")
#pragma comment(lib, "libplds4_s")

#pragma comment(lib, "nss")
#pragma comment(lib, "ssl")
#pragma comment(lib, "smime")
#pragma comment(lib, "sectool")
#pragma comment(lib, "nssutil")
#pragma comment(lib, "pkcs12")
#pragma comment(lib, "certdb")
#pragma comment(lib, "cryptohi")
#pragma comment(lib, "pk11wrap")
#pragma comment(lib, "certhi")
#pragma comment(lib, "pkcs7")
#pragma comment(lib, "nssb")
#pragma comment(lib, "nsspki")
#pragma comment(lib, "nssdev")
#pragma comment(lib, "zlib")

#pragma comment(lib, "pkixcertsel")
#pragma comment(lib, "pkixchecker")
#pragma comment(lib, "pkixcrlsel")
#pragma comment(lib, "pkixmodule")
#pragma comment(lib, "pkixparams")
#pragma comment(lib, "pkixpki")
#pragma comment(lib, "pkixresults")
#pragma comment(lib, "pkixstore")
#pragma comment(lib, "pkixsystem")
#pragma comment(lib, "pkixtop")
#pragma comment(lib, "pkixutil")

	// link windows libraries, on which NSS depends:
#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "Mswsock")
#pragma comment(lib, "Winmm")

#else // NOT NSSWRAPPER_LINK_NSS_STATIC
#pragma comment(lib, "libnspr4")
#pragma comment(lib, "libplc4")
#pragma comment(lib, "libplds4")
#pragma comment(lib, "nss3")
#pragma comment(lib, "nssutil3")
#pragma comment(lib, "smime3")
#pragma comment(lib, "ssl3")

//	// static lib, but nowhere else is CERT_IssuerNameFromDERCert defined :-/
//#pragma comment(lib, "certdb")
#endif // NSSWRAPPER_LINK_NSS_STATIC

	// NSS code was modified to enable loading
#if NSSWRAPPER_INCLUDE_DYNAMICS
#pragma comment(lib, "softokn")
#pragma comment(lib, "sqlite")

#pragma comment(lib, "freebl_s")

#pragma comment(lib, "nssdbm")
#pragma comment(lib, "dbm")

#endif // NSSWRAPPER_INCLUDE_DYNAMICS