# NSSWrapper
A .NET Wrapper around the Mozilla crypto library [Network Security Services (NSS)](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS)

NSSWrapper is written in C++/CLI and provides cryptographic functionality using the .NET crypto modules and especially NSS in the background. It provides a number of classes to analyze and modify X.509 data structures like X.509 certificates and Certificate Revocation Lists (CRLs) in ways not supported by the standard .NET classes.

## Build

NSSWrapper uses the Microsoft Visual C++ Redistributable Runtime. The static libraries of NSS are linked into NSSWrapper.dll to form one resulting DLL. Since NSS uses native code, it is not possible to have one DLL file to support both x86 and x64 code. Currently, only x86 code is supported. 

## Support

Please open an issue if you have problems using NSSWrapper or think you have found a bug. Professional development support is available from [Glück & Kanja](https://www.glueckkanja.com/).

## Licenses
NSSWrapper is available under the [Mozilla Public License](LICENSE) as well as the [GPL](gpl-3.0.md) (your choice). 

NSSWrapper depends on [log4net](https://logging.apache.org/log4net/), which is available under the [Apache License, Version 2.0](https://logging.apache.org/log4net/license.html).
