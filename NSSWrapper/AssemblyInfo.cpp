#include "stdafx.h"

using namespace System;
using namespace System::Reflection;
using namespace System::Runtime::CompilerServices;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Permissions;

// TODO: This file is ignored

//
// General Information about an assembly is controlled through the following
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
//
[assembly:AssemblyTitleAttribute("NSSWrapper")];
[assembly:AssemblyDescriptionAttribute("Provides methods for signing certificates without PKCS#10 requests using Mozilla Network Security Services")];
[assembly:AssemblyConfigurationAttribute("")];
[assembly:AssemblyCompanyAttribute("Glück & Kanja Consulting AG")];
[assembly:AssemblyProductAttribute("GK Directory Bridge")];
[assembly:AssemblyCopyrightAttribute("Copyright © 2010 Glück & Kanja Consulting AG")];
[assembly:AssemblyTrademarkAttribute("")];
[assembly:AssemblyCultureAttribute("")];

//
// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version
//      Build Number
//      Revision
//
// You can specify all the value or you can default the Revision and Build Numbers
// by using the '*' as shown below:

[assembly:AssemblyVersionAttribute("1.2.0.0")];
[assembly:AssemblyFileVersionAttribute("1.2.0.0")];

[assembly:ComVisible(false)];

[assembly:CLSCompliantAttribute(true)];

[assembly:SecurityPermission(SecurityAction::RequestMinimum, UnmanagedCode = true)];
