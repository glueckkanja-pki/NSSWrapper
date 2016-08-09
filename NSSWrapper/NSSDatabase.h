#pragma once

namespace GK
{
namespace NSSWrapper
{
	/// <summary>
	/// Provides an idempotent and thread save initialization routine for NSS
	/// </summary>
	public ref class NSSDatabase abstract sealed
	{
	public:
		/// <summary>
		/// The directory, in which temporary database files will be saved. May only be changed
		/// before the initialization
		/// </summary>
		static property System::String ^strDbPath {
			System::String ^get() { return _strDbPath; }
			void set(System::String ^strValue);
		}

		/// <summary>
		/// Initializes the NSS subsystem and hooks the temporary database into the system. This method
		/// is idempotent and should be called before any use of NSS.
		/// </summary>
		static void initialize();
	protected:
		/// <summary>
		/// Remembers whether NSS has already been initialized - this is the basis for the class'es
		/// idempotency
		/// </summary>
		static property bool isInitialized;
	private:
		/// <summary>
		/// Attribute for the property strDbPath
		/// </summary>
		static System::String ^_strDbPath;

		/// <summary>
		/// This lock provides thread safety for the class, so that no two initializations occur at the
		/// same time
		/// </summary>
		static Object ^nssInitLock;

		/// <summary>
		/// sets the default values
		/// </summary>
		static NSSDatabase();
	};
}
}