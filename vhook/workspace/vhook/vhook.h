#pragma once

typedef int( WINAPI* orig_test_func )( int );

#define contains_record( address, type, field ) ( ( type* )( ( char* )( address ) - ( std::uintptr_t )( & ( (type* ) 0 ) -> field ) ) )
#define loword(l) ((std::uint16_t)(((std::uintptr_t)(l)) & 0xffff))

struct SectionData 
{
	uintptr_t start;
	size_t size;
};

enum cc : std::uint32_t
{
	cc_cdecl ,
	cc_stdcall ,
	cc_fastcall
};

namespace ntos
{
	struct list_entry
	{
		struct list_entry* Flink;
		struct list_entry* Blink;
	};

	struct unicode_string
	{
		unsigned short Length;
		unsigned short MaximumLength;
		wchar_t* Buffer;
	};

	struct peb_ldr_data
	{
		unsigned long Length;
		unsigned long Initialized;
		const char* SsHandle;
		list_entry InLoadOrderModuleList;
		list_entry InMemoryOrderModuleList;
		list_entry InInitializationOrderModuleList;
	};

	struct peb
	{
		unsigned char   Reserved1[ 2 ];
		unsigned char   BeingDebugged;
		unsigned char   Reserved2[ 1 ];
		const char* Reserved3[ 2 ];
		peb_ldr_data* Ldr;
	};

	struct ldr_data_table_entry
	{
		list_entry InLoadOrderModuleList;
		list_entry InMemoryOrderLinks;
		list_entry InInitializationOrderModuleList;
		void* DllBase;
		void* EntryPoint;

		union
		{
			unsigned long SizeOfImage;
			const char* _dummy;
		};

		unicode_string FullDllName;
		unicode_string BaseDllName;
	};

	struct image_dos_header
	{
		unsigned short e_magic;
		unsigned short e_cblp;
		unsigned short e_cp;
		unsigned short e_crlc;
		unsigned short e_cparhdr;
		unsigned short e_minalloc;
		unsigned short e_maxalloc;
		unsigned short e_ss;
		unsigned short e_sp;
		unsigned short e_csum;
		unsigned short e_ip;
		unsigned short e_cs;
		unsigned short e_lfarlc;
		unsigned short e_ovno;
		unsigned short e_res[ 4 ];
		unsigned short e_oemid;
		unsigned short e_oeminfo;
		unsigned short e_res2[ 10 ];
		long e_lfanew;
	};

	struct image_file_header
	{
		unsigned short Machine;
		unsigned short NumberOfSections;
		unsigned long TimeDateStamp;
		unsigned long PointerToSymbolTable;
		unsigned long NumberOfSymbols;
		unsigned short SizeOfOptionalHeader;
		unsigned short Characteristics;
	};

	struct image_export_directory
	{
		unsigned long Characteristics;
		unsigned long TimeDateStamp;
		unsigned short MajorVersion;
		unsigned short MinorVersion;
		unsigned long Name;
		unsigned long Base;
		unsigned long NumberOfFunctions;
		unsigned long NumberOfNames;
		unsigned long AddressOfFunctions;
		unsigned long AddressOfNames;
		unsigned long AddressOfNameOrdinals;
	};

	struct image_data_directory
	{
		unsigned long VirtualAddress;
		unsigned long Size;
	};

	struct image_optional_header
	{
		unsigned short Magic;
		unsigned char MajorLinkerVersion;
		unsigned char MinorLinkerVersion;
		unsigned long SizeOfCode;
		unsigned long SizeOfInitializedData;
		unsigned long SizeOfUninitializedData;
		unsigned long AddressOfEntryPoint;
		unsigned long BaseOfCode;
		unsigned long long ImageBase;
		unsigned long SectionAlignment;
		unsigned long FileAlignment;
		unsigned short MajorOperatingSystemVersion;
		unsigned short MinorOperatingSystemVersion;
		unsigned short MajorImageVersion;
		unsigned short MinorImageVersion;
		unsigned short MajorSubsystemVersion;
		unsigned short MinorSubsystemVersion;
		unsigned long Win32VersionValue;
		unsigned long SizeOfImage;
		unsigned long SizeOfHeaders;
		unsigned long CheckSum;
		unsigned short Subsystem;
		unsigned short DllCharacteristics;
		unsigned long long SizeOfStackReserve;
		unsigned long long SizeOfStackCommit;
		unsigned long long SizeOfHeapReserve;
		unsigned long long SizeOfHeapCommit;
		unsigned long LoaderFlags;
		unsigned long NumberOfRvaAndSizes;
		image_data_directory DataDirectory[ 16 ];
	};

	struct image_nt_headers
	{
		unsigned long Signature;
		image_file_header FileHeader;
		image_optional_header OptionalHeader;
	};
}

// Note creating a class will lead the compiler by default to create a constructor for the class which can be sigged by anticheats.
class vhook
{
public:
	static auto open_console( ) -> void;
	static auto trampoline_hook( uintptr_t P1 , uintptr_t P2 , size_t P3 ) -> uintptr_t;
	static auto iat_hook( const char* P1 , orig_test_func P2 ) -> BOOL;
	static auto get_module_base( ) -> uintptr_t;
	static auto get_process_handle( ) -> HANDLE;
	static auto get_section_by_name( const char* P2 ) -> SectionData;
	
	static auto entry( ) -> INT;

	template <typename T>
	bool read( HANDLE P1 , uintptr_t P2 , T& P3 )
	{
		return ReadProcessMemory( P1 , reinterpret_cast< LPCVOID >( P2 ) , &P3 , sizeof( P3 ) , NULL ) != 0;
	}

	template <typename T>
	bool write( HANDLE P1 , uintptr_t P2 , const T& P3 )
	{
		return WriteProcessMemory( P1 , reinterpret_cast< LPVOID >( P2 ) , &P3 , sizeof( P3 ) , NULL ) != 0;
	}
};