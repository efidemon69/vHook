#include "../workspace.h"

/*

	vHook - the simplest dll hacking library.
	made by stable / roka.

*/

auto vhook::open_console( ) -> void
{
	const auto kernel_lib = LoadLibraryA( "KERNEL32.dll" ); // Loads kernel32.dll library.
	if ( !kernel_lib ) return;

	 // Get the address of FreeConsole function
	const auto free_console = ( uintptr_t ) ( GetProcAddress( kernel_lib , "FreeConsole" ) );
	if ( free_console )
	{
		printf( "FreeConsole: %p" , free_console );

		static uintptr_t jmp = free_console + 0x6;
		DWORD old_protection { };

		// Yk
		VirtualProtect( ( void* ) ( free_console ) , 0x6 , PAGE_EXECUTE_READWRITE , &old_protection );

		// Redirect the FreeConsole call to jump over it.
		*( uintptr_t** ) ( free_console + 0x2 ) = &jmp;
		*( uint8_t* ) ( free_console + 0x6 ) = 0xC3;

		// Restore orig protection.
		VirtualProtect( ( void* ) ( free_console ) , 0x6 , old_protection , &old_protection );
	}

	AllocConsole( );
	freopen( "CONOUT$" , "w" , stdout );
	SetConsoleTitleA( "vhook - simple module library" );
}

auto vhook::trampoline_hook( uintptr_t function , uintptr_t custom_function , size_t instance_size ) -> uintptr_t
{
	constexpr auto extra_size = 5;

	// We allocate memory for the cloned function + extra size bytes for the jmp instruction.
	auto clone = ( uintptr_t ) ( VirtualAlloc( nullptr , instance_size + extra_size , MEM_COMMIT | MEM_RESERVE , PAGE_EXECUTE_READWRITE ) );
	if ( !clone ) return 0;

	// Copy the original function's instructions to the newly allocated memory.
	memmove( ( void* ) ( clone ) , ( void* ) ( function ) , instance_size );

	// Adding the jmp instruction at the end of the cloned function to redirect to the original one.
	*( uint8_t* ) ( clone + instance_size ) = 0xE9;
	*( uintptr_t* ) ( clone + instance_size + 1 ) = ( function - clone - extra_size );

	DWORD old_protect { 0 };

	// Changing the protection of the original function's memory page to RWX.
	if ( !VirtualProtect( ( void* ) ( function ) , instance_size , PAGE_EXECUTE_READWRITE , &old_protect ) )
	{
		printf( "Could not change function's memory page protection." );
		VirtualFree( ( void* ) ( clone ) , 0 , MEM_RELEASE );
		return 0;
	}

	// Overwrite the original function's instructions with a NOP instruction. (0x90) bytes.
	memset( ( void* ) ( function ) , 0x90 , instance_size );

	// Add a jump instruction at the beginning of the original function to redirect to the custom function.
	*( uint8_t* ) ( function ) = 0xE9;
	*( uintptr_t* ) ( function + 1 ) = ( custom_function - function - extra_size );

	// Restore the original protection of the original function's memory page.
	if ( !VirtualProtect( ( void* ) ( function ) , instance_size , old_protect , &old_protect ) )
	{
		printf( "Could not restore the original protection of the function" );
		VirtualFree( ( void* ) ( clone ) , 0 , MEM_RELEASE );
		return 0;
	}

	return clone;
}

auto vhook::get_module_base( ) -> uintptr_t
{
	// Getting PEB.
	const ntos::peb* peb = ( ntos::peb* ) ( __readgsqword( 0x60 ) );
	if ( !peb ) return uintptr_t( 0 );

	// Get the entry of the main module from InMemoryOrderModuleList.
	const ntos::list_entry* main_mod_entry = peb->Ldr->InMemoryOrderModuleList.Flink;
	if ( main_mod_entry == &peb->Ldr->InMemoryOrderModuleList ) return uintptr_t( 0 );

	// Convert the entry to the ldr_data_table_entry structure & return the base address of the main module.
	const ntos::ldr_data_table_entry* main_mod = ( ntos::ldr_data_table_entry* ) ( contains_record( main_mod_entry , ntos::ldr_data_table_entry , InMemoryOrderLinks ) );
	return std::uintptr_t( main_mod->DllBase );
}

auto vhook::get_section_by_name( const char* sectionName ) -> SectionData
{
	HMODULE mod = ( HMODULE ) get_module_base( );

	// Get DOS and NT headers from the module.
	IMAGE_DOS_HEADER* dos_headers = ( IMAGE_DOS_HEADER* ) ( mod );
	IMAGE_NT_HEADERS* nt_headers = ( IMAGE_NT_HEADERS* ) ( ( BYTE* ) ( mod ) +dos_headers->e_lfanew );
	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION( nt_headers ); // Get the first section header.

	// Iterate through each section header.
	for ( int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i , ++section_header )
	{
		// Get the name of the current section
		const char* curr_section_name = ( const char* ) ( section_header->Name );
		if ( strcmp( curr_section_name , sectionName ) == 0 ) // Compare the current section name with the target section name.
		{
			// Calculate the start address and size of the section.
			uintptr_t sectionStart = ( uintptr_t ) ( mod ) +section_header->VirtualAddress;
			size_t sectionSize = section_header->SizeOfRawData;
			return { sectionStart, sectionSize };
		}
	}

	return { 0, 0 };
}

auto vhook::iat_hook( const char* function_name , orig_test_func custom_func ) -> BOOL
{
	HMODULE mod = ( HMODULE ) vhook::get_module_base( );

	// Get DOS & NT Headers from module.
	PIMAGE_DOS_HEADER dos_headers = ( PIMAGE_DOS_HEADER ) ( mod );
	PIMAGE_NT_HEADERS nt_headers = ( PIMAGE_NT_HEADERS ) ( ( BYTE* ) ( mod ) +dos_headers->e_lfanew );
	// Get the import descriptor table.
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = ( PIMAGE_IMPORT_DESCRIPTOR ) ( ( BYTE* ) ( mod ) +nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );

	// Loop through each import descriptor.
	while ( import_descriptor->Name )
	{
		PIMAGE_THUNK_DATA thunk_data = ( PIMAGE_THUNK_DATA ) ( ( BYTE* ) ( mod ) +import_descriptor->FirstThunk ); // Get the thunk data for the import descriptor.

		// again...
		while ( thunk_data->u1.Function )
		{
			PIMAGE_IMPORT_BY_NAME import_by_dawg = ( PIMAGE_IMPORT_BY_NAME ) ( ( BYTE* ) ( mod ) +thunk_data->u1.Function );
			
			// Compare the current import name with the target function name.
			if ( strcmp( ( char* ) ( import_by_dawg->Name ) , function_name ) == 0 )
			{
				// Modify the function pointer to point to the custom function.
				DWORD oldProtect;
				VirtualProtect( &thunk_data->u1.Function , sizeof( PVOID ) , PAGE_READWRITE , &oldProtect );
				*( PVOID* ) ( &thunk_data->u1.Function ) = ( PVOID ) ( custom_func );
				VirtualProtect( &thunk_data->u1.Function , sizeof( PVOID ) , oldProtect , &oldProtect );
				return true;
			}

			++thunk_data;
		}

		++import_descriptor;
	}
}

auto vhook::get_process_handle( ) -> HANDLE
{
	// I will make a new 1337 way soon, for now u can use this lol.
	HANDLE proc_handle = GetCurrentProcess( );
	return proc_handle;
}
