#include "workspace/workspace.h"

auto vhook::entry( ) -> INT
{
    vhook::open_console( );
    HMODULE current_mod = ( HMODULE ) ( vhook::get_module_base( ) );

    printf( "Module base: %p\n", current_mod );

    SectionData section = vhook::get_section_by_name( ".text" );
    if ( section.start != 0 && section.size != 0 )
    {
        printf( "Section virtual address: 0x%lx\n" , section.start );
        printf( "Section size of raw data: %zu\n" , section.size );
    }

    return true;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved )
{
    DBG_UNREFERENCED_LOCAL_VARIABLE( hModule );
    DBG_UNREFERENCED_LOCAL_VARIABLE( lpReserved );

    if ( ul_reason_for_call == DLL_PROCESS_ATTACH )
        std::thread { vhook::entry }.detach( );

    return TRUE;
}
