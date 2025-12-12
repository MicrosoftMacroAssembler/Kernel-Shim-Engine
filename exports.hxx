namespace nt {
      nt_status_t mi_obtain_section_for_driver( unicode_string_t* string1, unicode_string_t* driver_path, std::uint64_t zero1, std::uint64_t zero2, std::uint64_t* driver_section ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            std::uint64_t page_section_base;
            std::uint64_t page_section_size;
            if ( !nt::get_section( oxorany( "PAGE" ), &page_section_base, &page_section_size ) )
                return static_cast< nt_status_t >( -1 );

            fn_address =
                nt::find_ida_pattern( page_section_base, page_section_size,
                    oxorany( "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 48 8B 74 24" ) );
            if ( !fn_address )
                return static_cast< nt_status_t >( -1 );
        }

        using function_t = nt_status_t( __stdcall* )( unicode_string_t*, unicode_string_t*, std::uint64_t, std::uint64_t, std::uint64_t* );
        return reinterpret_cast< function_t >( fn_address )( string1, driver_path, zero1, zero2, driver_section );
    }

    nt_status_t ex_uuid_create( guid_t* uuid ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( oxorany( "ExUuidCreate" ) );
            if ( !fn_address ) return static_cast< nt_status_t >( -1 );
        }

        using function_t = nt_status_t( __stdcall* )( guid_t* );
        return reinterpret_cast< function_t >( fn_address )( uuid );
    }

    nt_status_t kse_register_shim_ex( kse_shim_t* kse_shim, driver_object_t* driver_object ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            std::uint64_t page_section_base;
            std::uint64_t page_section_size;
            if ( !nt::get_section( oxorany( "PAGE" ), &page_section_base, &page_section_size ) )
                return static_cast< nt_status_t >( -1 );

            fn_address =
                nt::find_ida_pattern( page_section_base, page_section_size,
                    oxorany( "4C 8B DC 49 89 5B ? 49 89 6B ? 56 57 41 55 41 56 41 57 48 83 EC ? 49 8B E9" ) );
            if ( !fn_address )
                return static_cast< nt_status_t >( -1 );
        }

        using function_t = nt_status_t( __stdcall* )( kse_shim_t*, driver_object_t*, std::uint64_t, void* );
        return reinterpret_cast< function_t >( fn_address )( kse_shim, driver_object, 0, nullptr );
    }

    kse_engine_t* get_kse_engine( ) {
        static kse_engine_t* kse_engine = nullptr;
        if ( !kse_engine ) {
            auto kse_unregister_shim = reinterpret_cast< std::uint8_t* >(
                get_export( oxorany( "KseUnregisterShim" ) ) 
                );
            if ( !kse_unregister_shim ) return nullptr;

            while ( !( kse_unregister_shim[ 0 ] == 0x48 &&
                kse_unregister_shim[ 1 ] == 0x8D &&
                kse_unregister_shim[ 2 ] == 0x0D ) )
                kse_unregister_shim++;

            auto rel = *reinterpret_cast< std::int32_t* >( kse_unregister_shim + 3 );
            auto ke_engine = kse_unregister_shim + 7 + rel;
            kse_engine = reinterpret_cast< kse_engine_t* >( ke_engine );
        }

        return kse_engine;
    }

    std::uint32_t* get_ksep_debug_flag( ) {
        static std::uint32_t* flag_addr = nullptr;
        if ( !flag_addr ) {
            std::uint64_t page_base, page_size;
            if ( !get_section( oxorany( "PAGE" ), &page_base, &page_size ) )
                return nullptr;

            auto pattern = find_ida_pattern( page_base, page_size, oxorany( "8B 05 ? ? ? ? 84 C2 74" ) );
            if ( !pattern )
                return nullptr;

            auto rel_offset = *reinterpret_cast< std::int32_t* >( pattern + 2 );
            flag_addr = reinterpret_cast< std::uint32_t* >( pattern + 6 + rel_offset );
        }

        return flag_addr;
    }

    std::uint32_t* get_kse_state_flag( ) {
        static std::uint32_t* flag_addr = nullptr;
        if ( !flag_addr ) {
            std::uint64_t page_base, page_size;
            if ( !get_section( oxorany( "PAGE" ), &page_base, &page_size ) )
                return nullptr;

            auto pattern = find_ida_pattern( page_base, page_size, oxorany( "8B 05 ? ? ? ? 48 8B DA 4C 8B F9" ) );
            if ( !pattern )
                return nullptr;

            auto rel_offset = *reinterpret_cast< std::int32_t* >( pattern + 2 );
            flag_addr = reinterpret_cast< std::uint32_t* >( pattern + 6 + rel_offset );
        }

        return flag_addr;
    }


    nt_status_t kse_apply_shims_to_driver( driver_load_info_t* driver_load_info, driver_info_t* driver_info, void* shim_list_buffer, std::uint32_t shim_count ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            std::uint64_t page_section_base, page_section_size;
            if ( !nt::get_section( oxorany( "PAGE" ), &page_section_base, &page_section_size ) )
                return static_cast< nt_status_t >( -1 );

            fn_address = nt::find_ida_pattern( page_section_base, page_section_size,
                oxorany( "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 45 8B F9" ) );
            if ( !fn_address )
                return static_cast< nt_status_t >( -1 );
        }

        using function_t = nt_status_t( __fastcall* )( void*, void*, void*, std::uint32_t );
        return reinterpret_cast< function_t >( fn_address )( driver_load_info, driver_info, shim_list_buffer, shim_count );
    }

    nt_status_t ob_reference_object_by_name( unicode_string_t* object_name, std::uint32_t attributes, void* access_state, std::uint32_t desired_access, object_type_t* object_type, std::uint8_t access_mode, void* parse_context, void** object ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( oxorany( "ObReferenceObjectByName" ) );
            if ( !fn_address )
                return static_cast< nt_status_t >( -1 );
        }

        using function_t = nt_status_t( __fastcall* )( unicode_string_t*, std::uint32_t, void*, std::uint32_t, object_type_t*, std::uint8_t, void*, void** );
        return reinterpret_cast< function_t >( fn_address )( object_name, attributes, access_state, desired_access, object_type, access_mode, parse_context, object );
    }

    driver_object_t* get_driver_object_by_name( const wchar_t* driver_name ) {
        wchar_t driver_path[ 260 ]{};
        std::size_t name_len = wcslen( driver_name );
        if ( name_len >= 4 && _wcsicmp( driver_name + name_len - 4, oxorany( L".sys" ) ) == 0 ) {
            name_len -= 4;
        }

        wcscpy( driver_path, oxorany( L"\\Driver\\" ) );
        wcsncat( driver_path, driver_name, name_len );
        driver_path[ 8 + name_len ] = L'\0';

        unicode_string_t object_name{};
        rtl_init_unicode_string( &object_name, driver_path );

        void* driver_object = nullptr;
        auto status = ob_reference_object_by_name( &object_name, 0x40, nullptr, 0, nt::io_driver_object_type( ), 0, nullptr, &driver_object );
        if ( status >= 0 && driver_object ) {
            return reinterpret_cast< driver_object_t* >( driver_object );
        }

        return nullptr;
    }

    void ksep_evnt_log_shims_applied( driver_info_t* driver_name, void* shim_list, std::uint32_t shim_count ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = nt::scan_ida_pattern( 
                oxorany( "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 33 E4 48 89 4D" ) );
            if ( !fn_address )
                return;
        }

        using function_t = void( __fastcall* )( driver_info_t*, void*, std::uint32_t );
        reinterpret_cast< function_t >( fn_address )( driver_name, shim_list, shim_count );
    }

    nt_status_t kse_shim_driver_io_callbacks( driver_object_t* driver_object, unicode_string_t* driver_path ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            std::uint64_t page_section_base, page_section_size;
            if ( !nt::get_section( oxorany( "PAGE" ), &page_section_base, &page_section_size ) )
                return static_cast< nt_status_t >( -1 );

            fn_address = nt::find_ida_pattern( page_section_base, page_section_size,
                oxorany( "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 56 41 57 48 8D 68 ? 48 81 EC ? ? ? ? 4C 8B 71" ) );
            if ( !fn_address )
                return static_cast< nt_status_t >( -1 );
        }

        using function_t = nt_status_t( __fastcall* )( std::uint64_t*, std::uint64_t, unicode_string_t* );
        return reinterpret_cast< function_t >( fn_address )( reinterpret_cast< std::uint64_t* >( driver_object ), 0, driver_path );
    }

    nt_status_t ksep_resolve_applicable_shims_for_driver( void* shim_list, std::uint32_t shim_count ) {
        static std::uint64_t fn_address = 0ull;
        if ( !fn_address ) {
            std::uint64_t page_section_base, page_section_size;
            if ( !nt::get_section( oxorany( "PAGE" ), &page_section_base, &page_section_size ) )
                return static_cast< nt_status_t >( -1 );

            fn_address = nt::find_ida_pattern( page_section_base, page_section_size,
                oxorany( "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 65 48 8B 04 25 ? ? ? ? 33 F6" ) );
            if ( !fn_address )
                return static_cast< nt_status_t >( -1 );
        }

        using function_t = nt_status_t( __fastcall* )( void*, std::uint32_t );
        return reinterpret_cast< function_t >( fn_address )( shim_list, shim_count );
    }
}

