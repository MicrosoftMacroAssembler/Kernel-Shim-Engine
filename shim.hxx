#pragma once

namespace kse {
	namespace shim {
        /*
        * Kernel Shim Engine
        * KSE Shims can be applied on drivers and devices
        * They can hook Import address table (IAT), Driver callbacks, and IRP I/O Packets
        * 
        * KSE Shims have been around since Windows XP
        * They have no documentation on there interface available, except for Windows Internals and Crowdstrike
        * (Shoutout to both providers because they helped me alot!)
        * 
        * My KSE Shim concept does not unregister and hook a Shim like the small number of open-source concepts do
        * We create our Shim from a unsigned driver, unlike legitimate Shims that would be present in either SDB or Registry
        * Since our Shim does not occur in the natural legitimate SDB/Registry we have to apply it to drivers by bruteforce
        * The problem with applying our Shim to drivers by bruteforce is that we do not have the privilege of patching IAT before Protection
        * 
        * Legitimate Shims would be applied by KseDriverLoadImage when a image is manual mapped or started by a service
        * Our Shim needs to be bruteforced to be applied to an image by replicating the behavouir KseDriverLoadImage 
        * Shims can only apply there hooks because they're called before MiApplyImportOptimizationToRuntimeDriver Protects the IAT with Driver Private Pages
        * Since we're Patching IAT during runtime (After IAT is marked with Driver Private Pages) KsepPatchImportTableEntry fails most of the time.
        * 
        * What makes Shims different than a traditional IAT hook detection wise is there efficient and fast patching of IAT and Callbacks
        * Since we do not have the same advantages as a Legitimate Shim, we have a couple options
        * Either Disable Page Protection or Place ourselves in SDB/Registry and find someway to reload the images we're targetting
        * Disabling Page Protection on IAT would mean we take away the advantage of what make Shims undetected
        * 
        * So I decided that I would choose neither choice since I disagree with both sides of this problem
        * I hope whoever comes across this can find some usefulness for the documentation I've created for KSE Shims
        * I left subtle documentation on code that I've mentioned in this introduction so you don't stumble around 
        * If you find any errors in my documentation or problems in my code then notify me by creating a issue or messaging me on discord (it's on my profile)
        * Below I will leave the Implementation for the usage of this Shimming Concept
     
        * Implementation to apply our KSE Shim to all Drivers in PsLoadedModuleList
            if ( !kse::shim::create( ) || !kse::shim::apply_to_drivers( ) )
                return false;

        * Implementation to apply our KSE Shim to a Driver through a LoadImageNotifyRoutine
            void image_callback( unicode_string_t* image_name, HANDLE process_id, p_image_info_t image_info ) {
                auto file_name = wcsrchr( image_name->m_buffer, oxorany( L'\\' ) );
                if ( file_name )
                   file_name++;
                else
                    file_name = image_name->m_buffer;

                if ( kse::shim::m_kse_shim ) {
                    auto name_len = wcslen( file_name );
                    if ( name_len >= 4 && !_wcsicmp( file_name + name_len - 4, oxorany( L".sys" ) ) ) {
                        kse::shim::shim_driver_entry_t shim_driver_entry{};
                        shim_driver_entry.m_driver_base = reinterpret_cast< std::uint64_t >( image_info->m_image_base );
                        shim_driver_entry.m_driver_size = static_cast< std::uint32_t >( image_info->m_image_size );

                        wcscpy( shim_driver_entry.m_driver_name, file_name );

                        if ( image_name->m_length > 0 && image_name->m_length < sizeof( shim_driver_entry.m_full_name ) - sizeof( wchar_t ) ) {
                            std::memcpy( shim_driver_entry.m_full_name, image_name->m_buffer, image_name->m_length );
                            shim_driver_entry.m_full_name[ image_name->m_length / sizeof( wchar_t ) ] = L'\0';
                        } else if ( image_name->m_length > 0 ) {
                            auto copy_len = ( sizeof( shim_driver_entry.m_full_name ) / sizeof( wchar_t ) ) - 1;
                            std::memcpy( shim_driver_entry.m_full_name, image_name->m_buffer, copy_len * sizeof( wchar_t ) );
                            shim_driver_entry.m_full_name[ copy_len ] = L'\0';
                        } else {
                            shim_driver_entry.m_full_name[ 0 ] = L'\0';
                        }

                        if ( !kse::shim::apply_to_driver( shim_driver_entry ) ) {
                            nt::dbg_print( oxorany( "[Shim] Could not place shim on %ls.\n" ), shim_driver_entry.m_driver_name );
                            client::root::push( oxorany( "[KEP] Could not place shim on %ls." ), shim_driver_entry.m_driver_name );
                            return;
                        }

                        nt::dbg_print( oxorany( "[Shim] Successfully placed shim on %ls.\n" ), shim_driver_entry.m_full_name );
                    }
                }
            }
        }
        */

        guid_t* m_shim_guid = nullptr;
        kse_shim_t* m_kse_shim = nullptr;

        struct shim_driver_entry_t {
            std::uint64_t m_driver_base = 0;
            std::uint32_t m_driver_size = 0;
            wchar_t m_driver_name[ 260 ]{ };
            wchar_t m_full_name[ 260 ]{ };
        };

		namespace hooks {
            static volatile std::uint64_t ob_register_callbacks_count = 0;
            static volatile std::uint64_t ex_allocate_pool_count = 0;
            static volatile std::uint64_t nt_query_information_token_count = 0;

            using ob_register_callbacks_t = nt_status_t( __stdcall* )( ob_callback_registration_t*, void** );
            ob_register_callbacks_t ob_register_callbacks_orig = nullptr;
            nt_status_t __stdcall ob_register_callbacks( ob_callback_registration_t* callback_registration, void** registration_handle ) {
                _InterlockedIncrement64( reinterpret_cast< volatile std::int64_t* >( &ob_register_callbacks_count ) );
                
                if ( ob_register_callbacks_orig )
                    return ob_register_callbacks_orig( callback_registration, registration_handle );
                
                return nt_status_t::success;
            }

            void __stdcall shimmed_notification( void* driver_object, void* context ) {
                nt::dbg_print( oxorany( "[Shim] Targeted Driver: 0x%llx\n" ), driver_object );
            }

            using ex_allocate_pool_with_tag_t = void*( __stdcall* )( std::uint32_t, std::size_t, std::uint32_t );
            ex_allocate_pool_with_tag_t ex_allocate_pool_with_tag_orig = nullptr;
            void* __stdcall ex_allocate_pool_with_tag( std::uint32_t pool_type, std::size_t number_of_bytes, std::uint32_t tag ) {
                _InterlockedIncrement64( reinterpret_cast< volatile std::int64_t* >( &ex_allocate_pool_count ) );

                if ( ex_allocate_pool_with_tag_orig ) {
                    return ex_allocate_pool_with_tag_orig( pool_type, number_of_bytes, tag );
                }

                return nullptr;
            }


            using nt_query_information_token_t = NTSTATUS( __stdcall* )( HANDLE, std::uint8_t, PVOID, ULONG, PULONG );
            nt_query_information_token_t nt_query_information_token_orig = nullptr;

            NTSTATUS __stdcall nt_query_information_token(
                HANDLE TokenHandle,
                std::uint8_t TokenInformationClass,
                PVOID TokenInformation,
                ULONG TokenInformationLength,
                PULONG ReturnLength ) {
                _InterlockedIncrement64( reinterpret_cast< volatile std::int64_t* >( &nt_query_information_token_count ) );

                if ( nt_query_information_token_orig ) {
                    return nt_query_information_token_orig( TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength );
                }

                return STATUS_SUCCESS;
            }
		}

        bool create( ) {
            // Enabling this flag allows KSE to DebugPrint
            // It's useful for seeing the internal behaviour but can cause Blue Screens (For some unknown reason)
            // It is more 1337 and stable to use Event Viewer to view KSE Events
            auto ksep_debug_flag = nt::get_ksep_debug_flag( );
            if ( ksep_debug_flag ) {
                auto old_flag = *ksep_debug_flag;
                *ksep_debug_flag = 0xFFFFFFFF;
                nt::dbg_print( oxorany( "[Shim] Enabled KsepDebugFlag\n" ) );
            }

            // If KSE State flag is not set to 2 it is explicitly disabled for the reasons:
            // Safe boot on, Verifier on, WinPE mode or loader issue
            auto kse_state_flag = nt::get_kse_state_flag( );
            if ( kse_state_flag && *kse_state_flag != 2 ) {
                nt::dbg_print( oxorany( "[Shim] KSE Flag not enabled\n" ) );
            }

            // Through my stress testing on Virtual Machines and Real Machines this flag has never been set
            // I don't know exactly what this would mean for our Shim but we're bruteforcing it to be applied to modules
            auto kse_engine = nt::get_kse_engine( );
            if ( kse_engine && !kse_engine->m_state ) {
                nt::dbg_print( oxorany( "[Shim] KSE Engine Flag not ready\n" ) );
            }

            static kse_hook_t exports_hook[ ] = {
                { .m_type = 0, .m_function_name = const_cast< char* >( "ObRegisterCallbacks" ), .m_hook_function = reinterpret_cast< void* >( hooks::ob_register_callbacks ) },
                { .m_type = 0, .m_function_name = const_cast< char* >( "ExAllocatePoolWithTag" ), .m_hook_function = reinterpret_cast< void* >( hooks::ex_allocate_pool_with_tag ) },
                { .m_type = 0, .m_function_name = const_cast< char* >( "NtQueryInformationToken" ), .m_hook_function = reinterpret_cast< void* >( hooks::nt_query_information_token ) },
                { .m_type = 2 }
            };

            static kse_hook_collection_t hook_collection[ ] = {
                { .m_type = 0, .m_export_driver_name = nullptr, .m_hook_array = exports_hook },
                { .m_type = 4 }
            };

            static guid_t shim_guid{};
            auto result = nt::ex_uuid_create( &shim_guid );
            if ( result < 0 ) {
                nt::dbg_print( oxorany( "[Shim] Failed to create GUID: 0x%X\n" ), result );
                return false;
            }

            nt::dbg_print( oxorany( "[Shim] Created GUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n" ),
                shim_guid.m_data1, shim_guid.m_data2, shim_guid.m_data3,
                shim_guid.m_data4[ 0 ], shim_guid.m_data4[ 1 ], shim_guid.m_data4[ 2 ], shim_guid.m_data4[ 3 ],
                shim_guid.m_data4[ 4 ], shim_guid.m_data4[ 5 ], shim_guid.m_data4[ 6 ], shim_guid.m_data4[ 7 ] );

            static wchar_t shim_name[ ] = L"HyperspaceShim";
            static kse_shim_t kse_shim = {
                .m_size = 56,
                .m_shim_guid = &shim_guid,
                .m_shim_name = shim_name,
                .m_kse_callback_routines = nullptr,
                .m_shimmed_driver_targeted_notification = nullptr,
                .m_shimmed_driver_untargeted_notification = reinterpret_cast< void* >( hooks::shimmed_notification ),
                .m_hook_collections_array = hook_collection
            };

            m_kse_shim = &kse_shim;
            m_shim_guid = &shim_guid;

            // We use KseRegisterShimEx instead of KseRegisterShim because we can pass the DriverObject
            // Kse takes a refrence of our DriverObject for safety to see if our DriverUnload is ever called
            auto kse_register_shim_ex = nt::get_export( oxorany( "KseRegisterShimEx" ) );
            if ( !kse_register_shim_ex )
                return false;

            std::uint8_t stub[ 28 ]{ };
            stub[ 0 ] = 0x48; stub[ 1 ] = 0x83; stub[ 2 ] = 0xEC; stub[ 3 ] = 0x28;
            stub[ 4 ] = 0x4D; stub[ 5 ] = 0x31; stub[ 6 ] = 0xC0;
            stub[ 7 ] = 0x4D; stub[ 8 ] = 0x31; stub[ 9 ] = 0xC9;
            stub[ 10 ] = 0x48; stub[ 11 ] = 0xB8;
            stub[ 20 ] = 0xFF; stub[ 21 ] = 0xD0;
            stub[ 22 ] = 0x48; stub[ 23 ] = 0x83; stub[ 24 ] = 0xC4; stub[ 25 ] = 0x28;
            stub[ 26 ] = 0xC3;
            *reinterpret_cast< std::uint64_t* >( &stub[ 12 ] ) = kse_register_shim_ex;

            auto stub_addr = module::find_unused_space( sizeof( stub ) );
            if ( !stub_addr || !rw::write_to_read_only( reinterpret_cast< void* >( stub_addr ), stub, sizeof( stub ) ) )
                return false;

            // KseRegisterShimEx Checks the ReturnAddress of the caller to see if it's in PsLoadedModuleList
            using stub_func_t = nt_status_t(*)( kse_shim_t*, void*, std::uint64_t, void* );
            result = reinterpret_cast< stub_func_t >( stub_addr )( m_kse_shim, nullptr, 0, device::m_driver_object );
            if ( result ) {
                nt::dbg_print( oxorany( "[Shim] KseRegisterShimEx failed: 0x%X\n" ), result );
                return false;
            }

            nt::dbg_print( oxorany( "[Shim] Registered successfully\n" ) );
            return true;
        }

        bool apply_to_driver( shim_driver_entry_t shim_driver_entry ) {
            if ( !m_kse_shim )
                return false;

            unicode_string_t driver_path{ };
            nt::rtl_init_unicode_string( &driver_path, shim_driver_entry.m_driver_name );

            unicode_string_t full_path{ };
            nt::rtl_init_unicode_string( &full_path, shim_driver_entry.m_full_name );

            std::uint64_t driver_section = 0;
            nt::mi_obtain_section_for_driver( &full_path, &driver_path, 0, 0, &driver_section );
            if ( !driver_section ) {
                // This case usually happens when this function is called from a Image Callback before the Image has initialized
                // I don't know if that is the exact reasoning but I've only encountered needing this fall case if I'm calling on a module from a Image Callback
                // There's probably a better way to deal with this case like calling MiGenerateSystemImageNames for the proper File Name but this works fine             
                auto ps_loaded_module_list = reinterpret_cast< list_entry_t* >( nt::get_export( oxorany( "PsLoadedModuleList" ) ) );
                if ( ps_loaded_module_list ) {
                    auto iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >( ps_loaded_module_list->m_flink );
                    while ( reinterpret_cast< list_entry_t* >( iter_ldr_entry ) != ps_loaded_module_list ) {
                        if ( iter_ldr_entry->m_dll_base == reinterpret_cast< void* >( shim_driver_entry.m_driver_base ) ) {
                            if ( iter_ldr_entry->m_section_pointer ) {
                                driver_section = reinterpret_cast< std::uint64_t >( iter_ldr_entry->m_section_pointer );
                                
                                if ( !shim_driver_entry.m_full_name[ 0 ] && iter_ldr_entry->m_full_dll_name.m_buffer && iter_ldr_entry->m_full_dll_name.m_length > 0 ) {
                                    auto copy_len = ( iter_ldr_entry->m_full_dll_name.m_length / sizeof( wchar_t ) );
                                    if ( copy_len < sizeof( shim_driver_entry.m_full_name ) / sizeof( wchar_t ) ) {
                                        std::memcpy( shim_driver_entry.m_full_name, iter_ldr_entry->m_full_dll_name.m_buffer, iter_ldr_entry->m_full_dll_name.m_length );
                                        shim_driver_entry.m_full_name[ copy_len ] = L'\0';
                                        nt::rtl_init_unicode_string( &full_path, shim_driver_entry.m_full_name );
                                    }
                                }
                                
                                nt::dbg_print( oxorany( "[Shim] Found section from module list: 0x%llx\n" ), driver_section );
                                break;
                            }
                        }
                        iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >( iter_ldr_entry->m_in_load_order_links.m_flink );
                    }
                }
                
                if ( !driver_section ) {
                    return false;
                }
            }

            static driver_load_info_t driver_load_info {
                 .m_section_object = reinterpret_cast< void* >( driver_section ),
                 .m_base_address = shim_driver_entry.m_driver_base,
                 .m_size = shim_driver_entry.m_driver_size
            };

            static driver_info_t driver_info {
                .m_name = shim_driver_entry.m_driver_name
            };

            static shim_entry_t entry_storage{ 
                .m_shim_ptr = reinterpret_cast< std::uint64_t >( m_kse_shim ),
                .m_driver_object = reinterpret_cast< std::uint64_t >( device::m_driver_object )
            };

            std::uint8_t shim_list_buffer[ 152 ]{};
            *reinterpret_cast< shim_entry_t** >( shim_list_buffer + 72 ) = &entry_storage;

            struct shim_resolve_entry_t {
                std::uint64_t m_entry[ 10 ];
            };

            static shim_resolve_entry_t resolve_entry{ };
            std::memcpy( &resolve_entry.m_entry[ 0 ], m_shim_guid, sizeof( guid_t ) );
            resolve_entry.m_entry[ 4 ] = reinterpret_cast< std::uint64_t >( m_kse_shim );
            resolve_entry.m_entry[ 7 ] = reinterpret_cast< std::uint64_t >( device::m_driver_object );
            resolve_entry.m_entry[ 9 ] = reinterpret_cast< std::uint64_t >( m_kse_shim );

            // Calls KsepResolveShimHooks that sets m_original_function from kse_shim_t to the export of the m_function_name from kse_shim_t?
            // This is the same sequence of events that happpen in KseDriverLoadImage (I tried my best to recreate the behaviour of it) 
            if ( auto result = nt::ksep_resolve_applicable_shims_for_driver( &resolve_entry, 1 ) ) {
                nt::dbg_print( oxorany( "[Shim] Could not resolve applicable shims: 0x%x\n" ), result );
                return false;
            }

            // Calls MmReplaceImportEntry, parameters suggest that it switches the m_hook_function and m_original_function from kse_shim_t
            // I tried to swap m_hook_function and m_original_function to see if it could successfully replace the IAT Entry but I didn't get far (My assumption could be incorrect)
            // MmReplaceImportEntry might be failing because Page Protection is set on the IAT Entries
            // Page Protection is set on the IAT Entries after KseDriverLoadImage is called by MiUpdateImportRelocationsOnDriverPrivatePages from MiApplyImportOptimizationToRuntimeDriver
            // I suggest to do a deeper dive with more critical thinking then I have left in me (3AM at the moment) to see the behaviour of this MmReplaceImportEntry
            if ( auto result = nt::kse_apply_shims_to_driver( &driver_load_info, &driver_info, shim_list_buffer, 1 ) ) {
                nt::dbg_print( oxorany( "[Shim] Could not apply shim to driver: 0x%x\n" ), result );
                return false;
            }

            // Not needed but I wanted it to be as accurate as possible, use Event Viewer to see the output
            nt::ksep_evnt_log_shims_applied( &driver_info, shim_list_buffer, 1 );

            // IRP Callbacks (doesn't work on our Shim since we're not in SDB (Shim Database) or Registry
            //auto driver_object = nt::get_driver_object_by_name( shim_driver_entry.m_driver_name );
            //if ( driver_object ) {
            //    if ( auto result = nt::kse_shim_driver_io_callbacks( driver_object, &driver_path ) ) {
            //        nt::dbg_print( oxorany( "[Shim] Could not apply IO callbacks: 0x%x\n" ), result );
            //    }
            //}

            return true;
        }

        bool apply_to_drivers( ) {
            if ( !m_shim_guid )
                return false;

            auto ps_loaded_module_list = reinterpret_cast< list_entry_t* >( nt::get_export( oxorany( "PsLoadedModuleList" ) ) );
            if ( !ps_loaded_module_list )
                return false;

            auto iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >( ps_loaded_module_list->m_flink );
            int driver_count = 0;
            int applied_count = 0;

            while ( reinterpret_cast< list_entry_t* >( iter_ldr_entry ) != ps_loaded_module_list ) {
                if ( iter_ldr_entry->m_base_dll_name.m_length && iter_ldr_entry->m_base_dll_name.m_length ) {
                    shim_driver_entry_t shim_driver_entry{ };
                    shim_driver_entry.m_driver_base = reinterpret_cast
                        < std::uint64_t >( iter_ldr_entry->m_dll_base );
                    shim_driver_entry.m_driver_size = iter_ldr_entry->m_size_of_image;

                    std::memcpy( shim_driver_entry.m_driver_name, iter_ldr_entry->m_base_dll_name.m_buffer, iter_ldr_entry->m_base_dll_name.m_length );
                    std::memcpy( shim_driver_entry.m_full_name, iter_ldr_entry->m_full_dll_name.m_buffer, iter_ldr_entry->m_full_dll_name.m_length );

                    shim_driver_entry.m_driver_name[ iter_ldr_entry->m_base_dll_name.m_length / 2 ] = L'\0';
                    shim_driver_entry.m_full_name[ iter_ldr_entry->m_full_dll_name.m_length / 2 ] = L'\0';

                    driver_count++;
                    if ( apply_to_driver( shim_driver_entry ) )
                        applied_count++;
                }

                iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >( iter_ldr_entry->m_in_load_order_links.m_flink );
            }

            nt::dbg_print( oxorany( "[Shim] apply: Applied shim to %d/%d drivers\n" ), applied_count, driver_count );
            return applied_count > 0;
        }
	}
}
