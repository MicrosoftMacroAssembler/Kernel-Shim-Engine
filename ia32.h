struct list_entry_t {
    list_entry_t* m_flink;
    list_entry_t* m_blink;
};

struct guid_t {
    std::uint32_t m_data1;                                                  // 0x00
    std::uint16_t m_data2;                                                  // 0x04
    std::uint16_t m_data3;                                                  // 0x06
    std::uint8_t m_data4[ 8 ];                                                // 0x08
};

typedef struct kse_hook_t {
    std::uint64_t m_type; // 0: Function, 1: IRP Callback, 2: Last
    union {
        char* m_function_name; // If Type == 0
        std::uint64_t m_callback_id; // If Type == 1
    };
    void* m_hook_function;      // +16: Validated during registration (must be in driver)
    void* m_original_function;  // +24: Populated by us, swapped before patching
};

typedef struct kse_hook_collection_t {
    std::uint64_t m_type; // 0: NT Export, 1: HAL Export, 2: Driver Export, 3: Callback, 4: Last
    wchar_t* m_export_driver_name; // If Type == 2
    kse_hook_t* m_hook_array; // array of _KSE_HOOK
};

typedef struct kse_shim_t {
    std::size_t m_size;
    guid_t* m_shim_guid;
    wchar_t* m_shim_name;
    void* m_kse_callback_routines;
    void* m_shimmed_driver_targeted_notification;
    void* m_shimmed_driver_untargeted_notification;
    kse_hook_collection_t* m_hook_collections_array; // array of _KSE_HOOK_COLLECTION
};

typedef struct kse_engine_t {
    std::uint32_t m_disable_flags;        // 0x01: DisableDriverShims, 0x02: DisableDeviceShims
    std::uint32_t m_state;                // 0: Not Ready, 1: In Progress, 2: Ready
    std::uint32_t m_flags;                // 0x02: GroupPolicyOK, 0x800: DrvShimsActive, 0x1000: DevShimsActive
    list_entry_t m_providers_list_head;   // Registered shims list
    list_entry_t m_shimmed_drivers_list_head;
    void* m_kse_get_io_callbacks_routine;
    void* m_kse_set_completion_hook_routine;
    void* m_device_info_cache;
    void* m_hardware_id_cache;
    void* m_shimmed_driver_hint;
};

typedef struct driver_load_info_t {
    void* m_section_object;
    std::uint8_t m_pad1[ 40 ];
    std::uint64_t m_base_address;
    std::uint8_t m_pad2[ 16 ];
    std::uint32_t m_size;
    std::uint8_t m_pad3[ 52 ];
    std::uint32_t m_field_120;
    std::uint8_t m_pad4[ 32 ];
    std::uint32_t m_field_156;
};

typedef struct driver_info_t {
    std::uint8_t m_pad1[ 8 ];
    const wchar_t* m_name;
};

typedef struct shim_entry_t {
    std::uint64_t m_flink;
    std::uint64_t m_blink;
    std::uint64_t m_shim_ptr;
    std::uint64_t m_field_18;
    std::uint32_t m_flags;
    std::uint8_t m_pad1[ 4 ];
    std::uint64_t m_field_20;
    std::uint64_t m_driver_object;
    std::uint8_t m_pad2[ 72 ];
};

struct shim_resolve_entry_t {
    std::uint64_t m_entry[ 10 ];
};

static_assert(sizeof(kse_hook_t) == 32, "kse_hook_t size mismatch");
static_assert(sizeof(kse_hook_collection_t) == 24, "kse_hook_collection_t size mismatch");
static_assert(sizeof(kse_shim_t) == 56, "kse_shim_t size mismatch");
