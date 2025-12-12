struct driver_object_t;

enum nt_status_t {
    success,
    unsuccessful = 0xc0000001,
    alerted = 0x101,
    timeout = 0x102,
    pending = 0x103,
    control_c_exit = 0xc000013a,
    buffer_too_small = 0xc0000023,
    info_length_mismatch = 0xc4l,
    insufficient_resources = 0xc9A,
    length_mismatch = 0xc4,
    invalid_parameter = 0xcd,
    access_violation = 0xc5,
    cancelled = 0xc0000120,
    not_supported = 0xc00000bb
};

enum class device_type_t : unsigned long {
    beep = 0x00000001,
    cd_rom = 0x00000002,
    cd_rom_file_system = 0x00000003,
    controller = 0x00000004,
    datalink = 0x00000005,
    dfs = 0x00000006,
    disk = 0x00000007,
    disk_file_system = 0x00000008,
    file_system = 0x00000009,
    inport_port = 0x0000000a,
    keyboard = 0x0000000b,
    mailslot = 0x0000000c,
    midi_in = 0x0000000d,
    midi_out = 0x0000000e,
    mouse = 0x0000000f,
    multi_unc_provider = 0x00000010,
    named_pipe = 0x00000011,
    network = 0x00000012,
    network_browser = 0x00000013,
    network_file_system = 0x00000014,
    null = 0x00000015,
    parallel_port = 0x00000016,
    physical_netcard = 0x00000017,
    printer = 0x00000018,
    scanner = 0x00000019,
    serial_mouse_port = 0x0000001a,
    serial_port = 0x0000001b,
    screen = 0x0000001c,
    sound = 0x0000001d,
    streams = 0x0000001e,
    tape = 0x0000001f,
    tape_file_system = 0x00000020,
    transport = 0x00000021,
    unknown = 0x00000022,
    video = 0x00000023,
    virtual_disk = 0x00000024,
    wave_in = 0x00000025,
    wave_out = 0x00000026,
    port_8042 = 0x00000027,
    network_redirector = 0x00000028,
    battery = 0x00000029,
    bus_extender = 0x0000002a,
    modem = 0x0000002b,
    vdm = 0x0000002c,
    mass_storage = 0x0000002d,
    smb = 0x0000002e,
    ks = 0x0000002f,
    changer = 0x00000030,
    smartcard = 0x00000031,
    acpi = 0x00000032,
    dvd = 0x00000033,
    full_text_index = 0x00000034,
    dfs_file_system = 0x00000035,
    dfs_volume = 0x00000036,
    serenum = 0x00000037,
    termsrv = 0x00000038,
    ksec = 0x00000039,
    fips = 0x0000003a,
    infiniband = 0x0000003b
};

struct unicode_string_t {
    std::uint16_t m_length;
    std::uint16_t m_maximum_length;
    wchar_t* m_buffer;
};

struct device_object_t {
    short type;
    unsigned short size;
    long reference_count;
    driver_object_t* driver_object;
    device_object_t* next_device;
    device_object_t* attached_device;
    void* current_irp;
    void* timer_queue;
    unsigned long flags;
    unsigned long characteristics;
    void* vpb;
    void* device_extension;
    device_type_t device_type;
    unsigned char stack_size;
    union {
        struct {
            unsigned short pending_returned;
            unsigned short padding;
        } list_entry;
        void* wait_list_entry;
    } queue;
    unsigned long align_requirement;
    void* device_queue;
    void* dpc;
    unsigned long active_threads;
    void* security_descriptor;
    void* device_lock;
    unsigned short sector_size;
    unsigned short spare1;
    void* device_object_extension;
    void* reserved;
};

struct driver_object_t {
    short type;
    short size;
    device_object_t* device_object;
    unsigned long flags;
    void* driver_start;
    unsigned long driver_size;
    void* driver_section;
    void* driver_extension;
    unicode_string_t driver_name;
    unicode_string_t* hardware_database;
    void* fast_io_dispatch;
    void* driver_init;
    void* driver_start_io;
    void* driver_unload;
    void* major_function[ 28 ];
};

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
