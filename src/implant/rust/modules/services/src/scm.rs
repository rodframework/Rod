//! The service control manager edge (the module's whole platform
//! surface): the SCM database's own seats -- services with a binary
//! path -- created, marked for deletion, and read through advapi32
//! directly, so the module owes the loader no dependency for nine
//! functions. Everything that must hold for a test (the start-kind
//! table, the error table) is a plain function this host runs
//! anywhere; only the calls themselves sit behind `cfg(windows)`, and
//! the Windows crosses the CI lane builds prove they compile.
//!
//! Two SCM facts shape the verb's honesty. Every write needs the
//! administrator's access -- creating and deleting seats alike -- and
//! deletion is a mark, not an act: the record is gone once the service
//! stops and its last handle closes, so the module's answers say so
//! rather than reporting an instant removal the manager never performs.

/// The start kinds the database carries, as the words a row prints.
/// The seat this module installs is the auto one -- a service that
/// runs at every boot -- and the others read as themselves instead of
/// a guessed cause.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn start_text(start: u32) -> String {
    match start {
        0 => "boot".to_string(),
        1 => "system".to_string(),
        2 => "auto".to_string(),
        3 => "demand".to_string(),
        4 => "disabled".to_string(),
        other => format!("start {other}"),
    }
}

/// The Win32 error codes the three actions can meet, as the messages
/// the operator reads. A code outside the table stands as its number --
/// never a guess at what the site's manager meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn status_message(status: i32) -> String {
    match status {
        5 => "access denied (service writes need an elevated implant)".to_string(),
        1060 => "the service does not exist".to_string(),
        1072 => "the service is already marked for deletion; it is removed once \
             it stops and its handles close"
            .to_string(),
        1073 => "a service with that name already exists".to_string(),
        other => format!("service error {other}"),
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    /// One listed seat: the service's name and the rest of its row --
    /// the binary path with its start kind, or the refusal when the
    /// manager withholds the config read.
    pub(crate) struct Seat {
        pub name: String,
        pub rest: String,
    }

    // The manager's own types: SC_HANDLE is a pointer the manager
    // owns, and the structs below are the API's layout, byte for byte.
    type ScHandle = *mut c_void;

    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
    const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;

    const SERVICE_QUERY_CONFIG: u32 = 0x0001;
    const SERVICE_QUERY_STATUS: u32 = 0x0004;
    const SERVICE_STOP: u32 = 0x0020;
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
    const DELETE: u32 = 0x0001_0000;

    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0010;
    const SERVICE_AUTO_START: u32 = 0x0002;
    const SERVICE_ERROR_IGNORE: u32 = 0;

    const SERVICE_STOPPED: u32 = 0x0001;
    const SERVICE_CONTROL_STOP: u32 = 0x0001;

    const SERVICE_WIN32: u32 = 0x0030;
    const SERVICE_STATE_ALL: u32 = 0x0003;
    const SC_ENUM_PROCESS: u32 = 0;

    const ERROR_MORE_DATA: i32 = 234;

    /// The API's own records, `#[repr(C)]` against its documented
    /// layout. The OS writes them whole through the buffers; the
    /// fields this module never reads still ride for the struct's
    /// shape, so the dead-code lint's reading never applies.
    #[repr(C)]
    #[allow(dead_code)]
    struct ServiceStatus {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct EnumServiceStatusProcess {
        service_name: *const u16,
        display_name: *const u16,
        status: ServiceStatusProcess,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct ServiceStatusProcess {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        process_id: u32,
        service_flags: u32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct QueryServiceConfig {
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path_name: *const u16,
        load_order_group: *const u16,
        tag_id: u32,
        dependencies: *const u16,
        service_start_name: *const u16,
        display_name: *const u16,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenSCManagerW(
            lpmachinename: *const u16,
            lpdatabasename: *const u16,
            dwdesiredaccess: u32,
        ) -> ScHandle;
        fn CreateServiceW(
            hscmanager: ScHandle,
            lpservicename: *const u16,
            lpdisplayname: *const u16,
            dwdesiredaccess: u32,
            dwservicetype: u32,
            dwstarttype: u32,
            dwerrorcontrol: u32,
            lpbinarypathname: *const u16,
            lploadordergroup: *const u16,
            lpdwtagid: *mut u32,
            lpdependencies: *const u16,
            lpservicestartname: *const u16,
            lppassword: *const u16,
        ) -> ScHandle;
        fn OpenServiceW(
            hscmanager: ScHandle,
            lpservicename: *const u16,
            dwdesiredaccess: u32,
        ) -> ScHandle;
        fn DeleteService(hservice: ScHandle) -> i32;
        fn QueryServiceStatus(hservice: ScHandle, lpservicestatus: *mut ServiceStatus) -> i32;
        fn ControlService(
            hservice: ScHandle,
            dwcontrol: u32,
            lpservicestatus: *mut ServiceStatus,
        ) -> i32;
        fn EnumServicesStatusExW(
            hscmanager: ScHandle,
            infolevel: u32,
            dwservicetype: u32,
            dwservicestate: u32,
            lpservices: *mut u8,
            cbbufsize: u32,
            pcbbytesneeded: *mut u32,
            lpservicesreturned: *mut u32,
            lpresumehandle: *mut u32,
            pszgroupname: *const u16,
        ) -> i32;
        fn QueryServiceConfigW(
            hservice: ScHandle,
            lpserviceconfig: *mut QueryServiceConfig,
            cbbufsize: u32,
            pcbbytesneeded: *mut u32,
        ) -> i32;
        fn CloseServiceHandle(hscobject: ScHandle) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A NUL-terminated UTF-16 string the manager wrote, read back to
    /// its NUL.
    fn from_wide(text: *const u16) -> String {
        let mut units = Vec::new();
        let mut cursor = text;
        unsafe {
            while *cursor != 0 {
                units.push(*cursor);
                cursor = cursor.add(1);
            }
        }
        String::from_utf16_lossy(&units)
    }

    /// A buffer the API's structs can land in: pointer-aligned u64
    /// units, cast at the call.
    fn aligned_buffer(bytes: usize) -> Vec<u64> {
        vec![0; (bytes + 7) / 8]
    }

    /// Creates the seat: one service record, own-process, auto-start
    /// at boot, running its binary path as LocalSystem. The display
    /// name is the service name itself -- a second name the operator
    /// never chose would be a second fact to track, and the database
    /// keeps the one that matters.
    pub(crate) fn create(name: &str, command: &str) -> Result<(), i32> {
        unsafe {
            let manager = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            );
            if manager.is_null() {
                return Err(GetLastError() as i32);
            }
            let service_name = wide(name);
            let binary_path = wide(command);
            let service = CreateServiceW(
                manager,
                service_name.as_ptr(),
                service_name.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_IGNORE,
                binary_path.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            let status = if service.is_null() {
                GetLastError() as i32
            } else {
                CloseServiceHandle(service);
                0
            };
            CloseServiceHandle(manager);
            (status == 0).then_some(()).ok_or(status)
        }
    }

    /// Marks the seat for deletion, asking a running service to stop
    /// first. The stop is a request the service may refuse or ignore;
    /// the mark takes either way, so the answer carries whether the
    /// seat was running -- the removal completes when it stops.
    pub(crate) fn delete(name: &str) -> Result<bool, i32> {
        unsafe {
            let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if manager.is_null() {
                return Err(GetLastError() as i32);
            }
            let service_name = wide(name);
            let service = OpenServiceW(
                manager,
                service_name.as_ptr(),
                DELETE | SERVICE_QUERY_STATUS | SERVICE_STOP,
            );
            if service.is_null() {
                let status = GetLastError() as i32;
                CloseServiceHandle(manager);
                return Err(status);
            }

            let mut status_record: ServiceStatus = std::mem::zeroed();
            let mut running = false;
            if QueryServiceStatus(service, &mut status_record) != 0 {
                running = status_record.current_state != SERVICE_STOPPED;
                if running {
                    let mut discard: ServiceStatus = std::mem::zeroed();
                    ControlService(service, SERVICE_CONTROL_STOP, &mut discard);
                }
            }

            let marked = DeleteService(service) != 0;
            let status = if marked { 0 } else { GetLastError() as i32 };
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            marked.then_some(running).ok_or(status)
        }
    }

    /// Every seat the database carries: the WIN32 services, whatever
    /// their state. Kernel drivers are not seats this verb can install,
    /// so the sweep never lists them.
    pub(crate) fn enumerate() -> Result<Vec<Seat>, i32> {
        unsafe {
            let manager = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
            );
            if manager.is_null() {
                return Err(GetLastError() as i32);
            }

            // The manager answers the whole list or the size it needs;
            // a database that outgrows the cap stands as its error
            // rather than a silent half-read.
            let mut bytes = 64 * 1024;
            loop {
                let mut buffer = aligned_buffer(bytes);
                let mut needed: u32 = 0;
                let mut returned: u32 = 0;
                let mut resume: u32 = 0;
                let ok = EnumServicesStatusExW(
                    manager,
                    SC_ENUM_PROCESS,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                    &mut needed,
                    &mut returned,
                    &mut resume,
                    std::ptr::null(),
                );
                if ok == 0 {
                    let status = GetLastError() as i32;
                    if status == ERROR_MORE_DATA && needed as usize > bytes && needed <= 1 << 20 {
                        bytes = needed as usize;
                        continue;
                    }
                    CloseServiceHandle(manager);
                    return Err(status);
                }

                let entries = std::slice::from_raw_parts(
                    buffer.as_ptr().cast::<EnumServiceStatusProcess>(),
                    returned as usize,
                );
                let mut seats = Vec::new();
                for entry in entries {
                    seats.push(Seat {
                        name: from_wide(entry.service_name),
                        rest: seat_rest(manager, entry.service_name),
                    });
                }
                CloseServiceHandle(manager);
                return Ok(seats);
            }
        }
    }

    /// One seat's row remainder: the binary path and its start kind,
    /// or the refusal when the manager withholds the config read --
    /// one withheld config never kills the sweep of the whole
    /// database.
    fn seat_rest(manager: ScHandle, service_name: *const u16) -> String {
        match config_of(manager, service_name) {
            Ok((binary, start)) => format!("{binary} ({})", super::start_text(start)),
            Err(status) => format!("(config not readable: {})", super::status_message(status)),
        }
    }

    /// The config one seat carries: its binary path, read into an
    /// owned string while the buffer that holds it is still alive.
    fn config_of(manager: ScHandle, service_name: *const u16) -> Result<(String, u32), i32> {
        unsafe {
            let service = OpenServiceW(manager, service_name, SERVICE_QUERY_CONFIG);
            if service.is_null() {
                return Err(GetLastError() as i32);
            }
            let mut buffer = aligned_buffer(1024);
            loop {
                let mut needed: u32 = 0;
                let ok = QueryServiceConfigW(
                    service,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                    &mut needed,
                );
                if ok != 0 {
                    let config = &*buffer.as_ptr().cast::<QueryServiceConfig>();
                    let binary = from_wide(config.binary_path_name);
                    let start = config.start_type;
                    CloseServiceHandle(service);
                    return Ok((binary, start));
                }
                let status = GetLastError() as i32;
                if needed as usize > buffer.len() * 8 && needed <= 1 << 20 {
                    buffer = aligned_buffer(needed as usize);
                    continue;
                }
                CloseServiceHandle(service);
                return Err(status);
            }
        }
    }
}

#[cfg(windows)]
pub(crate) use win::{create, delete, enumerate};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_table_names_the_kinds_a_row_can_carry() {
        assert_eq!(start_text(0), "boot");
        assert_eq!(start_text(2), "auto");
        assert_eq!(start_text(3), "demand");
        assert_eq!(start_text(4), "disabled");
        // An untabled kind keeps its number -- never a guessed word.
        assert_eq!(start_text(9), "start 9");
    }

    #[test]
    fn the_status_table_names_the_codes_operators_meet() {
        assert!(
            status_message(5).contains("elevated"),
            "{}",
            status_message(5)
        );
        assert_eq!(status_message(1060), "the service does not exist");
        assert!(
            status_message(1072).contains("marked for deletion"),
            "{}",
            status_message(1072)
        );
        assert_eq!(
            status_message(1073),
            "a service with that name already exists"
        );
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(status_message(1010), "service error 1010");
    }
}
