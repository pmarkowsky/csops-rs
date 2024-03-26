use std::ffi::c_void;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]

mod codesign {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn flag_set(flags: u32, flag: u32) -> bool {
    flags & flag == flag
}

pub fn decode_status(pid: i32, status: u32) {
    print!("pid: {} cs_flags: {}", pid, status);
    if flag_set(status, codesign::CS_VALID) {
        print!("; CS_VALID ");
    }
    if flag_set(status, codesign::CS_ADHOC) {
        print!("; CS_ADHOC ");
    }
    if flag_set(status, codesign::CS_GET_TASK_ALLOW) {
        print!("; CS_GET_TASK_ALLOW ");
    }
    if flag_set(status, codesign::CS_INSTALLER) {
        print!("; CS_INSTALLER ");
    }
    if flag_set(status, codesign::CS_FORCED_LV) {
        print!("; CS_FORCED_LV ");
    }
    if flag_set(status, codesign::CS_INVALID_ALLOWED) {
        print!("; CS_INVALID_ALLOWED ");
    }
    if flag_set(status, codesign::CS_HARD) {
        print!("; CS_HARD ");
    }
    if flag_set(status, codesign::CS_KILL) {
        print!("; CS_KILL ");
    }
    if flag_set(status, codesign::CS_CHECK_EXPIRATION) {
        print!("; CS_CHECK_EXPIRATION ");
    }
    if flag_set(status, codesign::CS_RESTRICT) {
        print!("; CS_RESTRICT ");
    }
    if flag_set(status, codesign::CS_ENFORCEMENT) {
        print!("; CS_ENFORCEMENT ");
    }
    if flag_set(status, codesign::CS_REQUIRE_LV) {
        print!("; CS_REQUIRE_LV ");
    }
    if flag_set(status, codesign::CS_ENTITLEMENTS_VALIDATED) {
        print!("; CS_ENTITLEMENTS_VALIDATED ");
    }
    if flag_set(status, codesign::CS_NVRAM_UNRESTRICTED) {
        print!("; CS_NVRAM_UNRESTRICTED ");
    }
    if flag_set(status, codesign::CS_RUNTIME) {
        print!("; CS_RUNTIME ");
    }
    if flag_set(status, codesign::CS_LINKER_SIGNED) {
        print!("; CS_LINKER_SIGNED ");
    }
    if flag_set(status, codesign::CS_EXEC_SET_HARD) {
        print!("; CS_EXEC_SET_HARD ");
    }
    if flag_set(status, codesign::CS_EXEC_SET_KILL) {
        print!("; CS_EXEC_SET_KILL ");
    }
    if flag_set(status, codesign::CS_EXEC_SET_ENFORCEMENT) {
        print!("; CS_EXEC_SET_ENFORCEMENT ");
    }
    if flag_set(status, codesign::CS_EXEC_INHERIT_SIP) {
        print!("; CS_EXEC_INHERIT_SIP ");
    }
    if flag_set(status, codesign::CS_KILLED) {
        print!("; CS_KILLED ");
    }
    if flag_set(status, codesign::CS_NO_UNTRUSTED_HELPERS) {
        print!("; CS_NO_UNTRUSTED_HELPERS ");
    }
    if flag_set(status, codesign::CS_PLATFORM_BINARY) {
        print!("; CS_PLATFORM_BINARY ");
    }
    if flag_set(status, codesign::CS_PLATFORM_PATH) {
        print!("; CS_PLATFORM_PATH ");
    }
    if flag_set(status, codesign::CS_DEBUGGED) {
        print!("; CS_DEBUGGED ");
    }
    if flag_set(status, codesign::CS_SIGNED) {
        print!("; CS_SIGNED ");
    }
    if flag_set(status, codesign::CS_DEV_CODE) {
        print!("; CS_DEV_CODE ");
    }
    if flag_set(status, codesign::CS_DATAVAULT_CONTROLLER) {
        print!("; CS_DATAVAULT_CONTROLLER ");
    }
    println!();
}

pub fn csops(pid: i32, op: u32, buffer: &mut [u8]) -> i32 {
    let mut result = 0;
    unsafe {
        result = codesign::csops(pid, op, buffer.as_mut_ptr() as *mut c_void, buffer.len());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status() {
        let status: u32 = 0;
        let result = csops(1, codesign::CS_OPS_STATUS, &mut status.to_ne_bytes());
        assert_eq!(result, 0);
        decode_status(1, status);
    }
}
