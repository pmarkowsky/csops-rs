use std::ffi::c_void;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]

pub mod codesign {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn csops(pid: i32, op: u32, buffer: &mut [u8]) -> i32 {
    let mut result = 0;
    unsafe {
        result = codesign::csops(pid, op, buffer.as_mut_ptr() as *mut c_void, buffer.len());
    }
    return result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status() {
        let status: u32 = 0;
        let result = csops(1, codesign::CS_OPS_STATUS, &mut status.to_ne_bytes());
        assert_eq!(result, 0);
    }
}
