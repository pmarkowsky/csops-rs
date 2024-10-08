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
    return result;
}

// csops_int is a helper function that returns the result and status as a tuple.
pub fn csops_int(pid: i32, op: u32) -> (i32, u32) {
    let mut status: u32 = 0;
    let status_slice = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut status as *mut u32) as *mut u8,
            std::mem::size_of::<u32>(),
        )
    };
    let result = csops(pid, op, status_slice);
    return (result, status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status() {
        let (result, status) = csops_int(1, codesign::CS_OPS_STATUS);
        assert_eq!(result, 0);
        assert_eq!(status & codesign::CS_VALID, codesign::CS_VALID);
    }
}
