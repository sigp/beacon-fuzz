use swap_or_not_shuffle::shuffle_list;
use std::{slice, ptr};
use libc::{uint8_t, size_t};

#[no_mangle]
pub fn shuffle_list_c(
    input_ptr: *mut usize,
    input_size: size_t,
    seed_ptr: *mut uint8_t) -> bool {

    let input: &[usize] = unsafe {
        slice::from_raw_parts(input_ptr, input_size as usize)
    };

    let seed = unsafe {
        Vec::from_raw_parts(seed_ptr, 32, 32)
    };

    return match shuffle_list(input.to_vec(), 90, &seed, false) {
        None => false,
        Some(x) => {
            unsafe {
                ptr::copy_nonoverlapping(x.as_ptr(), input_ptr, input_size);
            }
            true
        }

    }
}
