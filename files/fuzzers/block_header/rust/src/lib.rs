use ssz::{Encode, Decode};
use ssz_derive::{Encode, Decode};
use types::{BeaconState, BeaconBlock, EthSpec, FoundationEthSpec};
use std::{slice, ptr};
use libc::{uint8_t, size_t};
use state_processing::{BlockProcessingError, per_block_processing::{process_block_header, verify_block_signature}};

#[derive(Decode, Encode)]
struct BlockHeaderTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub block: BeaconBlock,
}

impl<T: EthSpec> BlockHeaderTestCase<T> {
    /// Run `process_block_header` and return a `BeaconState` on success, or a
    /// `BlockProcessingError` on failure.
    fn process_header(mut self) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = T::spec();

        process_block_header(&mut self.pre, &self.block, &spec)?;
        verify_block_signature(&mut self.pre, &self.block, &spec)?;

        Ok(self.pre)
    }
}

/// Accepts an SSZ-encoded `BlockHeaderTestCase` and returns an SSZ-encoded post-state on success,
/// or nothing on failure.
fn fuzz<T: EthSpec>(ssz_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let test_case = match BlockHeaderTestCase::from_ssz_bytes(&ssz_bytes) {
        Ok(test_case) => test_case,
        _ => return Err(())
    };

    let post_state: BeaconState<T> = match test_case.process_header() {
        Ok(state) => state,
        _ => return Err(())
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub fn block_header_c(
    // TODO: I'm not sure these input vars are correct.
    input_ptr: *mut uint8_t,
    input_size: size_t) -> bool {

    let input_bytes: &[u8] = unsafe {
        slice::from_raw_parts(input_ptr, input_size as usize)
    };

    // Note: `FoundationEthSpec` contains the "constants" in the official spec.
    if let Ok(output_bytes) = fuzz::<FoundationEthSpec>(input_bytes) {
        // TODO: I doubt this `copy_nonoverlapping` is correct.
        unsafe {
            ptr::copy_nonoverlapping(output_bytes.as_ptr(), input_ptr, input_size);
        }

        true
    } else {
        false
    }
}
