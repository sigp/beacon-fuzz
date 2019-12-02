use libc::{size_t, uint8_t};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing::{process_block_header, VerifySignatures},
    BlockProcessingError,
};
use std::{ptr, slice};
use types::{BeaconBlock, BeaconState, EthSpec, MainnetEthSpec};

#[derive(Decode, Encode)]
struct BlockHeaderTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub block: BeaconBlock<T>,
}

impl<T: EthSpec> BlockHeaderTestCase<T> {
    /// Run `process_block_header` and return a `BeaconState` on success, or a
    /// `BlockProcessingError` on failure.
    fn process_header(mut self) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = T::default_spec();

        process_block_header(
            &mut self.pre,
            &self.block,
            None,
            VerifySignatures::False,
            &spec,
        )?;

        Ok(self.pre)
    }
}

/// Accepts an SSZ-encoded `BlockHeaderTestCase` and returns an SSZ-encoded post-state on success,
/// or nothing on failure.
fn fuzz<T: EthSpec>(ssz_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let test_case = match BlockHeaderTestCase::from_ssz_bytes(&ssz_bytes) {
        Ok(test_case) => test_case,
        _ => return Err(()),
    };

    let post_state: BeaconState<T> = match test_case.process_header() {
        Ok(state) => state,
        _ => return Err(()),
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub fn block_header_c(
    input_ptr: *mut uint8_t,
    input_size: size_t,
    output_ptr: *mut uint8_t,
    output_size: *mut size_t,
) -> bool {
    let input_bytes: &[u8] = unsafe { slice::from_raw_parts(input_ptr, input_size as usize) };

    // Note: `MainnetEthSpec` contains the "constants" in the official spec.
    if let Ok(output_bytes) = fuzz::<MainnetEthSpec>(input_bytes) {
        unsafe {
            if output_bytes.len() > *output_size {
                return false;
            }
            ptr::copy_nonoverlapping(output_bytes.as_ptr(), output_ptr, output_bytes.len());
            *output_size = output_bytes.len();
        }

        return true;
    } else {
        return false;
    }
}
