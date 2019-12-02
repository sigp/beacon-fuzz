use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing::{process_attester_slashings, VerifySignatures},
    BlockProcessingError,
};
use std::{ptr, slice};
use types::{AttesterSlashing, BeaconState, EthSpec, MainnetEthSpec};

#[derive(Decode, Encode)]
struct AttesterSlashingTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub attester_slashing: AttesterSlashing<T>,
}

impl<T: EthSpec> AttesterSlashingTestCase<T> {
    /// Run `process_block_header` and return a `BeaconState` on success, or a
    /// TODO change error
    /// `BlockProcessingError` on failure.
    fn process_attester_slashing(mut self) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = T::default_spec();

        // TODO(gnattishness) allow signature verification to be enabled/disabled at compile-time
        process_attester_slashings(
            &mut self.pre,
            &[self.attester_slashing],
            VerifySignatures::False,
            &spec,
        )?;

        Ok(self.pre)
    }
}

/// Accepts an SSZ-encoded `AttesterSlashingTestCase` and returns an SSZ-encoded post-state on success,
/// or nothing on failure.
fn fuzz<T: EthSpec>(ssz_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let test_case = match AttesterSlashingTestCase::from_ssz_bytes(&ssz_bytes) {
        Ok(test_case) => test_case,
        _ => return Err(()),
    };

    let post_state: BeaconState<T> = match test_case.process_attester_slashing() {
        Ok(state) => state,
        _ => return Err(()),
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub fn attester_slashing_c(
    input_ptr: *mut u8,
    input_size: usize,
    output_ptr: *mut u8,
    output_size: *mut usize,
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
