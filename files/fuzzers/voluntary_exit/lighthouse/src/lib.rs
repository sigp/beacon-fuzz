use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing::{process_exits, VerifySignatures},
    BlockProcessingError,
};
use std::{ptr, slice};
use types::{BeaconState, EthSpec, MainnetEthSpec, SignedVoluntaryExit};

#[derive(Decode, Encode)]
struct VoluntaryExitTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub exit: SignedVoluntaryExit,
}

impl<T: EthSpec> VoluntaryExitTestCase<T> {
    /// Run `process_exits` and return a `BeaconState` on success, or a
    /// `BlockProcessingError` on failure.
    fn process_voluntary_exit(mut self) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = T::default_spec();

        process_exits(
            &mut self.pre,
            &[self.exit],
            // TODO(gnattishness) check whether we validate these consistently
            VerifySignatures::False,
            &spec,
        )?;

        Ok(self.pre)
    }
}

/// Accepts an SSZ-encoded `VoluntaryExitTestCase` and returns an SSZ-encoded post-state on success,
/// or nothing on failure.
fn fuzz<T: EthSpec>(ssz_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let test_case = match VoluntaryExitTestCase::from_ssz_bytes(&ssz_bytes) {
        Ok(test_case) => test_case,
        Err(e) => panic!(
            "rs deserialization failed. Preproc should ensure decodable: {:?}",
            e
        ),
    };

    let post_state: BeaconState<T> = match test_case.process_voluntary_exit() {
        Ok(state) => state,
        _ => return Err(()),
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub extern "C" fn voluntary_exit_c(
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
                // Likely indicates an issue with the fuzzer, we should halt here
                // This is different to a processing failure, so we panic to differentiate.
                panic!("Output buffer not large enough.")
            }
            ptr::copy_nonoverlapping(output_bytes.as_ptr(), output_ptr, output_bytes.len());
            *output_size = output_bytes.len();
        }

        return true;
    } else {
        return false;
    }
}
