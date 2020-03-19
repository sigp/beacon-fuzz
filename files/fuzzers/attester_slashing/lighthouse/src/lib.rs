use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing::{process_attester_slashings, VerifySignatures},
    BlockProcessingError,
};
use std::{ptr, slice};
use types::{AttesterSlashing, BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch};

#[derive(Decode, Encode)]
struct AttesterSlashingTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub attester_slashing: AttesterSlashing<T>,
}

impl<T: EthSpec> AttesterSlashingTestCase<T> {
    /// Run `process_attester_slashings` and return a `BeaconState` on success, or a
    /// `BlockProcessingError` on failure.
    fn process_attester_slashing(mut self) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = T::default_spec();

        let mut state = &mut self.pre;
        // Ensure the current epoch cache is built.
        // Required by slash_validator->initiate_validator_exit->get_churn_limit
        match state.build_committee_cache(RelativeEpoch::Current, &spec) {
            Err(e) => panic!(
                "Unable to build committee cache, invalid state? Error: {:?}",
                e
            ),
            _ => (),
        };

        process_attester_slashings(
            &mut self.pre,
            &[self.attester_slashing],
            // TODO(gnattishness) check whether we validate these consistently
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
        Err(e) => panic!(
            "rs deserialization failed. Preproc should ensure decodable: {:?}",
            e
        ),
    };

    let post_state: BeaconState<T> = match test_case.process_attester_slashing() {
        Ok(state) => state,
        _ => return Err(()),
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub extern "C" fn attester_slashing_c(
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
