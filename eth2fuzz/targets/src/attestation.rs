use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing::{process_attestations, VerifySignatures},
    BlockProcessingError,
};
use std::{ptr, slice};
use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec};

#[derive(Decode, Encode)]
pub struct AttestationTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub attestation: Attestation<T>,
}

impl<T: EthSpec> AttestationTestCase<T> {
    /// Run `process_block_header` and return a `BeaconState` on success, or a
    /// TODO change error
    /// `BlockProcessingError` on failure.
    pub fn process_attestation(mut self) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = T::default_spec();

        // TODO not certain whether we use beacon_node::beacon_chain::process_attestation,
        // or eth2::state_processing::per_block_processing::process_attestations
        // or possibly beacon_node:fork_choice
        // I think process_attestations, but only due to existing types etc, not proper understanding
        process_attestations(
            &mut self.pre,
            &[self.attestation],
            VerifySignatures::True,
            &spec,
        )?;

        Ok(self.pre)
    }
}

/// Accepts an SSZ-encoded `AttestationTestCase` and returns an SSZ-encoded post-state on success,
/// or nothing on failure.
fn fuzz<T: EthSpec>(ssz_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let test_case = match AttestationTestCase::from_ssz_bytes(&ssz_bytes) {
        Ok(test_case) => test_case,
        Err(e) => panic!(
            "rs deserialization failed. Preproc should ensure decodable: {:?}",
            e
        ),
    };

    let post_state: BeaconState<T> = match test_case.process_attestation() {
        Ok(state) => state,
        _ => return Err(()),
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub extern "C" fn attestation_c(
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
