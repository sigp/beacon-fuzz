use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
};
use std::{ptr, slice};
use types::{BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch, SignedBeaconBlock};

#[derive(Decode, Encode)]
struct BlockTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub block: SignedBeaconBlock<T>,
}

impl<T: EthSpec> BlockTestCase<T> {
    /// Run `process_block` and return a `BeaconState` on success, or a
    /// `BlockProcessingError` on failure.
    /// TODO N convert to a library in lighthouse that we import
    /// Most of this is copied from lighthouse/ef_tests/src/cases/sanity_blocks.rs,
    /// as lighthouse doesn't directly implement the state_transition function.

    fn state_transition(
        self,
        validate_state_root: bool,
    ) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = &T::default_spec();
        let mut state = self.pre; // No need to clone here, but means state_transition can only be called once?
        let block = self.block;

        // TODO(gnattishness) any reason why we would want to unwrap and panic here vs returning an error?
        state.build_all_caches(spec).unwrap();
        let result = {
            while state.slot < block.slot() {
                // TODO(gnattishness) handle option
                // requires implementation of an error trait that I can specify as the
                // return type
                per_slot_processing(&mut state, None, spec).unwrap();
            }

            state
                .build_committee_cache(RelativeEpoch::Current, spec)
                .unwrap();

            per_block_processing(
                &mut state,
                &block,
                None,
                BlockSignatureStrategy::VerifyIndividual,
                spec,
            )?;
            state
        };

        if !validate_state_root || block.state_root() == result.canonical_root() {
            Ok(result)
        } else {
            Err(BlockProcessingError::StateRootMismatch)
        }
    }
}

/// Accepts an SSZ-encoded `BlockTestCase` and returns an SSZ-encoded post-state on success,
/// or nothing on failure.
fn fuzz<T: EthSpec>(ssz_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let test_case = match BlockTestCase::from_ssz_bytes(&ssz_bytes) {
        Ok(test_case) => test_case,
        Err(e) => panic!(
            "rs deserialization failed. Preproc should ensure decodable: {:?}",
            e
        ),
    };

    // TODO(gnattishness) allow validate_state_root to be enabled/disabled at compile time
    // e.g. https://doc.rust-lang.org/cargo/reference/manifest.html
    // https://stackoverflow.com/questions/32291210/how-to-choose-between-macros-at-compile-time
    let post_state: BeaconState<T> = match test_case.state_transition(true) {
        Ok(state) => state,
        _ => return Err(()),
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub extern "C" fn block_c(
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
