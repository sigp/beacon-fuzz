use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
};
use std::{ptr, slice};
use types::{BeaconBlock, BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch};

#[derive(Decode, Encode)]
struct BlockTestCase<T: EthSpec> {
    pub pre: BeaconState<T>,
    pub block: BeaconBlock<T>,
}

impl<T: EthSpec> BlockTestCase<T> {
    /// Run `process_block` and return a `BeaconState` on success, or a
    /// `BlockProcessingError` on failure.
    /// TODO N convert to a library in lighthouse that we import
    /// Most of this is copied from lighthouse/ef_tests/src/cases/sanity_blocks.rs,
    /// as lighthouse doesn't directly implement the state_transition function.

    // TODO N why doesn't this need to be mutable, because self.pre is mutable?
    fn state_transition(mut self) -> Result<BeaconState<T>, BlockProcessingError> {
        let spec = &T::default_spec();
        let mut state = self.pre; // No need to clone here, but means state_transition can only be called once?
        let block = self.block;

        // TODO N any reason why we would want to unwrap and panic here vs returning an error?
        state.build_all_caches(spec).unwrap();
        let result = {
            while state.slot < block.slot {
                // TODO handle option
                per_slot_processing(&mut state, spec).unwrap();
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

        if block.state_root == result.canonical_root() {
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
        _ => return Err(()),
    };

    let post_state: BeaconState<T> = match test_case.state_transition() {
        Ok(state) => state,
        _ => return Err(()),
    };

    Ok(post_state.as_ssz_bytes())
}

#[no_mangle]
pub fn block_c(
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
