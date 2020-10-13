use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use crate::util::run_target;
use types::{BeaconState, Deposit, MainnetEthSpec};

// TODO move to common types/util crate?
#[derive(Decode, Encode)]
struct DepositTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub deposit: Deposit,
}

pub fn process_deposit(
    beacon: &BeaconState<MainnetEthSpec>,
    deposit: &Deposit,
    post: &[u8],
    debug: bool,
) -> bool {
    // create testcase ssz struct
    let target: DepositTestCase = DepositTestCase {
        pre: beacon.clone(),
        deposit: deposit.clone(),
    };

    let input_ssz = target.as_ssz_bytes();
    run_target(input_ssz.as_slice(), post, debug)
}
