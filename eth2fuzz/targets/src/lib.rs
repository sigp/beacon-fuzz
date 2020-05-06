extern crate ssz;

use ssz::{Decode, Encode};
//use ssz_derive::{Decode, Encode};

use types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, Deposit, MainnetEthSpec,
    ProposerSlashing, SignedBeaconBlock, SignedVoluntaryExit,
};


mod attestation;
#[inline(always)]
pub fn fuzz_lighthouse_attestation(data: &[u8], beaconstate: BeaconState<MainnetEthSpec>) {

    // extract state_if from attestation testcase
    let attestation = match Attestation::from_ssz_bytes(&data) {
        Ok(attestation) => attestation,
        Err(_e) => return,
    };

    let target: attestation::AttestationTestCase<MainnetEthSpec> =
        attestation::AttestationTestCase {
            pre: beaconstate,
            attestation: attestation,
        };
    let _post_state = target.process_attestation();
}

mod attester_slashing;
#[inline(always)]
pub fn fuzz_lighthouse_attester_slashing(data: &[u8], beaconstate: BeaconState<MainnetEthSpec>) {

    let attester_slashing = match AttesterSlashing::from_ssz_bytes(&data) {
        Ok(attester_slashing) => attester_slashing,
        Err(_e) => return,
    };

    let target: attester_slashing::AttesterSlashingTestCase<MainnetEthSpec> =
        attester_slashing::AttesterSlashingTestCase {
            pre: beaconstate,
            attester_slashing: attester_slashing,
        };
    let _post_state = target.process_attester_slashing();
}

mod block;
#[inline(always)]
pub fn fuzz_lighthouse_block(data: &[u8], beaconstate: BeaconState<MainnetEthSpec>) {

    let block = match SignedBeaconBlock::from_ssz_bytes(&data) {
        Ok(block) => block,
        Err(_e) => return,
    };

    let target: block::BlockTestCase<MainnetEthSpec> =
        block::BlockTestCase {
            pre: beaconstate,
            block: block,
        };
    let _post_state = target.state_transition(true);
}


mod block_header;
#[inline(always)]
pub fn fuzz_lighthouse_block_header(data: &[u8], beaconstate: BeaconState<MainnetEthSpec>) {

    let block_header = match BeaconBlock::from_ssz_bytes(&data) {
        Ok(block_header) => block_header,
        Err(_e) => return,
    };

    let target: block_header::BlockHeaderTestCase<MainnetEthSpec> =
        block_header::BlockHeaderTestCase {
            pre: beaconstate,
            block: block_header,
        };
    let _post_state = target.process_header();
}

mod deposit;
#[inline(always)]
pub fn fuzz_lighthouse_deposit(data: &[u8], beaconstate: BeaconState<MainnetEthSpec>) {

    let deposit = match Deposit::from_ssz_bytes(&data) {
        Ok(deposit) => deposit,
        Err(_e) => return,
    };

    let target: deposit::DepositTestCase<MainnetEthSpec> =
        deposit::DepositTestCase {
            pre: beaconstate,
            deposit: deposit,
        };
    let _post_state = target.process_deposit();
}

mod proposer_slashing;
#[inline(always)]
pub fn fuzz_lighthouse_proposer_slashing(data: &[u8], beaconstate: BeaconState<MainnetEthSpec>) {

    let proposer_slashing = match ProposerSlashing::from_ssz_bytes(&data) {
        Ok(proposer_slashing) => proposer_slashing,
        Err(_e) => return,
    };

    let target: proposer_slashing::ProposerSlashingTestCase<MainnetEthSpec> =
        proposer_slashing::ProposerSlashingTestCase {
            pre: beaconstate,
            proposer_slashing: proposer_slashing,
        };
    let _post_state = target.process_proposer_slashing();
}

mod voluntary_exit;
#[inline(always)]
pub fn fuzz_lighthouse_voluntary_exit(data: &[u8], beaconstate: BeaconState<MainnetEthSpec>) {

    let voluntary_exit = match SignedVoluntaryExit::from_ssz_bytes(&data) {
        Ok(voluntary_exit) => voluntary_exit,
        Err(_e) => return,
    };

    let target: voluntary_exit::VoluntaryExitTestCase<MainnetEthSpec> =
        voluntary_exit::VoluntaryExitTestCase {
            pre: beaconstate,
            voluntary_exit: voluntary_exit,
        };
    let _post_state = target.process_voluntary_exit();
}

mod beaconstate;
#[inline(always)]
pub fn fuzz_lighthouse_beaconstate(data: &[u8], _beaconstate: BeaconState<MainnetEthSpec>) {

    // we are not using the provided beaconstate here

    let mut beaconstate = match BeaconState::from_ssz_bytes(&data) {
        Ok(beaconstate) => beaconstate,
        _ => return,
    };

    beaconstate::fuzz_beaconstate_accessors(&mut beaconstate);
}
