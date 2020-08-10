pub mod attestation;
pub mod attester_slashing;
pub mod block;
pub mod block_header;
pub mod deposit;
pub mod proposer_slashing;
pub mod voluntary_exit;

#[link(name = "pfuzz", kind = "static")]
extern "C" {
    fn PrysmMain(bls: bool);
}

/// Initialize Prysm
pub fn init_prysm(disable_bls: bool) {
    unsafe {
        PrysmMain(disable_bls);
    }
}

/// process Attestation container
pub fn process_attestation(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::attestation::process_attestation(beacon, attest, post)
}

/// process AttesterSlashing container
pub fn process_attester_slashing(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::attester_slashing::process_attester_slashing(beacon, attest, post)
}

/// process Block container
pub fn process_block(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::block::process_block(beacon, attest, post)
}

/// process Blockheader container
pub fn process_block_header(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::block_header::process_block_header(beacon, attest, post)
}

/// process Deposit container
pub fn process_deposit(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::deposit::process_deposit(beacon, attest, post)
}

/// process ProposerSlashing container
pub fn process_proposer_slashing(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::proposer_slashing::process_proposer_slashing(beacon, attest, post, true)
}

/// process VoluntaryExit container
pub fn process_voluntary_exit(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::voluntary_exit::process_voluntary_exit(beacon, attest, post)
}
