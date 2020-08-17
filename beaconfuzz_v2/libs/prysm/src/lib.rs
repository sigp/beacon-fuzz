pub mod attestation;
pub mod attester_slashing;
pub mod block;
pub mod block_header;
pub mod debug;
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

static DEBUG: bool = false;

// SSZ decoding

/// SSZ decoding for Attestation container
pub fn ssz_attestation(input: &[u8]) -> bool {
    self::attestation::ssz_attestation(input)
}

/// SSZ decoding for AttesterSlashing container
pub fn ssz_attester_slashing(input: &[u8]) -> bool {
    self::attester_slashing::ssz_attester_slashing(input)
}

/// SSZ decoding for Block container
pub fn ssz_block(input: &[u8]) -> bool {
    self::block::ssz_block(input)
}

/// SSZ decoding for BlockHeader container
pub fn ssz_block_header(input: &[u8]) -> bool {
    self::block_header::ssz_block_header(input)
}

/// SSZ decoding for Deposit container
pub fn ssz_deposit(input: &[u8]) -> bool {
    self::deposit::ssz_deposit(input)
}

/// SSZ decoding for ProposerSlashing container
pub fn ssz_proposer_slashing(input: &[u8]) -> bool {
    self::proposer_slashing::ssz_proposer_slashing(input)
}

/// SSZ decoding for VoluntaryExit container
pub fn ssz_voluntary_exit(input: &[u8]) -> bool {
    self::voluntary_exit::ssz_voluntary_exit(input)
}

/// process Attestation container
pub fn process_attestation(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::attestation::process_attestation(beacon, attest, post, DEBUG)
}

/// process AttesterSlashing container
pub fn process_attester_slashing(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::attester_slashing::process_attester_slashing(beacon, attest, post, DEBUG)
}

/// process Block container
pub fn process_block(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::block::process_block(beacon, attest, post, DEBUG)
}

/// process Blockheader container
pub fn process_block_header(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::block_header::process_block_header(beacon, attest, post, DEBUG)
}

/// process Deposit container
pub fn process_deposit(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::deposit::process_deposit(beacon, attest, post, DEBUG)
}

/// process ProposerSlashing container
pub fn process_proposer_slashing(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::proposer_slashing::process_proposer_slashing(beacon, attest, post, DEBUG)
}

/// process VoluntaryExit container
pub fn process_voluntary_exit(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    self::voluntary_exit::process_voluntary_exit(beacon, attest, post, DEBUG)
}
