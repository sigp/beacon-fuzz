pub fn initialize_clients(disable_bls: bool) {
    prysm::init_prysm(disable_bls);
    nimbus::init_nimbus(disable_bls);
}

pub mod attestation;
pub mod attester_slashing;
pub mod block;
pub mod block_header;
pub mod deposit;
pub mod proposer_slashing;
pub mod voluntary_exit;

pub fn run_attestation(beacon_blob: &[u8], container_blob: &[u8]) {
    self::attestation::run_attestation(beacon_blob, container_blob, true)
}
pub fn fuzz_attestation(beacon_blob: &[u8], container_blob: &[u8]) {
    self::attestation::run_attestation(beacon_blob, container_blob, false)
}
pub fn run_attester_slashing(beacon_blob: &[u8], container_blob: &[u8]) {
    self::attester_slashing::run_attester_slashing(beacon_blob, container_blob, true)
}
pub fn fuzz_attester_slashing(beacon_blob: &[u8], container_blob: &[u8]) {
    self::attester_slashing::run_attester_slashing(beacon_blob, container_blob, false)
}
pub fn run_block(beacon_blob: &[u8], container_blob: &[u8]) {
    self::block::run_block(beacon_blob, container_blob, true)
}
pub fn fuzz_block(beacon_blob: &[u8], container_blob: &[u8]) {
    self::block::run_block(beacon_blob, container_blob, false)
}
pub fn run_block_header(beacon_blob: &[u8], container_blob: &[u8]) {
    println!("TODO FIX");
    // self::block_header::run_block_header(beacon_blob, container_blob, true)
}
pub fn run_deposit(beacon_blob: &[u8], container_blob: &[u8]) {
    self::deposit::run_deposit(beacon_blob, container_blob, true)
}
pub fn fuzz_deposit(beacon_blob: &[u8], container_blob: &[u8]) {
    self::deposit::run_deposit(beacon_blob, container_blob, false)
}
pub fn run_proposer_slashing(beacon_blob: &[u8], container_blob: &[u8]) {
    self::proposer_slashing::run_proposer_slashing(beacon_blob, container_blob, true)
}
pub fn fuzz_proposer_slashing(beacon_blob: &[u8], container_blob: &[u8]) {
    self::proposer_slashing::run_proposer_slashing(beacon_blob, container_blob, false)
}

pub fn run_voluntary_exit(beacon_blob: &[u8], container_blob: &[u8]) {
    self::voluntary_exit::run_voluntary_exit(beacon_blob, container_blob, true)
}
pub fn fuzz_voluntary_exit(beacon_blob: &[u8], container_blob: &[u8]) {
    self::voluntary_exit::run_voluntary_exit(beacon_blob, container_blob, false)
}
