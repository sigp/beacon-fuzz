use types::{BeaconState, ChainSpec, MainnetEthSpec, RelativeEpoch};

// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#beacon-state-accessors
pub fn fuzz_beaconstate_accessors(beaconstate: &mut BeaconState<MainnetEthSpec>) {
    let chainspec = ChainSpec::mainnet();

    // pub fn canonical_root(&self) -> Hash256 {
    let hash256 = beaconstate.canonical_root();

    // pub fn historical_batch(&self) -> HistoricalBatch<T> {
    let _ = beaconstate.historical_batch();

    // pub fn get_validator_index(&self, pubkey: &PublicKeyBytes) -> Result<Option<usize>, Error> {

    // pub fn current_epoch(&self) -> Epoch {
    let epoch = beaconstate.current_epoch();

    // pub fn previous_epoch(&self) -> Epoch {
    let _ = beaconstate.previous_epoch();

    // pub fn next_epoch(&self) -> Epoch {
    let _ = beaconstate.next_epoch();

    // pub fn get_committee_count_at_slot(&self, slot: Slot) -> Result<u64, Error> {
    let _ = beaconstate.get_committee_count_at_slot(beaconstate.slot);

    // pub fn get_epoch_committee_count(&self, relative_epoch: RelativeEpoch) -> Result<u64, Error> {
    let _ = beaconstate.get_epoch_committee_count(RelativeEpoch::Previous);
    let _ = beaconstate.get_epoch_committee_count(RelativeEpoch::Current);
    let _ = beaconstate.get_epoch_committee_count(RelativeEpoch::Next);

    // pub fn get_cached_active_validator_indices(&self,relative_epoch: RelativeEpoch,
    let _ = beaconstate.get_cached_active_validator_indices(RelativeEpoch::Previous);
    let _ = beaconstate.get_cached_active_validator_indices(RelativeEpoch::Current);
    let _ = beaconstate.get_cached_active_validator_indices(RelativeEpoch::Next);

    // pub fn get_active_validator_indices(&self, epoch: Epoch) -> Vec<usize> {
    //let _ = beaconstate.get_active_validator_indices(epoch);

    // pub fn get_shuffling(&self, relative_epoch: RelativeEpoch) -> Result<&[usize], Error> {
    let _ = beaconstate.get_shuffling(RelativeEpoch::Previous);
    let _ = beaconstate.get_shuffling(RelativeEpoch::Current);
    let _ = beaconstate.get_shuffling(RelativeEpoch::Next);

    // pub fn get_beacon_committee(&self, slot: Slot, index: CommitteeIndex)
    let _ = beaconstate.get_beacon_committee(beaconstate.slot, 0);

    // pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<BeaconCommittee>, Error> {
    let _ = beaconstate.get_beacon_committees_at_slot(beaconstate.slot);

    // pub fn get_beacon_committees_at_epoch(&self, relative_epoch: RelativeEpoch)
    let _ = beaconstate.get_beacon_committees_at_epoch(RelativeEpoch::Previous);
    let _ = beaconstate.get_beacon_committees_at_epoch(RelativeEpoch::Current);
    let _ = beaconstate.get_beacon_committees_at_epoch(RelativeEpoch::Next);

    // pub fn compute_proposer_index(&self, indices: &[usize], seed: &[u8], spec: &ChainSpec,

    // pub fn get_beacon_proposer_index(&self, slot: Slot, spec: &ChainSpec) -> Result<usize, Error> {
    let _ = beaconstate.get_beacon_proposer_index(beaconstate.slot, &chainspec);

    // pub fn get_latest_block_root(&self, current_state_root: Hash256) -> Hash256 {
    let _ = beaconstate.get_latest_block_root(hash256);

    // pub fn get_block_root(&self, slot: Slot) -> Result<&Hash256, BeaconStateError> {
    let _ = beaconstate.get_block_root(beaconstate.slot);

    // pub fn get_block_root_at_epoch(&self, epoch: Epoch) -> Result<&Hash256, BeaconStateError> {
    let _ = beaconstate.get_block_root_at_epoch(epoch);

    // pub fn set_block_root(&mut self,slot: Slot,block_root: Hash256)
    let _ = beaconstate.set_block_root(beaconstate.slot, hash256);

    // pub fn fill_randao_mixes_with(&mut self, index_root: Hash256) {
    let _ = beaconstate.fill_randao_mixes_with(hash256);

    // pub fn update_randao_mix(&mut self, epoch: Epoch, signature: &Signature) -> Result<(), Error> {

    // pub fn get_randao_mix(&self, epoch: Epoch) -> Result<&Hash256, Error> {
    let _ = beaconstate.get_randao_mix(epoch);

    // pub fn set_randao_mix(&mut self, epoch: Epoch, mix: Hash256) -> Result<(), Error> {
    let _ = beaconstate.set_randao_mix(epoch, hash256);

    // pub fn get_state_root(&self, slot: Slot) -> Result<&Hash256, Error> {
    let _ = beaconstate.get_state_root(beaconstate.slot);

    // pub fn get_oldest_state_root(&self) -> Result<&Hash256, Error> {
    let _ = beaconstate.get_oldest_state_root();

    // pub fn get_oldest_block_root(&self) -> Result<&Hash256, Error> {
    let _ = beaconstate.get_oldest_block_root();

    // pub fn set_state_root(&mut self, slot: Slot, state_root: Hash256) -> Result<(), Error> {
    let _ = beaconstate.set_state_root(beaconstate.slot, hash256);

    // pub fn get_all_slashings(&self) -> &[u64] {
    let _ = beaconstate.get_all_slashings();

    // pub fn get_slashings(&self, epoch: Epoch) -> Result<u64, Error> {
    let _ = beaconstate.get_slashings(epoch);

    // pub fn set_slashings(&mut self, epoch: Epoch, value: u64) -> Result<(), Error> {
    let _ = beaconstate.set_slashings(epoch, 0);

    // pub fn get_matching_source_attestations(        &self,epoch: Epoch,
    let _ = beaconstate.get_matching_source_attestations(epoch);

    // pub fn get_seed(&self,epoch: Epoch,domain_type: Domain,spec: &ChainSpec,
    // pub fn get_effective_balance(&self,validator_index: usize,_spec: &ChainSpec,
    let _ = beaconstate.get_effective_balance(0, &chainspec);

    // pub fn compute_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
    let _ = beaconstate.compute_activation_exit_epoch(epoch, &chainspec);

    // pub fn get_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
    let _ = beaconstate.get_churn_limit(&chainspec);

    // pub fn get_attestation_duties(&self,validator_index: usize,relative_epoch: RelativeEpoch,
    let _ = beaconstate.get_attestation_duties(0, RelativeEpoch::Previous);
    let _ = beaconstate.get_attestation_duties(0, RelativeEpoch::Current);
    let _ = beaconstate.get_attestation_duties(0, RelativeEpoch::Next);

    // pub fn get_total_balance(&self, validator_indices: &[usize], spec: &ChainSpec,

    // pub fn build_all_caches(&mut self, spec: &ChainSpec) -> Result<(), Error> {
    // TODO - commented for performance reasons
    // let _ = beaconstate.build_all_caches(&chainspec);

    // pub fn build_all_committee_caches(&mut self, spec: &ChainSpec) -> Result<(), Error> {
    let _ = beaconstate.build_all_committee_caches(&chainspec);

    // pub fn drop_all_caches(&mut self) {
    let _ = beaconstate.drop_all_caches();

    // pub fn build_committee_cache(        &mut self,relative_epoch: RelativeEpoch,spec: &ChainSpec,
    let _ = beaconstate.build_committee_cache(RelativeEpoch::Previous, &chainspec);
    let _ = beaconstate.build_committee_cache(RelativeEpoch::Current, &chainspec);
    let _ = beaconstate.build_committee_cache(RelativeEpoch::Next, &chainspec);

    // pub fn force_build_committee_cache(        &mut self,relative_epoch: RelativeEpoch,spec: &ChainSpec,
    let _ = beaconstate.force_build_committee_cache(RelativeEpoch::Previous, &chainspec);
    let _ = beaconstate.force_build_committee_cache(RelativeEpoch::Current, &chainspec);
    let _ = beaconstate.force_build_committee_cache(RelativeEpoch::Next, &chainspec);

    // pub fn advance_caches(&mut self) {
    let _ = beaconstate.advance_caches();

    // pub fn committee_cache(&self, relative_epoch: RelativeEpoch) -> Result<&CommitteeCache, Error> {
    let _ = beaconstate.committee_cache(RelativeEpoch::Previous);
    let _ = beaconstate.committee_cache(RelativeEpoch::Current);
    let _ = beaconstate.committee_cache(RelativeEpoch::Next);

    // pub fn update_pubkey_cache(&mut self) -> Result<(), Error> {
    let _ = beaconstate.update_pubkey_cache();

    // pub fn drop_pubkey_cache(&mut self) {
    let _ = beaconstate.drop_pubkey_cache();

    // pub fn initialize_tree_hash_cache(&mut self) {
    let _ = beaconstate.initialize_tree_hash_cache();

    // pub fn update_tree_hash_cache(&mut self) -> Result<Hash256, Error> {
    let _ = beaconstate.update_tree_hash_cache();

    // pub fn drop_tree_hash_cache(&mut self) {
    let _ = beaconstate.drop_tree_hash_cache();

    // pub fn decompress_validator_pubkeys(&mut self) -> Result<(), Error> {
    // deprecated in v0.2.0
    // let _ = beaconstate.decompress_validator_pubkeys();

    // pub fn clone_with(&self, config: CloneConfig) -> Self {

    // pub fn clone_with_only_committee_caches(&self) -> Self {
    let _ = beaconstate.clone_with_only_committee_caches();
}
