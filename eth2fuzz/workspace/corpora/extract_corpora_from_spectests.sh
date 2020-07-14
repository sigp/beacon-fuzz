#!/bin/bash

git clone --depth 1 --recursive --branch v0.12.1 https://github.com/ethereum/eth2.0-spec-tests
eth2_spectests_dir=./eth2.0-spec-tests/tests/
destination_dir=.

# extract files
# 1st arg: 		folder
# 2nd arg: 		file name
# 3rd arg: 		output dir
extract_file () {

	for file in $(find "$1" -iname "$2")
	do
	    hash=$(md5sum "${file}"|cut -d' ' -f1)
		
		ext=${file##*.}

	    cp "$file" "$3/${hash}.${ext}"
	    # verbose
	    # cp -v "$file" "$3/${hash}.${ext}"
	done
}

# python implementation of similar tool:
# https://github.com/sigp/beacon-fuzz-corpora/blob/master/beacon_fuzz_corpora_tools/corpora_from_tests.py


#### MAINNET
##### PHASE 0 

# Extract beaconstate
# ==> all pre.ssz/post.ssz inside eth2_spectests_dir

mkdir "${destination_dir}/beaconstate"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "pre.ssz" "${destination_dir}/beaconstate"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "post.ssz" "${destination_dir}/beaconstate"

# Extract other containers

mkdir "${destination_dir}/attestation"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "attestation.ssz" "${destination_dir}/attestation"

mkdir "${destination_dir}/attester_slashing"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "attester_slashing.ssz" "${destination_dir}/attester_slashing"

mkdir "${destination_dir}/block"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "block.ssz" "${destination_dir}/block"
# SignedBeaconBlock are inside sanity folder
extract_file "${eth2_spectests_dir}/mainnet/phase0/sanity/" "blocks_*.ssz" "${destination_dir}/block"

mkdir "${destination_dir}/block_header"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "block.ssz" "${destination_dir}/block_header"

mkdir "${destination_dir}/deposit"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "deposit.ssz" "${destination_dir}/deposit"

mkdir "${destination_dir}/proposer_slashing"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "proposer_slashing.ssz" "${destination_dir}/proposer_slashing"

mkdir "${destination_dir}/voluntary_exit"
extract_file "${eth2_spectests_dir}/mainnet/phase0/" "voluntary_exit.ssz" "${destination_dir}/voluntary_exit"

# TODO if needed

rm -rf ./eth2.0-spec-tests

### verify there is no duplicate files
# fdupes -rd .
