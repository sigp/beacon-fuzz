.PHONY: default help build fmt clean docker test

#
# Utils for beaconfuzz_v2.
#

default: run

help:
	@echo 'Management commands for beacon-fuzz v2'
	@echo
	@echo 'Usage:'
	@echo '    make build 										Compile the project.'
	@echo '    make fmt 										Run Rust fmt.'
	@echo '    make clean 										Clean the project artifacts.'
	@echo '    make fuzz-* 										Run fuzzing target using honggfuzz.'

# Compile the project
build:
	cargo +nightly build --release --out-dir=. -Z unstable-options

# Run beaconfuzz_v2
run: build
	./beaconfuzz_v2 list

# Compile and run beaconfuzz_v2 with debug command
test: build
	./beaconfuzz_v2 debug beacon.ssz attest.ssz Attestation 

# Compile and run beaconfuzz_v2 with fuzz command
test-fuzz: build
	./beaconfuzz_v2 fuzz attestation

# Run Rust fmt to make code cleaner
fmt:
	cargo fmt --all

# Clean the project.
clean:
	cargo clean
	rm -rf target
	rm -rf ./beaconfuzz_v2

# Compile the project (called by docker)
build-docker:
	CARGO_PRYSM_DIR=../../prysm \
	CARGO_NIMBUS_DIR=../../nim-beacon-chain \
	cargo +nightly build --release --out-dir=. -Z unstable-options

## Create the beaconfuzz_v2 docker
docker:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/Dockerfile \
	-t beaconfuzz_v2 \
	. \
	$(CACHE)
	@echo 'USAGE: docker run -it -v beaconfuzz_v2'

fuzz_attestation:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo hfuzz run diff_attestation --release
fuzz_attestation-struct:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo +nightly fuzz run struct_attestation --release

fuzz_attester_slashing:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo hfuzz run diff_attester_slashing --release

fuzz_attester_slashing-struct:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo +nightly fuzz run struct_attester_slashing --release

fuzz_block:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo hfuzz run diff_block --release

fuzz_block-struct:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo +nightly fuzz run struct_block --release

# TODO - fix this one
#fuzz_block_header:
#	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_block_header

fuzz_deposit:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo hfuzz run diff_deposit --release

fuzz_deposit-struct:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo +nightly fuzz run struct_deposit --release

fuzz_proposer_slashing:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo hfuzz run diff_proposer_slashing --release

fuzz_proposer_slashing-struct:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo +nightly fuzz run struct_proposer_slashing --release

fuzz_voluntary_exit:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo hfuzz run diff_voluntary_exit --release

fuzz_voluntary_exit-struct:
	ASAN_OPTIONS=detect_leaks=0 \
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate \
	cargo +nightly fuzz run struct_voluntary_exit --release

pfuzz:
	echo "TODO"
	# cd ../../prysm/; export GOPATH=$(pwd);
	# cd pfuzz ; go get .
	# go build -o libpfuzz.a -buildmode=c-archive pfuzz.go


#
# CI utils
#

# Check code style quickly by running `rustfmt` over all code
check-fmt:
	cargo fmt --all -- --check