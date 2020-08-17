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

## Create the beaconfuzz_v2 docker
docker:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/Dockerfile \
	-t beaconfuzz_v2 \
	. \
	$(CACHE)
	@echo 'USAGE: docker run -it -v beaconfuzz_v2'

fuzz_attestation:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_attestation

fuzz_attestation-struct:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo +nightly fuzz run struct_attestation

fuzz_attester_slashing:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_attester_slashing

fuzz_attester_slashing-struct:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo +nightly fuzz run struct_attester_slashing

fuzz_block:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_block

fuzz_block-struct:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo +nightly fuzz run struct_block

# TODO - fix this one
#fuzz_block_header:
#	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_block_header

fuzz_deposit:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_deposit

fuzz_deposit-struct:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo +nightly fuzz run struct_deposit

fuzz_proposer_slashing:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_proposer_slashing

fuzz_proposer_slashing-struct:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo +nightly fuzz run struct_proposer_slashing

fuzz_voluntary_exit:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_voluntary_exit

fuzz_voluntary_exit-struct:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo +nightly fuzz run struct_voluntary_exit

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