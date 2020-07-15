.PHONY: default update check-fmt help build docker corpora fmt clippy clean clean-all test test-debug test-hfuzz test-afl test-libfuzzer test-nim-libfuzzer test-all

#
# User utils
#

default: build

help:
	@echo 'Management commands for eth2fuzz'
	@echo
	@echo 'Usage:'
	@echo '    make build 										Compile the project.'
	@echo '    make corpora		 								Create an initial corpora.'
	@echo
	@echo '    make fmt 										Run Rust fmt.'
	@echo '    make clean 										Clean only eth2fuzz binary.'
	@echo '    make clean-all 									Clean all (eth2fuzz && compiled fuzz target harnesses).'
	@echo
	@echo '    make test		 								Simple test to check if eth2fuzz is working.'
	@echo '    make test-debug		 							Test running a simple wasm to a debugging tool.'
	@echo '    make test-{libfuzzer, hfuzz, afl}				Test one fuzzing hardness over choosen fuzzer.'
	@echo '    make test-all		 							Test one fuzzing hardness over all fuzzers.'
	@echo '    make test-continuously-{libfuzzer, hfuzz, afl}	Test all fuzzing hardness over choosen fuzzer.'
	@echo
	@echo 'TODO - add other commands'


# Build the project locally
build:
	cargo +nightly build --release --out-dir=. -Z unstable-options

# Create an initial corpora
corpora:
	cd workspace/corpora/ && ./extract_corpora_from_spectests.sh

#
# Developer utils
#

# Run Rust fmt to make code cleaner
fmt:
	cargo fmt --all

# Run Rust clippy to make code cleaner
clippy:
	cargo clippy --all

#
# Eth2fuzz
#

# Clean only eth2fuzz target
clean:
	rm -rf target/

#
# ALL CLIENTS
#

## Build all docker
docker-all: lighthouse lodestar nimbus prysm teku

## Fuzz all eth2 clients
fuzz-all: fuzz-lighthouse fuzz-lodestar fuzz-nimbus fuzz-prysm fuzz-teku

# Clean all (eth2fuzz && compiled fuzz target harnesses).
clean-all: clean clean-lighthouse clean-nimbus clean-prysm
	rm -rf workspace/debug/target
	# clean js - not needed
	# clean java libfuzzer - TODO

#
# Lighthouse
# https://github.com/sigp/lighthouse
#

## Fuzzing of lighthouse using docker.
lighthouse:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/lighthouse.Dockerfile \
	-t eth2fuzz_lighthouse \
	. \
	$(CACHE)
	@echo 'USAGE: docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse list'

## Fuzz all lighthouse targets during 1 hour each
fuzz-lighthouse: lighthouse
	docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse continuously -q lighthouse -t 3600 -n 1

## Try to run each targets for 1 sec
test-lighthouse:
	for i in $(shell docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse list); do \
		docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse target $$i -t 1; \
	done

## clean compiled fuzzing targets
clean-lighthouse:
	# clean lighthouse afl
	rm -rf workspace/afl/target
	# clean lighthouse hfuzz
	rm -rf workspace/hfuzz/hfuzz_target
	# clean lighthouse libfuzzer
	rm -rf workspace/libfuzzer/fuzz/target

#
# Lodestar
# https://github.com/ChainSafe/lodestar
#

## Fuzzing of lodestar using docker.
lodestar:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/lodestar.Dockerfile \
	-t eth2fuzz_lodestar \
	. \
	$(CACHE)
	@echo 'USAGE: docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lodestar list'

## Fuzz all lodestar targets during 1 hour each
fuzz-lodestar: lodestar
	docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lodestar continuously -q lodestar -t 3600

## Try to run each targets for 1 sec
test-lodestar:
	for i in $(shell docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lodestar list); do \
		docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lodestar target $$i -t 1; test $$? -eq 1; \
	done

## Nothing to clean with lodestar since there
## is not compiled fuzzing targets
clean-lodestar:

#
# Nimbus
# https://github.com/status-im/nim-beacon-chain
#

## Fuzzing of nim-beacon-chain using docker.
nimbus:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/nimbus.Dockerfile \
	-t eth2fuzz_nimbus \
	. \
	$(CACHE)
	@echo 'USAGE: docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus list'

## Fuzz all nimbus targets during 1 hour each
fuzz-nimbus: nimbus
	docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus continuously -q nimbus -t 3600

## Try to run each targets for 1 sec
test-nimbus:
	for i in $(shell docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus list); do \
		docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus target $$i -t 1; \
	done

## clean compiled fuzzing targets
clean-nimbus:
	for i in $(shell docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus list); do \
		rm -rf workspace/nimlibfuzzer/$$i; \
	done

#
# Prysm
# https://github.com/prysmaticlabs/prysm
#

## Fuzzing of prysm using docker.
prysm:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/prysm.Dockerfile \
	-t eth2fuzz_prysm \
	. \
	$(CACHE)
	@echo 'USAGE: docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_prysm list'

## Fuzz all prysm targets during 1 hour each
fuzz-prysm: prysm
	docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_prysm continuously -q prysm -t 3600

## Try to run each targets for 1 sec
test-prysm:
	for i in $(shell docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_prysm list); do \
		docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_prysm target $$i -t 1; \
	done

## clean compiled fuzzing targets
clean-prysm:
	# clean gofuzz libfuzzer
	rm -rf workspace/gofuzz/*.libfuzzer

#
# Teku
# https://github.com/PegaSysEng/teku
#

## Fuzzing of teku using docker.
teku:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/teku.Dockerfile \
	-t eth2fuzz_teku \
	. \
	$(CACHE)
	@echo 'USAGE: docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_teku list'

## Fuzz all teku targets during 1 hour each
fuzz-teku: teku
	docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_teku continuously -q teku -t 3600

## Try to run each targets for 1 sec
test-teku:
	for i in $(shell docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_teku list); do \
		docker run -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_teku target $$i -t 1; test $$? -eq 1; \
	done

## clean compiled fuzzing targets
clean-teku:
	# clean javafuzz
	rm -rf workspace/javafuzz/T*.class

#
# Testing utils
#

# Simple test to check if eth2fuzz is working.
test: build
	./eth2fuzz list

# Test running a simple wasm to a debugging tool.
test-debug: build
	./eth2fuzz debug lighthouse_attestation
	./workspace/debug/target/debug/debug_lighthouse_attestation \
		workspace/corpora/beaconstate/004a360e8f5b1d4a32c158c2c688fc4e.ssz \
		workspace/corpora/attestation/05db7ea93a4ee2467a1a04f3a0fa8f38.ssz

# Run one fuzzing hardness over honggfuzz during 2s
test-hfuzz: build
	./eth2fuzz target lighthouse_attestation -t 2

# Run one fuzzing hardness over afl during 2s
test-afl: build
	./eth2fuzz target lighthouse_attestation --fuzzer afl -t 2

# Run one fuzzing hardness over libfuzzer during 2s
test-libfuzzer: build
	./eth2fuzz target lighthouse_attestation --fuzzer libfuzzer -t 2

# Run one fuzzing hardness over nim-libfuzzer during 2s
test-nim-libfuzzer: build
	./eth2fuzz target nimbus_enr --fuzzer NimLibfuzzer -t 2

# Run one fuzzing hardness over all fuzzer
test-all: test-hfuzz test-afl test-libfuzzer test-nim-libfuzzer

# Run all fuzzing hardness over honggfuzz
test-continuously-hfuzz: build
	./eth2fuzz continuously -t 2 --fuzzer honggfuzz

# Run all fuzzing hardness over libfuzzer
test-continuously-libfuzzer: build
	./eth2fuzz continuously -t 2 --fuzzer libfuzzer

# Run all fuzzing hardness over afl
test-continuously-afl: build
	./eth2fuzz continuously -t 2 --fuzzer afl


#
# CI utils
#

# Check code style quickly by running `rustfmt` over all code
check-fmt:
	cargo fmt --all -- --check

# Check code quality by running `clippy` over all code
check-clippy:
	cargo clippy --all
