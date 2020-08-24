# For use inside docker container or if building eth2fuzz locally
#
# Not platform/shell agnostic

SHELL := /bin/sh

.PHONY: help clean test test-debug test-hfuzz test-afl test-libfuzzer test-nim-libfuzzer test-all

#
# Eth2fuzz
#

# Build the project locally
build:
	cargo +nightly build --release --out-dir=. -Z unstable-options

# Clean only eth2fuzz target
# TODO should this be in the main Makefile too?
clean:
	rm -rf target/

help:
	@echo 'Management commands for eth2fuzz'
	@echo
	@echo 'Usage:'
	@echo '    make build 										Compile the eth2fuzz CLI binary.'
	@echo '    make clean 										Clean only eth2fuzz binary.'
	@echo '    make test-build		 								Simple test to check if eth2fuzz is working.'
	@echo '    make test-debug		 							Test running a simple wasm to a debugging tool.'
	@echo '    make test-{libfuzzer, hfuzz, afl}				Test one fuzzing harness over choosen fuzzer.'
	@echo '    make test-all		 							Test one fuzzing harness over all fuzzers.'
	@echo '    make test-continuously-{libfuzzer, hfuzz, afl}	Test all fuzzing harness over choosen fuzzer.'

#
# Testing utils
#

# Simple test to check if eth2fuzz is working.
test-build: build
	./eth2fuzz list

# Test running a simple wasm to a debugging tool.
test-debug: build
	./eth2fuzz debug lighthouse_attestation
	./workspace/debug/target/debug/debug_lighthouse_attestation $(n)
		workspace/corpora/beaconstate/004a360e8f5b1d4a32c158c2c688fc4e.ssz $(n)
		workspace/corpora/attestation/05db7ea93a4ee2467a1a04f3a0fa8f38.ssz

# Run one fuzzing harness over honggfuzz for 2s
test-hfuzz: build
	./eth2fuzz target lighthouse_attestation -t 2

# Run one fuzzing harness over afl for 2s
test-afl: build
	./eth2fuzz target lighthouse_attestation --fuzzer afl -t 2

# Run one fuzzing harness over libfuzzer for 2s
test-libfuzzer: build
	./eth2fuzz target lighthouse_attestation --fuzzer libfuzzer -t 2

# Run one fuzzing harness over nim-libfuzzer for 2s
test-nim-libfuzzer: build
	./eth2fuzz target nimbus_enr --fuzzer NimLibfuzzer -t 2

# Run one fuzzing harness over all fuzzer
test-all: test-hfuzz test-afl test-libfuzzer test-nim-libfuzzer

# Run all fuzzing harness over honggfuzz
test-continuously-hfuzz: build
	./eth2fuzz continuously -t 2 --fuzzer honggfuzz

# Run all fuzzing harness over libfuzzer
test-continuously-libfuzzer: build
	./eth2fuzz continuously -t 2 --fuzzer libfuzzer

# Run all fuzzing harness over afl
test-continuously-afl: build
	./eth2fuzz continuously -t 2 --fuzzer afl
