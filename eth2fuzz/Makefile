.PHONY: default update check-fmt help build docker corpora fmt clean clean-all

#
# User utils
#

default: build

help:
	@echo 'Management commands for eth2fuzz'
	@echo
	@echo 'Usage:'
	@echo '    make build 										Compile the project.'
	@echo '    make docker										Build a docker image for this project.'
	@echo '    make corpora		 								Test eth2 clients with valid state + block files.'
	@echo
	@echo '    make fmt 										Run Rust fmt.'
	@echo '    make clean 										Clean only eth2fuzz binary.'
	@echo '    make clean-all 									Clean all (eth2fuzz && compiled fuzz target harnesses).'



# Build the project locally
build:
	cargo +nightly build --release --out-dir=. -Z unstable-options

# TODO
test: build
	./eth2fuzz list-targets

# TODO
test-debug: build
	./eth2fuzz debug lighthouse_attestation
	./workspace/debug/target/debug/debug_lighthouse_attestation \
		workspace/corpora/beaconstate/004a360e8f5b1d4a32c158c2c688fc4e.ssz \
		workspace/corpora/attestation/05db7ea93a4ee2467a1a04f3a0fa8f38.ssz

test-hfuzz: build
	./eth2fuzz target lighthouse_attestation \
		-t 2

test-afl: build
	./eth2fuzz target lighthouse_attestation \
		--fuzzer afl \
		-t 2

test-libfuzzer: build
	./eth2fuzz target lighthouse_attestation \
		--fuzzer libfuzzer \
		-t 2

# Build the docker
# NOTE: `make docker CACHE=--no-cache` to force docker update/build everything again
docker:
	echo "TODO docker"

# Create an initial corpora of wasm modules
corpora:
	echo "TODO ../script/corpora"

# Run Rust fmt to make code cleaner
fmt:
	cargo fmt --all

# Clean only eth2fuzz target
clean:
	rm -rf target/

# Clean all (eth2fuzz && compiled fuzz target harnesses).
clean-all: clean
	rm -rf workspace/targets
	rm -rf workspace/debug
	rm -rf workspace/afl
	rm -rf workspace/hfuzz
	rm -rf workspace/libfuzzer

#
# CI utils
#

# Run all fuzzing hardness over libfuzzer
test-continuously-libfuzzer: build
	./eth2fuzz continuously -t 2 --fuzzer libfuzzer

# Run all fuzzing hardness over honggfuzz
test-continuously-honggfuzz: build
	./eth2fuzz continuously -t 2 --fuzzer honggfuzz

# Run all fuzzing hardness over afl
test-continuously-afl: build
	./eth2fuzz continuously -t 2 --fuzzer afl
