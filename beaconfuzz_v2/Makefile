.PHONY: default help build fmt clean docker test

#
# Utils for eth2diff.
#

default: build

help:
	@echo 'Management commands for beacon-fuzz v2'
	@echo
	@echo 'Usage:'
	@echo '    make build 										Compile the project.'
	@echo '    make fmt 										Run Rust fmt.'
	@echo '    make clean 										Clean the project artifacts.'

# Compile the project
build:
	cargo +nightly build --release --out-dir=. -Z unstable-options

# Run beaconfuzz_v2
run:
	./beaconfuzz_v2 debug

# Compile and run beaconfuzz_v2
test: build
	./beaconfuzz_v2 debug attestation

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

fuzz_attester_slashing:
	ETH2FUZZ_BEACONSTATE=../eth2fuzz/workspace/corpora/beaconstate cargo hfuzz run diff_attester_slashing


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