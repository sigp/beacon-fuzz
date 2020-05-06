.PHONY: default help build fmt clean docker test test-error eth2-clean eth2-all zcli lighthouse nimbus prysm teku

#
# Utils for eth2diff.
#

default: build

help:
	@echo 'Management commands for basic differential execution tool'
	@echo
	@echo 'Usage:'
	@echo '    make build 										Compile the project.'
	@echo '    make fmt 										Run Rust fmt.'
	@echo '    make clean 										Clean the directory tree.'
	@echo '    make docker										Build a docker image for this project.'
	@echo
	@echo '    make test		 								Test eth2 clients with valid state + block files.'
	@echo '    make test-error		 							Test eth2 clients with invalid state + block files.'
	@echo '    make docker-test		 							Test eth2 clients with valid state + block files using docker.'
	@echo '    make eth2-clean		 							Clean all compiled eth2 clients inside shared.'
	@echo '    make eth2-all		 							Compile all eth2 clients using dockers.'
	@echo '    make {zcli, lighthouse, nimbus, prysm, teku}		Compile only the choosen client.'
	@echo

# Compile the project
build:
	cargo +nightly build --release --out-dir=. -Z unstable-options

# Run Rust fmt to make code cleaner
fmt:
	cargo fmt --all

# Clean the project.
clean:
	cargo clean
	rm ./eth2diff

# Build the docker
docker:
	DOCKER_BUILDKIT=1 docker build . -t eth2diff $(CACHE)
	@echo 'USAGE: docker run -it \
			-v `pwd`/shared:/shared \
			eth2diff transition shared/corpora/pre.ssz shared/corpora/block.ssz'

#
# eth2diff tests.
#

# Simple test with valid ssz.
# Expected result: exit code 0 for all.
test: build
	./eth2diff transition shared/corpora/pre.ssz shared/corpora/block.ssz # test transition
	./eth2diff pretty Attestation shared/corpora/attestation.ssz

# Simple test with invalid ssz.
# Expected result: exit code 1 for all.
# TODO - clean sample names
test-error: build
	./eth2diff transition shared/corpora/mainnet/beaconstate/004a360e8f5b1d4a32c158c2c688fc4e.ssz shared/corpora/mainnet/block/12ad31d6744858b15f564774bff9e4f9.ssz

# Simple test with valid ssz using docker.
docker-test:
	docker run -it \
		-v `pwd`/shared:/shared \
		eth2diff transition shared/corpora/pre.ssz shared/corpora/block.ssz
	docker run -it \
		-v `pwd`/shared:/shared \
		eth2diff pretty Attestation shared/corpora/attestation.ssz


#
# Utils for eth2-client tools.
#

# Remove all compiled eth2-client tools
eth2-clean: 
	rm -rf shared/zcli
	rm -rf shared/lighthouse
	rm -rf shared/nimbus
	rm -rf shared/prysm
	rm -rf shared/teku

# Build all eth2-client tools.
eth2-all: zcli lighthouse nimbus prysm teku

## Build ZCLI using docker.
## https://github.com/protolambda/zcli
zcli:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/zcli.Dockerfile \
	--output ./shared/zcli . \
	$(CACHE)

## Build lighthouse (lcli) using docker.
## https://github.com/sigp/lighthouse
lighthouse:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/lighthouse.Dockerfile \
	--output ./shared/lighthouse . \
	$(CACHE)

## Build nim-beacon-chain (ncli) using docker.
## https://github.com/status-im/nim-beacon-chain
nimbus:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/nimbus.Dockerfile \
	--output ./shared/nimbus . \
	$(CACHE)

## Build prysm (pcli) using docker.
## https://github.com/prysmaticlabs/prysm
prysm:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/prysm.Dockerfile \
	--output ./shared/prysm . \
	$(CACHE)

## Build teku (teku) using docker.
## https://github.com/PegaSysEng/teku
teku:
	DOCKER_BUILDKIT=1 docker build \
	--file docker/teku.Dockerfile \
	--output ./shared/teku . \
	$(CACHE)

#
# CI utils
#

# Check code style quickly by running `rustfmt` over all code
check-fmt:
	cargo fmt --all -- --check
