.PHONY: default help build fmt clean 

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

# Run Rust fmt to make code cleaner
fmt:
	cargo fmt --all

# Clean the project.
clean:
	cargo clean
	rm -rf target
	rm -rf ./beaconfuzz_v2

#
# CI utils
#

# Check code style quickly by running `rustfmt` over all code
check-fmt:
	cargo fmt --all -- --check