# Main Makefile designed for multi-platform support for sh and Windows pwsh
# Helps provide docker commands

ifeq ($(OS),Windows_NT)
	# NOTE: for this to work, docker-related commands need to have a pwsh equivalent alias
	SHELL := pwsh.exe
	.SHELLFLAGS := -Command
	BUILD_ENV :=
else
	SHELL := /bin/sh
	BUILD_ENV := DOCKER_BUILDKIT=1
endif

.PHONY: check-fmt help docker corpora fmt clippy clean clean-all

.DEFAULT_GOAL=docker-all

# NOTE: this works for windows too!
WORKSPACE_DIR := $(realpath workspace)

clients := lighthouse nimbus prysm teku lodestar
test_clients := $(addprefix test-,$(clients))
clean_clients := $(addprefix clean-,$(clients))


help:
	@echo 'Management commands for eth2fuzz'
	@echo ''
	@echo 'Available clients:'
	@echo '    lighthouse'
	@echo '    lodestar'
	@echo '    nimbus'
	@echo '    prysm'
	@echo '    teku'
	@echo ''
	@echo 'Basic Usage:'
	@echo ''
	@echo '    make fuzz-all                                    Build and fuzz all targets for all clients, 1 hr each.'
	@echo '    make fuzz-[CLIENT]                               Fuzz all targets for CLIENT, 1 hr each.'
	@echo '                                                     e.g. `make fuzz-lighthouse`'
	@echo '    make or make docker-all                          Build all docker images.'
	@echo '    make CLIENT                                      Build all docker image for CLIENT.'
	@echo '                                                     e.g. `make prysm`'
	@echo ''
	@echo '    make clean                                       Clean all (eth2fuzz && compiled fuzz target harnesses).'
	@echo '    make clean-[CLIENT]                              Clean build artifacts for a single client CLIENT.'
	@echo ''
	@echo 'Dev helpers:'
	@echo '    make test-all                                    Fuzz all targets for all clients, 1 s each.'
	@echo '    make test-[CLIENT]                               Fuzz all targets for CLIENT, 1 s each.'
	@echo ''
	@echo '    make corpora                                     Create initial corpora from Eth2 Spec tests.'
	@echo ''
	@echo '    make fmt                                         Run Rust fmt.'
	@echo ''
	@echo ''


# Create an initial corpora
corpora:
	cd workspace/corpora/ && ./extract_corpora_from_spectests.sh


#
# ALL CLIENTS
#

## Build all docker
docker-all: lighthouse lodestar nimbus prysm teku

## Fuzz all eth2 clients
fuzz-all: fuzz-lighthouse fuzz-lodestar fuzz-nimbus fuzz-prysm fuzz-teku

# Clean all (eth2fuzz && compiled fuzz target harnesses).
clean: $(clean_clients)
	rm -rf workspace/debug/target
	# clean js - not needed
	# clean java libfuzzer - TODO

#
# Lighthouse
# https://github.com/sigp/lighthouse
#

## Fuzzing of lighthouse using docker.
#
# Note: we define the command outside of the recipe to avoid passing the \ to the shell (not handled nicely in pwsh)
# See https://www.gnu.org/software/make/manual/html_node/Splitting-Recipe-Lines.html#Splitting-Recipe-Lines
lighthouse: build_cmd = $(BUILD_ENV) docker build \
	--file docker/lighthouse.Dockerfile \
	-t eth2fuzz_lighthouse \
	. \
	$(CACHE)
lighthouse:
	$(build_cmd)
	@echo 'USAGE: docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_lighthouse list'

## Fuzz all lighthouse targets for 1 hour each
fuzz-lighthouse: lighthouse
	docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_lighthouse continuously -q lighthouse -t 3600 -n 1

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
lodestar: build_cmd = $(BUILD_ENV) docker build \
	--file docker/lodestar.Dockerfile \
	-t eth2fuzz_lodestar \
	. \
	$(CACHE)
lodestar:
	$(build_cmd)
	@echo 'USAGE: docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_lodestar list'

## Fuzz all lodestar targets for 1 hour each
fuzz-lodestar: lodestar
	docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_lodestar continuously -q lodestar -t 3600

## Nothing to clean with lodestar since there
## is not compiled fuzzing targets
clean-lodestar:

#
# Nimbus
# https://github.com/status-im/nimbus-eth2
#

## Fuzzing of nimbus-eth2 using docker.
nimbus: build_cmd = $(BUILD_ENV) docker build \
	--file docker/nimbus.Dockerfile \
	-t eth2fuzz_nimbus \
	. \
	$(CACHE)
nimbus:
	$(build_cmd)
	@echo 'USAGE: docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_nimbus list'

## Fuzz all nimbus targets for 1 hour each
fuzz-nimbus: nimbus
	docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_nimbus continuously -q nimbus -t 3600

## clean compiled fuzzing targets
clean-nimbus:
	for i in $(shell docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_nimbus list); do \
		rm -rf workspace/nimlibfuzzer/$$i; \
	done

#
# Prysm
# https://github.com/prysmaticlabs/prysm
#

## Fuzzing of prysm using docker.
prysm: build_cmd = $(BUILD_ENV) docker build \
	--file docker/prysm.Dockerfile \
	-t eth2fuzz_prysm \
	. \
	$(CACHE)
prysm:
	$(build_cmd)
	@echo 'USAGE: docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_prysm list'

## Fuzz all prysm targets for 1 hour each
fuzz-prysm: prysm
	docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_prysm continuously -q prysm -t 3600

## clean compiled fuzzing targets
clean-prysm:
	# clean gofuzz libfuzzer
	rm -rf workspace/gofuzz/*.libfuzzer

#
# Teku
# https://github.com/PegaSysEng/teku
#

## Fuzzing of teku using docker.
teku: build_cmd = $(BUILD_ENV) docker build \
	--file docker/teku.Dockerfile \
	-t eth2fuzz_teku \
	. \
	$(CACHE)
teku:
	$(build_cmd)
	@echo 'USAGE: docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_teku list'

## Fuzz all teku targets for 1 hour each
fuzz-teku: teku
	docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_teku continuously -q teku -t 3600

## clean compiled fuzzing targets
clean-teku:
	# clean javafuzz
	rm -rf workspace/javafuzz/T*.class

test-all: $(test_clients)

test-lighthouse: exit_success=0
test-prysm: exit_success=0
test-nimbus: exit_success=0
test-teku: exit_success=1
test-lodestar: exit_success=1

# TODO depend on the build client? Wanna avoid rebuilding it unnecessarily
ifeq ($(OS),Windows_NT)
## Try to run each target for 1 sec
# Note: we keep this outside of the recipe, so we can split up lines with \ without sending
# the backslash to pwsh
# TODO break if test fails?
$(test_clients): test_cmd = "$(shell docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_$* list)".Split() | \
	ForEach-Object -Process { docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_$* target $$_ -t 2; \
	if ($$LastexitCode -neq $(exit_success)) { exit 1 } }
$(test_clients): test-%:
	@echo "Windows tests"
	$(test_cmd)
else
## Try to run each target for a minimal time
# (prob wanna run it until at least INITed?
# TODO break if test fails?
$(test_clients): test-%:
	@echo "Expecting exit status of $(exit_success)"
	for i in $(shell docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_$* list); do \
		docker run -v $(WORKSPACE_DIR):/eth2fuzz/workspace eth2fuzz_$* target $$i -t 2; \
		test $$? -eq $(exit_success) || exit 1; \
	done
endif

#
# Developer utils
#

# Run Rust fmt to make code cleaner
fmt:
	cargo fmt --all

# Run Rust clippy to make code cleaner
clippy:
	cargo clippy --all
