# A common Makefile used by all fuzzers

ifeq ($(MAKELEVEL),0)
$(error "Intended for use as a sub-make file, don't call this directly!")
endif

# require that the current directory is the fuzzing target's root
# enforced by the parent Makefile
here := $(CURDIR)

# so def.mk doesn't unintentionally override the default goal
.DEFAULT_GOAL := all

# Custom functions

# Check that given variables are set and all have non-empty values,
# die with an error otherwise.
#
# Params:
#   1. Variable name(s) to test.
#   2. (optional) Error message to print.
#
# Based on https://stackoverflow.com/a/10858332
check_defined = \
    $(strip $(foreach 1,${1}, \
        $(call __check_defined,${1},$(strip $(value 2)))))
__check_defined = \
    $(if $(value ${1}),, \
        $(error Undefined ${1}$(if ${2}, (${2}))$(if $(value @), \
                required by target "$@")))

# include fuzzer-specific overrides and definitions
-include def.mk

# can disable clients via variables in the form of BFUZZ_<IMPL>_OFF
# e.g. BFUZZ_NIMBUS_OFF=1 (set to any value other than empty)
#
# Possible values:
#
# BFUZZ_ARTEMIS_OFF
# BFUZZ_HARMONY_OFF
# BFUZZ_LODESTAR_OFF
# BFUZZ_LIGHTHOUSE_OFF
# BFUZZ_NIMBUS_OFF
# BFUZZ_PYSPEC_OFF
# BFUZZ_PRYSM_OFF
# BFUZZ_TRINITY_OFF
# BFUZZ_ZRNT_OFF # Note: we can avoid fuzzing with ZRNT, but still needed for preprocessing
#
# Also:
# BFUZZ_PYTHON_OFF equiv to BFUZZ_TRINITY_OFF + BFUZZ_PYSPEC_OFF
# and other lang-specific flags?
#
# TODO also allow a list of them via BFUZZ_CLIENT_DISABLE=nimbus lighthouse
# TODO(gnattishness) a "help" PHONY
# TODO(have in master makefile?)
#
# Other flags:
#
# BFUZZ_NO_DISABLE_BLS (disabled by default)
# TODO BFUZZ_CONFIG_MINIMAL/BFUZZ_CONFIG_MAINNET

PY_SPEC_HARNESS_PATH := $(here)/pyspec/harness.py
TRINITY_HARNESS_PATH := $(here)/trinity/harness.py

lighthouse_dir_contents := $(shell find $(here)/lighthouse | sed 's/ /\\ /g')

# defaults for fuzzer-specific variables

# the name of the current directory
target_name ?= $(lastword $(subst /, ,$(realpath $(here))))
zrnt_prefix ?= zrnt_$(target_name)_
lighthouse_package_name ?= $(target_name)_fuzzer

comma := ,

# check that required variables are set
required_variables := target_name

ifndef BFUZZ_LIGHTHOUSE_OFF
required_variables += lighthouse_package_name
endif
ifndef BFUZZ_NIMBUS_OFF
required_variables += NIM_CPPFLAGS NIM_LDFLAGS NIM_LDLIBS
endif
ifndef BFUZZ_PYSPEC_OFF
required_variables += PY_SPEC_VENV_PATH
endif
ifndef BFUZZ_TRINITY_OFF
required_variables += TRINITY_VENV_PATH
endif
ifndef BFUZZ_ZRNT_OFF
required_variables += zrnt_prefix GO_FUZZ_BUILD_PATH
endif

$(call check_defined, $(required_variables))


.PHONY: all clean mostlyclean
all: fuzzer

# TODO N depend on lib or GO_FUZZ_BUILD_PATH?
# TODO check GO_BFUZZ_BUILD is accessible?
zrnt.a : zrnt/fuzz.go
	cd zrnt && \
		GO111MODULE=on $(GO_BFUZZ_BUILD) \
		-tags 'preset_mainnet$(if $(BFUZZ_NO_DISABLE_BLS),,$(comma)bls_off)' \
		-o ../zrnt.a $(zrnt_prefix),fuzz,Fuzz

lighthouse.a : lighthouse $(lighthouse_dir_contents) $(CARGO_CONFIG_PATH)
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	# NOTE: we can't pass coverage flags via RUSTFLAGS, so rely on a custom .cargo/config
	# until https://github.com/rust-lang/cargo/issues/6139 is resolved
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		$(if $(BFUZZ_NO_DISABLE_BLS),,--features fake_crypto )\
		--release
	cp lighthouse_out/release/deps/lib$(lighthouse_package_name)-*.a lighthouse.a


# TODO would optimally want this rebuilt if the env var values changed
# https://stackoverflow.com/questions/11647859/make-targets-depend-on-variables
# TODO move LDFLAGS before and use LDLIBS for all -llibname flags
# TODO how to split up the PYTHON_LDFLAGS?
#
# TODO N depend on lib/*.h etc?
# NOTE: its not nice to have the python `-L` flags after LDLIBS,
# but -leth2fuzz depends on -lpython, so we have to link -lpython after
#
# TODO depend on lib header files here?
# TODO build to enable/disable bls in trinity, pyspec, nimbus

fuzzer.o : CPPFLAGS += $(NIM_CPPFLAGS)
fuzzer.o : fuzzer.cpp
	#test -d $(TRINITY_VENV_PATH)
	test -d $(PY_SPEC_VENV_PATH)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) \
		$(if $(BFUZZ_NO_DISABLE_BLS),-DBFUZZ_NO_DISABLE_BLS=1) \
	    -DPY_SPEC_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" \
	    -DPY_SPEC_VENV_PATH="\"$(PY_SPEC_VENV_PATH)\"" \
	    -DTRINITY_HARNESS_PATH="\"$(TRINITY_HARNESS_PATH)\"" \
	    -DTRINITY_VENV_PATH="\"$(TRINITY_VENV_PATH)\"" \
		-c fuzzer.cpp -o fuzzer.o

fuzzer : LDFLAGS += $(NIM_LDFLAGS)
fuzzer : LDLIBS += $(NIM_LDLIBS)
fuzzer : fuzzer.o zrnt.a lighthouse.a
	$(CXX) -fsanitize=fuzzer \
	    fuzzer.o lighthouse.a zrnt.a \
	    $(LDFLAGS) $(LDLIBS) $(PYTHON_LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer *.a *.o lighthouse_out

mostlyclean:
	@# only clean executable and .o files
	rm fuzzer *.o
