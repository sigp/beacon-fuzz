CARGO_CONFIG_PATH := $(realpath ../.cargo/config)

# NOTE this is both LD_FLAGS and LDLIBS for Python-related stuff
PYTHON_LD_FLAGS := $(shell $(CPYTHON_INSTALL_PATH)/bin/python3-config --ldflags) -lpython3.8 -Xlinker -export-dynamic

# TODO use python3-config --cflags
CXXFLAGS+=-I $(realpath ..) -I$(CPYTHON_INSTALL_PATH)/include/python3.8
LDFLAGS+=-L $(realpath ../lib)
LDLIBS+= -leth2fuzz -lstdc++fs
export

#TARGETS := py-go-test shuffle deposit block_header attestation transfer voluntary_exit attester_slashing proposer_slashing zssz pyssztest block
TARGETS := shuffle block block_header attestation attester_slashing
.PHONY: $(TARGETS)

$(TARGETS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

all clean: $(TARGETS)
