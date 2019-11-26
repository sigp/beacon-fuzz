# TODO remove if unneeded
CPYTHON_LIB_PATH := $(CPYTHON_INSTALL_PATH)/lib/python3.8
CPYTHON_LIB_DYNLOAD_PATH := $(CPYTHON_LIB_PATH)/lib-dynload
CARGO_CONFIG_PATH := $(realpath ../.cargo/config)

# (paths to) dynamic libraries needed at runtime need to be linked into the binary
# See also: https://stackoverflow.com/questions/11842920/undefined-symbol-pyexc-importerror-when-embedding-python-in-c
DYNLOAD_LIBS := _hashlib _sha3 _blake2 _struct binascii math pyexpat _random _socket select _decimal
DYNLOAD_LIBS_PATHS := $(addsuffix *.so,$(addprefix $(CPYTHON_LIB_DYNLOAD_PATH)/,$(DYNLOAD_LIBS)))

PYTHON_LD_FLAGS := $(shell $(CPYTHON_INSTALL_PATH)/bin/python3-config --ldflags) -lpython3.8 -Xlinker -export-dynamic

#PYTHON_LD_FLAGS := "$(CPYTHON_INSTALL_PATH)/lib/libpython3.8.a" -lutil -lpthread $(DYNLOAD_LIBS_PATHS)

# TODO use python3-config --cflags
CXXFLAGS+=-I $(realpath ..) -I$(CPYTHON_INSTALL_PATH)/include/python3.8
LDFLAGS+=-L $(realpath ../lib)
LDLIBS+= -leth2fuzz -lstdc++fs
export

#TARGETS := py-go-test shuffle deposit block_header attestation transfer voluntary_exit attester_slashing proposer_slashing zssz pyssztest block
TARGETS := shuffle
.PHONY: $(TARGETS)

$(TARGETS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

all clean: $(TARGETS)
