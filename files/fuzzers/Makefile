CPYTHON_LIB_PATH=$(CPYTHON_INSTALL_PATH)/lib/python3.8
CPYTHON_LIB_DYNLOAD_PATH=$(CPYTHON_LIB_PATH)/lib-dynload

# (paths to) dynamic libraries needed at runtime need to be linked into the binary
# See also: https://stackoverflow.com/questions/11842920/undefined-symbol-pyexc-importerror-when-embedding-python-in-c
DYNLOAD_LIBS=_hashlib _sha3 _blake2 _struct
DYNLOAD_LIBS_PATHS=$(addsuffix *.so,$(addprefix $(CPYTHON_LIB_DYNLOAD_PATH)/,$(DYNLOAD_LIBS)))

PYTHON_LD_FLAGS=$(CPYTHON_INSTALL_PATH)/lib/libpython3.8.a -lutil -lpthread $(DYNLOAD_LIBS_PATHS)

CXXFLAGS+=-I $(realpath ..)
LDFLAGS+=-L $(realpath ../lib) -leth2fuzz
export

TARGETS := py-go-test shuffle deposit
.PHONY: $(TARGETS)

$(TARGETS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

all clean: $(TARGETS)
