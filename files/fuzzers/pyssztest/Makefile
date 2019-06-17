all: fuzzer

PYTHON_HARNESS_PATH="\"$(realpath harness.py)\""
PYTHON_LIB_PATH="\"$(realpath lib/)\""

lib/:
	rm -rf eth2.0-specs/
	rm -rf lib/
	git clone https://github.com/ethereum/eth2.0-specs.git
	cd eth2.0-specs/ && git fetch origin pull/1178/head:pr-1178 && git checkout pr-1178 && make pyspec && cd ..
	mkdir lib/
	cp -R eth2.0-specs/test_libs/pyspec/eth2spec lib/
	cp -R eth2.0-specs/test_libs/config_helpers/preset_loader lib/
	pip3 install -r eth2.0-specs/test_libs/config_helpers/requirements.txt -t lib/ --system
	pip3 install -r eth2.0-specs/test_libs/pyspec/requirements.txt -t lib/ --system

fuzzer : fuzzer.cpp lib/
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH=$(PYTHON_HARNESS_PATH) -DPYTHON_LIB_PATH=$(PYTHON_LIB_PATH) fuzzer.cpp $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer lib/
