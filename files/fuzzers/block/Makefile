all: fuzzer

PYTHON_HARNESS_PATH="\"$(realpath harness.py)\""
PYTHON_LIB_PATH="\"$(realpath pythonlib/)\""

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_minimal -libfuzzer-prefix=block_ -libfuzzer-ex -o ../zrnt.a .

pythonlib/:
	rm -rf eth2.0-specs/
	rm -rf pythonlib/
	git clone https://github.com/ethereum/eth2.0-specs.git

	# TODO just checkout master once PR is merged
	cd eth2.0-specs/ && git fetch origin pull/1178/head:pr-1178 && git checkout pr-1178 && make pyspec && cd ..

	mkdir pythonlib/
	cp -R eth2.0-specs/test_libs/pyspec/eth2spec pythonlib/
	cp -R eth2.0-specs/test_libs/config_helpers/preset_loader pythonlib/
	CFLAGS="" CXXFLAGS="" LDFLAGS="" pip3 install -r eth2.0-specs/test_libs/config_helpers/requirements.txt -t pythonlib/ --system
	CFLAGS="" CXXFLAGS="" LDFLAGS="" pip3 install -r eth2.0-specs/test_libs/pyspec/requirements.txt -t pythonlib/ --system

fuzzer : fuzzer.cpp zrnt.a pythonlib/
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH=$(PYTHON_HARNESS_PATH) -DPYTHON_LIB_PATH=$(PYTHON_LIB_PATH) fuzzer.cpp zrnt.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a pythonlib/
