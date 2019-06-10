all: fuzzer

PYTHON_HARNESS_PATH="\"$(realpath harness.py)\""
PYTHON_LIB_PATH="\"$(realpath lib/)\""

lib/:
	mkdir -p lib
	pip3 install ssz -t lib/ --system

fuzzer : fuzzer.cpp lib/
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH=$(PYTHON_HARNESS_PATH) -DPYTHON_LIB_PATH=$(PYTHON_LIB_PATH) fuzzer.cpp $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer lib/
