CXXFLAGS+=-std=c++17 -O3
# TODO(gnattishness) recommended cflags from python3-config

.PHONY: all
all : libeth2fuzz.a

base.o : base.cpp base.h
	$(CXX) $(CXXFLAGS) -c -o base.o base.cpp

util.o : util.cpp util.h
	$(CXX) $(CXXFLAGS) -c -o util.o util.cpp

differential.o : differential.cpp differential.h base.h
	$(CXX) $(CXXFLAGS) -c -o differential.o differential.cpp

python.o : python.cpp python.h base.h
	test $(CPYTHON_INSTALL_PATH)
	$(CXX) $(CXXFLAGS) -c -o python.o -I"$(CPYTHON_INSTALL_PATH)/include/python3.8" python.cpp

java.o : CXXFLAGS += $(JAVA_CXXFLAGS)
java.o : java.cpp java.h base.h
	$(CXX) $(CXXFLAGS) -c -o java.o java.cpp

# NOTE: if python.o is used, you also need to link the python lib
libeth2fuzz.a : base.o differential.o python.o util.o java.o
	ar rcs libeth2fuzz.a base.o differential.o python.o util.o java.o
	ranlib libeth2fuzz.a

clean:
	rm -rf *.o *.a
