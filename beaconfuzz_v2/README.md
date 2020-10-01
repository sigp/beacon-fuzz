# beaconfuzz_v2

This tool help to find logic bug using differential fuzzing accross multiple eth2 client implementation.

## Setup and Installation

After setup and installation, your workspace should look as following:
```
├── beacon-fuzz
├── lighthouse
├── nim-beacon-chain
├── prysm
└── teku
```

### Beaconfuzz_v2 setup

Clone this repository
```
git clone https://github.com/sigp/beacon-fuzz
```

### lighthouse setup

Clone the repository of lighthouse:
```
git clone https://github.com/sigp/lighthouse
```

### nimbus setup

Install nimbus dependencies:
```
sudo apt install libpcre3-dev
```

Clone the repository of nimbus and compile the nimbus fuzzing library:
```
git clone https://github.com/status-im/nim-beacon-chain --branch devel
cd nim-beacon-chain
NIMFLAGS="-d:disableLTO" make libnfuzz.a libnfuzz.so
```

Finally, set the following variable with the current path of nimbus:
```
export CARGO_NIMBUS_DIR=~/path/to/nim-beacon-chain
```

### prysm setup
<!---
Create a prysm folder:
```
mkdir prysm
cp -r beacon-fuzz/beaconfuzz_v2/libs/pfuzz prysm/
```

Compile the prysm fuzzing library:
```
go get .
go build -o libpfuzz.a -buildmode=c-archive pfuzz.go
```
 -->
Set the following variable with the current path of prysm:
```
export CARGO_PRYSM_DIR=beacon-fuzz/beaconfuzz_v2/libs
```

### Beaconfuzz_v2 compilation

Compile the project using the Makefile
```
cd beacon-fuzz/beaconfuzz_v2
make
```

Install rust fuzzers:
```
cargo +nightly install cargo-fuzz
cargo +nightly install honggfuzz
```

Compile and run the fuzzers:
```
make fuzz_*
fuzz_attestation               fuzz_block                     fuzz_proposer_slashing       
fuzz_attestation-struct        fuzz_block-struct              fuzz_proposer_slashing-struct
fuzz_attester_slashing         fuzz_deposit                   fuzz_voluntary_exit          
fuzz_attester_slashing-struct  fuzz_deposit-struct            fuzz_voluntary_exit-struct
```

there is two differents kind of fuzzing targets:
- `fuzz_*`: Mutation fuzzing using honggfuzz
- `fuzz_*-struct`: structural fuzzing using libfuzzer + arbitrary

<!---
RUSTFLAGS='-L /home/scop/Documents/consulting/sigmaprime/prysm/pfuzz/ -L /home/scop/Documents/consulting/sigmaprime/nim-beacon-state/build/ ' make fuzz_block-struct
 -->