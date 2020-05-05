# ETH2FUZZ TUTORIAL


## Goal of this tool


The main goal of this tool is to provide an easy way to fuzz lighthouse (and other clients) to create new inputs for differential fuzzers.
Generated samples/inputs can than be reused as unittest and testcases for differential fuzzers (eth2diff && beacon-fuzz-2).


Main features are:
- Automatic fuzzing of lighthouse harnesses (without user interaction)
- Multiple fuzzing engines available (honggfuzz, afl++, libfuzzer)
- Multi-threading (depending of the fuzzer, honggfuzz OK)
- Crash report/detection
- *Automatic and pseudo-random selection of new beaconstate per fuzzing thread.*


Architecture of this tool came from this [project](https://github.com/rust-fuzz/targets).

## Installation

You need to install the different fuzzing engine and cargo subcommands:
``` sh
# Ideally using cargo +nightly and --force to to sure your version is updated

# installs hfuzz and honggfuzz subcommands in cargo
cargo +nightly install --force honggfuzz

# cargo-fuzz (i.e. libfuzzer for Rust)
cargo +nightly install --force cargo-fuzz

# afl-rs
cargo +nightly install --force afl
```


## Available targets

Current target available can be listed with:
```sh
$ ./eth2fuzz list-targets
lighthouse_attestation
lighthouse_attester_slashing
lighthouse_block
lighthouse_block_header
lighthouse_deposit
lighthouse_proposer_slashing
lighthouse_voluntary_exit
lighthouse_beaconstate
ssz_encode_decode
ssz_decode_encode
```

# Commands

Help:
``` sh
$ ./eth2fuzz help
[...]
SUBCOMMANDS:
    continuously    Run all fuzz targets
    help            Prints this message or the help of the given subcommand(s)
    list-targets    List all available targets
    target          Run one target with specific fuzzer

```

## Run targets

Help: `./eth2fuzz target --help`.

Run targets: `cargo +nightly run target lighthouse_attestation`.
Using other fuzzing engines:
``` sh
# --fuzzer <fuzzer>    Which fuzzer to run [default: Honggfuzz]  [possible values: Afl, Honggfuzz, Libfuzzer]
./eth2fuzz target lighthouse_attestation --fuzzer Libfuzzer`.
```

## Continuous fuzzing 

CAUTIONS: eth2fuzz continuous mode will stop after all target being executed once if you are not providing infinite flag.

Help:
``` sh
$ ./eth2fuzz continuously --help
Run eth2fuzz targets

USAGE:
    cli continuously [FLAGS] [OPTIONS]

FLAGS:
        --cargo-update    
    -h, --help            Prints help information
    -i, --infinite        
    -V, --version         Prints version information

OPTIONS:
    -q, --filter <filter>      Only run target containing this string
        --fuzzer <fuzzer>      Which fuzzer to run [default: Honggfuzz]  [possible values: Afl, Honggfuzz, Libfuzzer]
    -t, --timeout <timeout>    Set timeout per target [default: 10]
```

Useful command for lighthouse:
``` sh
./eth2fuzz continuously -i -q attestation -t 600
# -i => infinite mode
# -q => will run lighthouse_attestation target
# -t => timeout of 10 min, will restart the fuzzer every 10 min
# TODO ====> restarting the fuzzer will be more useful in the future when beaconstate will be choosen randomly at start
```

## Specific fuzzer engine options

It's possible to provide extra flags to fuzzing engines (honggfuzz, afl, libfuzzer)

### honggfuzz-rs

FLAG: `HFUZZ_RUN_ARGS`

Limit corpus file size: `HFUZZ_RUN_ARGS="-F 500000"`.
TODO

### afl-rs

TODO

### cargo-fuzz (libfuzzer)


libfuzzer output details: http://llvm.org/docs/LibFuzzer.html#output 

# Improvements

This tool can be improved 

## General improvement for this tool

- add first time running script for afl
- add more documentation
- fix libfuzzer (cargofuzz) => use cargo-fuzz instead of existing code.
- support new fuzzers (lain, fuzzcheck, customs, etc.)
- compile all target before running fuzzing (no need to compile targets each time fuzzer restart)
- Verify sharing coverage + seeds work as expected

## Specific improvement for this tool

- this tool could be used to fuzz other eth2 implementation using bindings/FFI.

# Going deeper


## How to add new harnesses?

Modify the `common/src/lib.rs` to add the function you want to fuzz.
TODO
