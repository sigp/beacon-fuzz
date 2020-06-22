# ETH2FUZZ

This tool provide an easy way to fuzz ethereum 2.0 clients using docker files.
Generated samples/inputs during fuzzing can than be reused as unittest or testcases for differential fuzzers (`eth2diff` && `beacon-fuzz-2`).


## Quick start

Build the fuzzing docker of one eth2 client:
``` sh
make lighthouse
# make nimbus
# make prysm
# make lodestar
```

Run the docker (don't foget to provide the workspace folder as shared volume):
``` sh
docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_prysm
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lodestar
``` 

At this point you will now interact with `eth2fuzz` over docker:
``` sh
docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse help
```


# Eth2fuzz commands

## list available targets

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
```

## Run targets

Run one target: `./eth2fuzz target lighthouse_attestation`.
Run one target with specific fuzzing engines:
``` sh
# --fuzzer <fuzzer>    Which fuzzer to run [default: Honggfuzz]  [possible values: Afl, Honggfuzz, Libfuzzer]
./eth2fuzz target lighthouse_attestation --fuzzer libfuzzer`.
```

## Continuous fuzzing 

CAUTIONS: eth2fuzz continuous mode will stop after all target being executed once if you are not providing infinite flag.

Help:
``` sh
$ ./eth2fuzz continuously --help
Run all fuzz targets
USAGE:
    eth2fuzz continuously [FLAGS] [OPTIONS]

FLAGS:
        --cargo-update    
    -h, --help            Prints help information
    -i, --infinite        
    -V, --version         Prints version information

OPTIONS:
    -q, --filter <filter>      Only run target containing this string
        --fuzzer <fuzzer>      Which fuzzer to run [default: Honggfuzz]  [possible values: Afl, Honggfuzz, Libfuzzer]
    -n, --thread <thread>      Set number of thread (only for hfuzz)
    -t, --timeout <timeout>    Set timeout per target [default: 10]
```

Useful command for lighthouse:
``` sh
./eth2fuzz continuously -i -q attestation -t 600
# -i => infinite mode
# -q => will run lighthouse_attestation target
# -t => timeout of 10 min, will restart the fuzzer every 10 min
```

# TODO - Improvements

## General improvement for this tool

- add more documentation
- add support teku
- add state processing lodestar
- improve cli commands
- compile all target before running fuzzing (no need to compile targets each time fuzzer restart)
