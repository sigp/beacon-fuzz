# eth2fuzz

This tool provide an easy way to fuzz eth2 clients using Docker files.
Generated samples/inputs during fuzzing can than be reused as unit tests or testcases for differential fuzzers (`eth2diff` && `beacon-fuzz-2`).


## Quick start

Clone this repository:

```sh
git clone https://github.com/sigp/beacon-fuzz
```

Change your current directory to `ethfuzz`:

```sh
cd beacon-fuzz/eth2fuzz
```

Make sure the Docker service is running on your machine (we assume that Docker has been setup on your machine. Please refer to the great official instructions, see for example [this guide](https://docs.docker.com/engine/install/ubuntu/) for Ubuntu). For Arch Linux users:

```sh
systemctl start docker.service
```

Build the fuzzing docker for any given eth2 client:
``` sh
make lighthouse
# make nimbus
# make prysm
# make teku
# make lodestar
```

Run the docker. You will need to provide the `workspace` folder as shared volume):
``` sh
docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_prysm
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lodestar
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_teku
```

At this point you will now interact with `eth2fuzz` over docker:
``` sh
docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse help
```


# `eth2fuzz` commands

## List available targets

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

`eth2fuzz` can be configured to continuously fuzz all available targets for a given client, using the `continuously` CLI parameter. Execution will stop after 30 minutes per target if the `--infinite` flag is not provided (the timeout can also be changed, using the `--timeout` flag). Make sure to use the `-q` flag to select the client you've built your fuzzer for.

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

Example command for lighthouse:
``` sh
./eth2fuzz continuously -i -q attestation -t 600
# -i => infinite mode
# -q => will run lighthouse_attestation target
# -t => timeout of 10 min, will restart the fuzzer every 10 min
```

# Support

Join our beacon-fuzz channel on [Discord](https://discord.gg/AkPb4vx) to report any bugs you've found, or if you're running into any issues using these fuzzers.
