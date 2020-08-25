# eth2fuzz

This tool provide an easy way to fuzz eth2 clients using Docker files.
Generated samples/inputs during fuzzing can than be reused as unit tests or testcases for differential fuzzers (`eth2diff` && `beacon-fuzz-2`).


## Quick start

Clone this repository:

```console
$ git clone https://github.com/sigp/beacon-fuzz
```

Change your current directory to `eth2fuzz`:

```console
$ cd beacon-fuzz/eth2fuzz
```

Make sure the Docker service is running on your machine (we assume that Docker has been setup on your machine. Please refer to the great official instructions, see for example [this guide](https://docs.docker.com/engine/install/ubuntu/) for Ubuntu).
For Arch Linux users:

```console
$ sudo systemctl start docker.service
```

NOTE: docker commands require elevated permissions by default.
If you see an error like `Got permission denied while trying to connect to the Docker daemon socket ...`, you likely need to use `sudo`.


You can run all fuzzing targets for 1 hour each with:

```console
$ sudo make fuzz-all
```
(This will take roughly 7 hours per client)

Similarly, to run all the fuzzers for a single client, for 1 hour each:

```console
# make fuzz-lighthouse
# make fuzz-nimbus
# make fuzz-prysm
# make fuzz-teku
# make fuzz-lodestar
```

Build the fuzzing docker image (without running it) for any given eth2 client:
```console
# make lighthouse
# make nimbus
# make prysm
# make teku
# make lodestar
```

See `make help` for all options.


### Interacting with the docker images directly:

Run the docker. You will need to provide the `workspace` folder as shared volume):
```console
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_nimbus
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_prysm
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lodestar
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_teku
```

At this point you will now interact with `eth2fuzz` over docker:
```console
# docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz_lighthouse help
```

### Rebuilding after getting updates:

Get the latest code changes:

```console
$ git pull
```

Build fresh docker image (without caching):
```console
$ sudo make CACHE=--no-cache nimbus
```

Run your relevant fuzzer:
```console
$ sudo make fuzz-nimbus
```

## `eth2fuzz` commands

### List available targets

Current target available can be listed with:
```console
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

### Run targets

Run one target: `./eth2fuzz target lighthouse_attestation`.
Run one target with specific fuzzing engines:
```console
$ # --fuzzer <fuzzer>    Which fuzzer to run [default: Honggfuzz]  [possible values: Afl, Honggfuzz, Libfuzzer]
$ ./eth2fuzz target lighthouse_attestation --fuzzer libfuzzer`.
```

### Continuous fuzzing

`eth2fuzz` can be configured to continuously fuzz all available targets for a given client, using the `continuously` CLI parameter. Execution will stop after 30 minutes per target if the `--infinite` flag is not provided (the timeout can also be changed, using the `--timeout` flag). Make sure to use the `-q` flag to select the client you've built your fuzzer for.

```console
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
```console
$ ./eth2fuzz continuously -i -q attestation -t 600
$ # options:
$ # -i => infinite mode
$ # -q => will run lighthouse_attestation target
$ # -t => timeout of 10 min, will restart the fuzzer every 10 min
```

## Support

Join our "fuzzing" channel on [Discord](https://discord.gg/AkPb4vx) to report any bugs you've found, or if you're running into any issues using these fuzzers.
