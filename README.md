# beacon-fuzz

Open-source differential fuzzing of Ethereum 2.0 Phase 0 implementations. Maintained by Sigma Prime for the Ethereum Foundation.

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Overview

A differential fuzzer of Eth2.0 implementations using [libfuzzer](https://llvm.org/docs/LibFuzzer.html). By default, fuzzing progresses indefinitely unless an implementation panics or differing output is identified.

This is a continuation of Guido Vranken's [eth2.0-fuzzing](https://github.com/guidovranken/eth2.0-fuzzing)

This project and its inner workings are subject to change.

## Current Status

Currently fuzzes against Eth2 `v0.8.3` python or Go executable specs ([pyspec](https://github.com/ethereum/eth2.0-specs/tree/v0.8.3/test_libs/pyspec) or [zrnt](https://github.com/protolambda/zrnt/tree/v0.8.3))


### Implementations

* [Lighthouse](https://github.com/sigp/lighthouse/)/rust
* [pyspec](https://github.com/ethereum/eth2.0-specs/tree/dev/test_libs/pyspec)/python
* [zrnt](https://github.com/protolambda/zrnt/)/go

### Operational Fuzz Targets:

(and their relevant spec function)

All currently use the "mainnet" config: https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/configs/mainnet.yaml

* `block` - [`state_transition`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function)
* `block_header` - [`process_block_header`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#block-header)
* `attestation` - [`process_attestation`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#attestations)
* `shuffle` -  [`compute_shuffled_index`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#compute_shuffled_index)

See [corpora](https://github.com/sigp/beacon-fuzz-corpora) repository for explanation of input structure.

### Corpora

See [corpora](https://github.com/sigp/beacon-fuzz-corpora) for examples and explanation of structure.


## Usage

Quickstart:

```bash
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz.git
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz-corpora.git
$ cd beacon-fuzz
$ ./runfuzzer.sh block_header ../beacon-fuzz-corpora/0-8-3/mainnet/block_header/ ../beacon-fuzz-corpora/0-8-3/mainnet/beaconstate
```

Interactive usage:

```bash
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz.git
$ cd beacon-fuzz
$ sudo docker build . -t beacon_fuzz
$ sudo docker run -it beacon_fuzz bash
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz-corpora.git
$ export ETH2_FUZZER_STATE_CORPUS_PATH="/eth2/beacon-fuzz-corpora/0-8-3/mainnet/beaconstate"
$ /eth2/fuzzers/attestation/fuzzer /eth2/beacon-fuzz-corpora/0-8-3/mainnet/attestation
```

Use `help=1` for more arguments (see also [libfuzzer docs](https://llvm.org/docs/LibFuzzer.html))


## Contributing

Use [pre-commit](https://pre-commit.com/)

```console
$ pre-commit install
```

If build fails, comment the `RUN /eth2/build.sh` in `Dockerfile`, and run it manually from within the container. Can adjust Makefiles as needed.

### Adding new implementations for a target

The following implementations will be added to the various fuzzing targets:

* [Nimbus](https://github.com/status-im/nim-beacon-chain)
* [Prysm](https://github.com/prysmaticlabs/prysm)
* [Artemis](https://github.com/PegaSysEng/artemis)
* [Harmony](https://github.com/harmony-dev/beacon-chain-java)
* [Lodestar](https://github.com/ChainSafe/lodestar)

## Roadmap

- Add more implementations
- Add more fuzz targets
- Improved onboarding, ease of adding new targets and implementations
- Improved coverage measurements and visibility
- Deploy on dedicated production fuzzing infrastructure

## License

MIT - see [LICENSE](./LICENSE)
