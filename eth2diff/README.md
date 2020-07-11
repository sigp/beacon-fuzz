# eth2diff

**This tool is only doing state transition for the moment.**

When you provide a state and a block, eth2diff will process them through all clients you have (compiled using docker, see Makefile) inside the shared folder.

The goal is to detect execution differences between all eth2 implementation. 


## Usage

First build some clients (binaries will be stored inside shared folder):
``` sh
# Build all clients using multiple dockers
# WARNING: ~ 13GB and > 30 min
make eth2-all 

# Only build the one you want to test
# TIPS: Force update to lastest master using
#
# make zcli CACHE=--no-cache
make zcli lighthouse nimbus # ...
```

Build eth2diff:
``` sh
# Build the project on your host
make build
# Build the project using docker
make docker
```

Run the tool:
``` sh
# Run on your host
./eth2diff transition pre.ssz block.ssz
# Run with docker
# pre-state and block needs to be inside the shared folder
docker run -it -v "$(pwd)"/shared:/shared eth2diff transition shared/corpora/pre.ssz shared/corpora/block.ssz
docker run -it -v "$(pwd)"/shared:/shared eth2diff pretty Attestation shared/corpora/attestation.ssz
```

# TODO

- Detect if stuff inside stderr of process
-- if so, keep first line for the report? and for exception regex?

- Process:
-- Multithreading?
-- Timeout?

# Q&A 

- Is it possible to speed up docker build?
-- not using ubuntu 18:04 in all dockerfile
-- improve docker caching

- Is it possible to speed up client execution?
-- multithreading?

-- teku is running inside the eth2diff docker without java installed?
