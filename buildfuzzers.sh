#!/bin/bash

docker build . --no-cache -t eth2-fuzzers
rm -rf out/
mkdir out
docker run -v `realpath out`:/eth2/out -t eth2-fuzzers /bin/sh -c "find /eth2/files/fuzzers -type f ! -name '*.*' -executable -exec cp {} /eth2/out \;"
