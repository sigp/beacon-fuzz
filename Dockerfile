FROM ubuntu:18.04
WORKDIR /eth2

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential clang-8 git zlib1g-dev libssl-dev libboost-all-dev wget locales curl python3-pip g++-8 gcc-8
# For trinity
# TODO trinity has cmake in its dockerfile, needed?
RUN apt-get install -y libleveldb1v5 libleveldb-dev libgmp3-dev libsnappy-dev

RUN wget https://dl.google.com/go/go1.12.linux-amd64.tar.gz
RUN tar -zxf go1.12.linux-amd64.tar.gz

# To clear cache when branch updates
ADD https://api.github.com/repos/gnattishness/cpython/git/refs/heads/fuzzing meta/cpython_version.json
RUN git clone --branch fuzzing --depth 1 https://github.com/gnattishness/cpython.git

# Should be at b7a0feb7253965b1d5e622b6247736ca29e1a254
# This is a tag, so fine to always cache
RUN git clone --branch v0.8.3 --depth 1 https://github.com/sigp/lighthouse lighthouse

# TODO(gnattishness) add other git clones here so they get cached

ADD files /eth2

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8
RUN /eth2/build.sh
