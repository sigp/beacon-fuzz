FROM ubuntu:18.04
WORKDIR /eth2

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential clang-8 git zlib1g-dev libssl-dev libboost-all-dev wget locales curl python3-pip g++-8 gcc-8
# For trinity, teku
RUN apt-get install -y libleveldb1v5 libleveldb-dev libgmp3-dev libsnappy-dev openjdk-11-jdk

# For nimbus
RUN apt-get install -y librocksdb-dev libpcre3-dev

RUN wget -q https://dl.google.com/go/go1.14.linux-amd64.tar.gz
RUN tar -zxf go1.14.linux-amd64.tar.gz

# To clear cache when branch updates
ADD https://api.github.com/repos/gnattishness/cpython/git/refs/heads/fuzzing meta/cpython_version.json
RUN git clone --branch fuzzing --depth 1 https://github.com/gnattishness/cpython.git

# TODO use tag when possible
# This is a tag, so fine to always cache
#RUN git clone --branch XXX --depth 1 https://github.com/sigp/lighthouse lighthouse
RUN git clone --branch master https://github.com/sigp/lighthouse lighthouse && cd lighthouse && git checkout 784997b09bc7c49de9b3ddb5b11680549d577523

# RUN git clone --branch master https://github.com/PegaSysEng/teku && cd teku && git checkout d0848be277bbaa23e271927fd60303e3d44246d4 && ./gradlew dependencies --refresh-dependencies
# TODO replace when suitable harnesses are in teku master
RUN git clone --branch fuzz_utils https://github.com/gnattishness/teku.git && cd teku && ./gradlew installDist -x test --stacktrace

# TODO(gnattishness) add other git clones here so they get cached

ADD files /eth2

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8
RUN /eth2/build.sh
