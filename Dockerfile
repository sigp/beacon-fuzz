FROM ubuntu:18.04
WORKDIR /eth2

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential clang-6.0 git zlib1g-dev libssl-dev libboost-all-dev wget locales curl python3-pip

# install bazel - could pull their image but want to keep it all available on 18.04
RUN echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list \
&& curl https://bazel.build/bazel-release.pub.gpg | apt-key add -

RUN apt-get update && apt-get install -y bazel

RUN git clone --branch fuzzing --depth 1 https://github.com/guidovranken/cpython.git

RUN wget https://dl.google.com/go/go1.12.linux-amd64.tar.gz
RUN tar -zxf go1.12.linux-amd64.tar.gz

# Should be at b7a0feb7253965b1d5e622b6247736ca29e1a254
RUN git clone --branch v0.8.3 --depth 1 https://github.com/sigp/lighthouse lighthouse

ADD files /eth2

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8
RUN /eth2/build.sh
