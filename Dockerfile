FROM ubuntu:18.04
WORKDIR /eth2

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential clang-6.0 git zlib1g-dev libssl-dev libboost-all-dev wget locales

RUN git clone https://github.com/guidovranken/cpython.git
RUN cd cpython && git checkout fuzzing

RUN wget https://dl.google.com/go/go1.12.linux-amd64.tar.gz
RUN tar zxvf go1.12.linux-amd64.tar.gz

ADD files /eth2

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8
RUN /eth2/build.sh
