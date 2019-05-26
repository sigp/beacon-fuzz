FROM ubuntu:18.04
WORKDIR /eth2

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential clang-6.0 git zlib1g-dev libssl-dev libboost-all-dev wget

RUN git clone https://github.com/guidovranken/cpython.git
RUN cd cpython && git checkout fuzzing

RUN wget https://dl.google.com/go/go1.12.linux-amd64.tar.gz
RUN tar zxvf go1.12.linux-amd64.tar.gz

ADD files /eth2

RUN /eth2/build.sh
