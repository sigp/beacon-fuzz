# PRYSM

Prysm: An Ethereum 2.0 Client Written in Go - [github](https://github.com/prysmaticlabs/prysm)

## Installation

Installing Prysm on GNU/Linux with Bazel - [link](https://docs.prylabs.network/docs/install/lin/bazel/)


Install bazel: https://docs.bazel.build/versions/master/install-ubuntu.html

``` sh
sudo apt install curl -y
curl https://bazel.build/bazel-release.pub.gpg | sudo apt-key add -
echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list

sudo apt update && sudo apt install bazel-3.0.0
```

pcli info: https://github.com/prysmaticlabs/prysm/pull/5644/files

Test pcli:
``` sh
bazel run //tools/pcli:pcli -- state-transition --pre-state-path /path/to/state.ssz --block-path /path/to/block.ssz
```

``` sh
bazel build //tools/pcli:pcli
cp bazel-bin/tools/pcli/linux_amd64_stripped/pcli .

```
