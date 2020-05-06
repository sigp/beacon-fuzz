# TEKU

Teku is a Java implementation of the Ethereum 2.0 Beacon Chain. [github](https://github.com/PegaSysEng/teku)

## Compilation

- Install java 11 on Ubuntu:

``` sh
sudo apt update && sudo apt upgrade
sudo add-apt-repository ppa:linuxuprising/java
sudo apt-get update
sudo apt-get install -y oracle-java11-installer-local
sudo apt-get install oracle-java11-set-default-local
java -version
```
Or using `openjdk11`.


- Copy project and build:
``` sh
git clone https://github.com/PegaSysEng/teku.git
cd teku && ./gradlew installDist
```
