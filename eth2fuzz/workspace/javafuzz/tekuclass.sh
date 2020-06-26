#!/bin/bash

# Create classpath
cp=""

for jar in ../../teku/build/install/teku/lib/*.jar; do
  cp="$cp:$jar"
done

#for jar in ./testfuzz/*.jar; do
#  cp="$cp:$jar"
#done

for jar in ../../jqf/fuzz/target/dependency/*.jar; do
  cp="$cp:$jar"
done

for jar in ../../jqf/fuzz/target/*.jar; do
  cp="$cp:$jar"
done

echo $cp
