#include <stdio.h>

#include "bfuzzjni.h"

int main() {
  bfuzz_jni_init("DummyFuzzUtil", "fuzzAttestation", ".", 1);
  uint8_t data[50] = {1, 2, 3, 4, 5};
  int out = bfuzz_jni_run(data, 50);
  printf("In C Result val=%d\n", out);
  if (out > 0) {
    uint8_t result[out];
    bfuzz_jni_load_result(result, out);
    printf("Result content: ");
    for (int i = 0; i < 50; i++) {
      printf("%d ", result[i]);
    }
    printf("\n");
  }
}
