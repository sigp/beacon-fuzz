#ifndef BEACONFUZZ_V2_LIBS_BFUZZ_JNI_SRC_BFUZZJNI_H_
#define BEACONFUZZ_V2_LIBS_BFUZZ_JNI_SRC_BFUZZJNI_H_

#include <stdint.h>
#include <stdlib.h>

void bfuzz_jni_init(char const *fuzz_class_name, char const *fuzz_method_name,
                    char const *class_path, bool bls_disabled);

uint8_t *bfuzz_jni_run(uint8_t *data, size_t size);

#endif  // BEACONFUZZ_V2_LIBS_BFUZZ_JNI_SRC_BFUZZJNI_H_
