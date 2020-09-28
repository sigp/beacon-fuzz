#ifndef BEACONFUZZ_V2_LIBS_BFUZZ_JNI_SRC_BFUZZJNI_H_
#define BEACONFUZZ_V2_LIBS_BFUZZ_JNI_SRC_BFUZZJNI_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Initialize Java vm and target for fuzzing.
 *
 * \warning Should only be called once for the lifetime of the process.
 *
 * \param[in] fuzz_class_name The name Java class containing the fuzzing target
 * to exercise. \param[in] fuzz_method_name The name of the fuzzing target to
 * exercise. \param[in] class_path Java Classpath containing user defined
 * classes and packages. Colon delimited in Unix. \param[in] bls_disabled
 * Whether to disable bls verification. \see
 * https://en.wikipedia.org/wiki/Classpath
 */
void bfuzz_jni_init(char const *fuzz_class_name, char const *fuzz_method_name,
                    char const *class_path, bool bls_disabled);

/**
 * Run the registered Java fuzzing target with some input.
 *
 * \param[in] data The memory area to pass to the fuzzing target.
 * \param[in] size The number of bytes to pass.
 * \return The number of bytes in the target's output, or -1 if an (expected)
 * error occurred
 *
 * \note
 * max java array size is contained within an int32, so fine to use an int32_t
 * as the return type
 * https://stackoverflow.com/questions/3038392/do-java-arrays-have-a-maximum-size
 * Also GetArrayLength returns a jint, which is an int32
 * https://docs.oracle.com/en/java/javase/11/docs/specs/jni/functions.html#getarraylength
 * https://docs.oracle.com/en/java/javase/11/docs/specs/jni/types.html#primitive-types
 *
 */
int32_t bfuzz_jni_run(uint8_t *data, size_t size);

/**
 * Copy last successful fuzzing result into dest.
 *
 * \param[out] dest the memory region in which to store the result
 * \param[in] size the maximum number of bytes to copy to dest
 *
 * \warning Should only be called at most once per call to bfuzz_jni_run
 *
 * Should be called if the last call to bfuzz_jni_run returned successfully
 *
 * may or may not deallocate the result after copying, so don't call it twice!
 * size is not a necessary parameter, but is used to protect against accidental
 * buffer overflows. will abort if size is not as expected
 */
void bfuzz_jni_load_result(uint8_t *dest, size_t size);

#endif  // BEACONFUZZ_V2_LIBS_BFUZZ_JNI_SRC_BFUZZJNI_H_
