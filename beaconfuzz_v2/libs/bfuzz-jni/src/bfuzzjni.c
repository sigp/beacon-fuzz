#include "bfuzzjni.h"

#include <inttypes.h>
#include <jni.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LINT_C_FILE

// TODO(gnattishness) note assumptions regarding trying to fuzz multiple Java
// targets or implementations

// NOTE: just use global variables to store state for now
// Means we can't have more than 1 Java client at once, but can't run multiple
// JVM interpreters anyway

static JavaVM *g_jvm;  // Pointer to the JVM
static JNIEnv *g_env;  // Pointer to native interface
static jclass g_fuzz_class;
static jobject g_fuzz_instance;
static jmethodID g_fuzz_method;
static jclass g_optional_class;
static jmethodID g_optional_is_present;
static jmethodID g_optional_get;

/**
 * Holds the last result from the fuzzing target.
 *
 * May be NULL if the last result was an error
 * A JNI global ref, needs to be explicitly freed.
 */
static jobject g_last_result;

/**
 * Stores the size of the last result, if it exists.
 *
 * May be -1 if the last result was an error.
 *
 * (Used for bounds checking)
 *
 * \Note jsize == int32_t
 */
static int32_t g_last_result_size;

// TODO(gnattishness) do we reset g_last_result_size or leave as garbage when
// freeing last result? if reset, can more safely handle when an error-free,
// valid result is empty (with size 0)
// * Only valid when `g_last_result != NULL`

// TODO(gnattishness) use a persistent block of memory to hold most recent
// result or malloc/free every time? time vs space tradeoffs we malloc for now,
// for simplicity

/**
 * TODO(gnattishness) delete, outdated?
 * Helper function to setup the temporary "g_last_result" storage for some size
 *
 * Upon completion, g_last_result points to some memory that can hold new_size
 * bytes, and g_last_result_size == new_size.
 *
 * appropriately handles if g_last_result == NULL or not without leaking memory
 *
 * \param[in] new_size How big g_last_result should be.
 *    If 0 or negative, g_last_result is set to NULL.
 *
 */
// void prepare_last_result(int32_t new_size){
//  // Also good for encapsulation so can more easily convert to fancier
//  // methods to reduce memory allocations between fuzzing executions
//  if (new_size <= 0) {
//    if (g_last_result != NULL) {
//      free(g_last_result);
//      g_last_result = NULL;
//    }
//  } else if (g_last_result != NULL) {
//    g_last_result = realloc(new_size);
//    if (g_last_result == NULL) {
//      fprintf(stderr, "BFUZZ Fatal: memory allocation failed.");
//      abort();
//    }
//  } else {
//    g_last_result = malloc(new_size);
//    if (g_last_result == NULL) {
//      fprintf(stderr, "BFUZZ Fatal: memory allocation failed.");
//      abort();
//    }
//  }
//  g_last_result_size = new_size;
//}

/**
 * Just some safety checking.
 *
 * Should be NULL if bfuzz_jni_load_result was appropriately called after a
 * successful result.
 */
void last_result_should_be_null() {
  if (g_last_result != NULL) {
    fprintf(stderr,
            "BFUZZ warning: Need to call bfuzz_jni_load_result after every "
            "successful call to bfuzz_jni_run! Likely bug in fuzzer.\n");
    (*g_env)->DeleteGlobalRef(g_env, g_last_result);
    g_last_result = NULL;
  }
}

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
                    char const *class_path, bool bls_disabled) {
  // TODO(gnattishness) more docs on what the expected Java interface looks
  // like? i.e. Java take in some byte array and returns an optional byte array
  JavaVMInitArgs vm_args;
  size_t len = strlen(class_path);
  char const *prefix = "-Djava.class.path=";
  size_t prefix_len = strlen(prefix);
  // can be big so use a heap variable
  char *class_path_option = malloc(prefix_len + len + 1);
  if (class_path_option == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Failed to allocate class_path_option memory");
    abort();
  }
  strncpy(class_path_option, prefix, prefix_len + 1);
  // TODO(gnattishness) best practice to add a null at the end here? it should
  // never overflow anyway
  strncat(class_path_option, class_path, len);

  JavaVMOption options[1];
  options[0].optionString = class_path_option;
  // options[1].optionString = (char*)"-verbose:jni";

  // TODO(gnattishness) abort and exit hooks if it doesn't immediately abort
  // already?
  // https://docs.oracle.com/en/java/javase/11/docs/specs/jni/invocation.html#jni_createjavavm
  // TODO(gnattishness) what version should I use?
  vm_args.version = JNI_VERSION_10;
  vm_args.nOptions = 1;
  vm_args.options = options;
  vm_args.ignoreUnrecognized = false;
  jint err = JNI_CreateJavaVM(&g_jvm, (void **)&g_env, &vm_args);
  if (err != JNI_OK) {
    fprintf(stderr,
            "BFUZZ Fatal: JNI_CreateJavaVM() initialization failed: %" PRId32
            "\n",
            (int32_t)err);
    abort();
  }

  g_fuzz_class = (*g_env)->FindClass(g_env, fuzz_class_name);
  if (g_fuzz_class == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Unable to load %s class definition\n",
            fuzz_class_name);
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  jmethodID fuzzCtor =
      (*g_env)->GetMethodID(g_env, g_fuzz_class, "<init>", "(ZZ)V");
  if (fuzzCtor == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Unable to locate fuzz class constructor\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  // bool params correspond to useMainnetConfig, disable_bls flags
  g_fuzz_instance = (*g_env)->NewObject(g_env, g_fuzz_class, fuzzCtor, JNI_TRUE,
                                        bls_disabled);
  if (g_fuzz_instance == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Unable to construct fuzz class instance.\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  g_fuzz_method = (*g_env)->GetMethodID(g_env, g_fuzz_class, fuzz_method_name,
                                        "([B)Ljava/util/Optional;");
  if (g_fuzz_method == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Unable to find method: %s.\n",
            fuzz_method_name);
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  // we keep a reference to this so subsequent methodIds remain valid
  // see
  // https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html#accessing-fields-and-methods
  g_optional_class = (*g_env)->FindClass(g_env, "java/util/Optional");
  if (g_optional_class == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Unable to locate \"Optional\" class\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  g_optional_is_present =
      (*g_env)->GetMethodID(g_env, g_optional_class, "isPresent", "()Z");
  if (g_optional_is_present == NULL) {
    fprintf(stderr,
            "BFUZZ Fatal: Unable to locate Optional.isPresent() method\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  // NOTE: for the types here, get should return a jbyteArray "()[B", but this
  // is not enforced at runtime
  g_optional_get = (*g_env)->GetMethodID(g_env, g_optional_class, "get",
                                         "()Ljava/lang/Object;");
  if (g_optional_get == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Unable to locate Optional.get() method\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }

  g_last_result =
      NULL;  // It should probably be this anyway, but double checking.
  g_last_result_size = -1;
  // TODO(gnattishness) detach?
}

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
int32_t bfuzz_jni_run(uint8_t *data, size_t size) {
  last_result_should_be_null();

  if (size > INT32_MAX) {
    // this makes it ok to call NewByteArray without worrying about it
    // truncating the size value.
    fprintf(stderr,
            "BFUZZ Fatal: input size %zu too large for Java Array (must be "
            "within int32)\n",
            size);
    abort();
  }

  // TODO(gnattishness) in 2 steps to find the exact size?
  // Does rust want to provide the return destination?
  // or do we make it free the result?
  // Just do the same as for Prysm for now
  //
  // TODO(gnattishness) think about how many times these are copied
  // TODO(gnattishness) use primitivearraycritical to reduce copying?

  jbyteArray input = (*g_env)->NewByteArray(g_env, size);
  if (input == NULL) {
    fprintf(stderr, "BFUZZ Fatal: Unable to create input jarray.\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }

  (*g_env)->SetByteArrayRegion(g_env, input, 0, size, (const jbyte *)data);

  // NOTE: type checking is not performed here
  jobject maybe_result =
      (*g_env)->CallObjectMethod(g_env, g_fuzz_instance, g_fuzz_method, input);
  if ((*g_env)->ExceptionCheck(g_env) == JNI_TRUE) {
    fprintf(stderr, "Uncaught Java exception:\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  (*g_env)->DeleteLocalRef(g_env, input);  // no longer need this

  if ((*g_env)->CallBooleanMethod(g_env, maybe_result, g_optional_is_present) ==
      JNI_TRUE) {
    // bytes were returned
    jbyteArray result = (jbyteArray)(*g_env)->CallObjectMethod(
        g_env, maybe_result, g_optional_get);
    if (result == NULL) {
      fprintf(stderr, "BFUZZ Fatal: Java result array unexpectedly NULL.\n");
      (*g_env)->ExceptionDescribe(g_env);
      abort();
    }
    jsize result_size = (*g_env)->GetArrayLength(g_env, result);
    if ((*g_env)->ExceptionCheck(g_env) == JNI_TRUE) {
      // NOTE: better practice to check for pending exceptions after each
      // call, as later calls may have undefined behavior, but we are ok to
      // abort if any exception occurs in the above
      fprintf(stderr,
              "BFUZZ Fatal: Unexpected exception extracting Java result.\n");
      (*g_env)->ExceptionDescribe(g_env);
      abort();
    }

    if (result_size == 0) {
      // don't worry about the result if it's a 0 length array
      (*g_env)->DeleteLocalRef(g_env, result);
    } else {
      g_last_result = (*g_env)->NewGlobalRef(env, result);
      if (g_last_result == NULL) {
        fprintf(stderr, "BFUZZ Fatal: System probably out of memory.\n");
        abort();
      }
    }
    g_last_result_size = result_size;
  } else {
    // optional result is empty, indicating an error during processing
    g_last_result_size = -1;
  }

  // docs e.g.
  // https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html#referencing-java-objects
  // refer to the case where java is calling a native method that eventually
  // returns not the other way around - can a local ref used within a c++
  // method be freed during any subsequent JNI method that is not
  // `NewGlobalRef`?
  //
  // or are local references never automatically freed because this doesn't
  // "return" to Java according to this:
  // https://www.ibm.com/support/knowledgecenter/en/SSYKE2_8.0.0/com.ibm.java.vm.80.doc/docs/jni_refs.html
  // we would need to detach from the JVM in order for automatic garbage
  // collection to occur as this is single threaded, we never perform garbage
  // collection unless we detach or manually Can methods create local
  // references internally that can then explode?
  //
  // could detach and attach the jvm each time, but a fair bit of overhead?
  // And how would gc occur without an active Java thread? a daemon-thread?
  // TODO(gnattishness) if internal code creates local references that are
  // never gc'd we'd need to detach
  //
  // TODO(gnattishness) delete local references
  // shouldn't need to worry about threads and attaching the vm,
  // as libfuzzer is single-threaded
  //
  // don't have to worry about cleaning up if we abort.
  (*g_env)->DeleteLocalRef(g_env, maybe_result);

  // TODO(gnattishness) detach?
  return g_last_result_size;
}

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
void bfuzz_jni_load_result(uint8_t *dest, size_t size) {
  if (g_last_result_size == -1) {
    // Either called this twice in a row, or trying to get a result when an
    // error was returned
    fprintf(stderr,
            "BFUZZ Fatal: trying to load a result when none was last returned. "
            "Bug in fuzzing!\n");
    abort();
  }
  if (size != g_last_result_size) {
    fprintf(stderr,
            "BFUZZ Fatal: trying to load result with wrong size. Bug in "
            "fuzzing!\n");
    abort();
  }
  if (g_last_result_size == 0) {
    // TODO(gnattishness) implement - what to do it last_result_size is 0?
    // complain or zero out, or noop?
    fprintf(stderr,
            "Need to figure out what to do for empty but valid results\n");
    abort();
  }
  (*g_env)->GetByteArrayRegion(g_env, g_last_result, 0, size, (*jbyte)(dest));
  if ((*g_env)->ExceptionCheck(g_env) == JNI_TRUE) {
    fprintf(stderr,
            "BFUZZ Fatal: Unexpected exception extracting Java result.\n");
    (*g_env)->ExceptionDescribe(g_env);
    abort();
  }
  // free g_last_result and uninitialize it
  (*g_env)->DeleteGlobalRef(g_env, g_last_result);
  g_last_result = NULL;
  g_last_result_size = -1;

  // TODO(gnattishness) detach?
}

// TODO(gnattishness) destroy VM?
