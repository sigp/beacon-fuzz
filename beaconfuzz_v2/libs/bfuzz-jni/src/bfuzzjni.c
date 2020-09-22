#include "bfuzzjni.h"

#include <inttypes.h>
#include <jni.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LINT_C_FILE

// NOTE: just use global variables to store state for now
// Means we can't have more than 1 Java client at once, but can't run multiple
// JVM interpreters anyway

static JavaVM *jvm;  // Pointer to the JVM
static JNIEnv *env;  // Pointer to native interface
static jclass fuzz_class;
static jobject fuzz_instance;
static jmethodID fuzz_method;
static jclass optional_class;
static jmethodID optional_is_present;
static jmethodID optional_get;

/*
 * Initialize Java vm and target for fuzzing.
 *
 * Should only be called once for the lifetime of the process.
 */
void bfuzz_jni_init(char const *fuzz_class_name, char const *fuzz_method_name,
                    char const *class_path, bool bls_disabled) {
  JavaVMInitArgs vm_args;
  size_t len = strlen(class_path);
  char const *prefix = "-Djava.class.path=";
  size_t prefix_len = strlen(prefix);
  // can be big so use a heap variable
  char *class_path_option = malloc(prefix_len + len + 1);
  if (class_path_option == NULL) {
    fprintf(stderr, "Fatal: Failed to allocate class_path_option memory");
    abort();
  }
  strncpy(class_path_option, prefix, prefix_len + 1);
  // TODO(gnattishness) best practice to add a null at the end here? it should
  // never overflow anyway
  strncat(class_path_option, class_path, len);

  JavaVMOption options[1];
  // do this instead of directly passing the literal, as optionString wants a
  // char* not a const char*
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
  jint err = JNI_CreateJavaVM(&jvm, (void **)&env, &vm_args);
  if (err != JNI_OK) {
    fprintf(stderr,
            "Fatal: JNI_CreateJavaVM() initialization failed: %" PRId32 "\n",
            (int32_t)err);
    abort();
  }

  fuzz_class = (*env)->FindClass(env, fuzz_class_name);
  if (fuzz_class == NULL) {
    fprintf(stderr, "Fatal: Unable to load %s class definition\n",
            fuzz_class_name);
    (*env)->ExceptionDescribe(env);
    abort();
  }
  jmethodID fuzzCtor = (*env)->GetMethodID(env, fuzz_class, "<init>", "(ZZ)V");
  if (fuzzCtor == NULL) {
    fprintf(stderr, "Fatal: Unable to locate fuzz class constructor\n");
    (*env)->ExceptionDescribe(env);
    abort();
  }
  // bool params correspond to useMainnetConfig, disable_bls flags
  fuzz_instance =
      (*env)->NewObject(env, fuzz_class, fuzzCtor, JNI_TRUE, bls_disabled);
  if (fuzz_instance == NULL) {
    fprintf(stderr, "Fatal: Unable to construct fuzz class instance.\n");
    (*env)->ExceptionDescribe(env);
    abort();
  }
  fuzz_method = (*env)->GetMethodID(env, fuzz_class, fuzz_method_name,
                                    "([B)Ljava/util/Optional;");
  if (fuzz_method == NULL) {
    fprintf(stderr, "Fatal: Unable to find method: %s.\n", fuzz_method_name);
    (*env)->ExceptionDescribe(env);
    abort();
  }
  // we keep a reference to this so subsequent methodIds remain valid
  // see
  // https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html#accessing-fields-and-methods
  optional_class = (*env)->FindClass(env, "java/util/Optional");
  if (optional_class == NULL) {
    fprintf(stderr, "Fatal: Unable to locate \"Optional\" class\n");
    (*env)->ExceptionDescribe(env);
    abort();
  }
  optional_is_present =
      (*env)->GetMethodID(env, optional_class, "isPresent", "()Z");
  if (optional_is_present == NULL) {
    fprintf(stderr, "Fatal: Unable to locate Optional.isPresent() method\n");
    (*env)->ExceptionDescribe(env);
    abort();
  }
  // NOTE: for the types here, get should return a jbyteArray "()[B", but this
  // is not enforced at runtime
  optional_get =
      (*env)->GetMethodID(env, optional_class, "get", "()Ljava/lang/Object;");
  if (optional_get == NULL) {
    fprintf(stderr, "Fatal: Unable to locate Optional.get() method\n");
    (*env)->ExceptionDescribe(env);
    abort();
  }
}

uint8_t *bfuzz_jni_run(uint8_t *data, size_t size) {
  // TODO(gnattishness)
  //

  // TODO(gnattishness) in 2 steps to find the exact size?
  // Does rust want to provide the return destination?
  // or do we make it free the result?
  // Just do the same as for Prysm for now
  //
  // TODO(gnattishness) think about how many times these are copied
}

// TODO(gnattishness) destroy VM?
