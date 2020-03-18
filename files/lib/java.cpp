#include "java.h"

#include <jni.h>

#include <cinttypes>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

// TODO(gnattishness) wrapper class that dereferences java objects?
// TODO(gnattishness) use smart pointers for jvm etc?
}  // namespace

namespace fuzzing {

// TODO(gnattishness) enable extended JNI checks
class Java::Impl {
 public:
  Impl(const std::string& fuzzClassName, const std::string& fuzzMethodName,
       const std::string& classPath, bool bls_disabled) {
    // TODO(gnattishness) config details optionally via Environment to allow
    // classes to be moved around after compilation
    JavaVMInitArgs vmArgs;
    std::string classPathOption = "-Djava.class.path=" + classPath;
    JavaVMOption* options = new JavaVMOption[1];
    // do this instead of directly passing the literal, as optionString wants a
    // char* not a const char*
    options[0].optionString = classPathOption.data();
    // TODO(gnattishness) abort and exit hooks if it doesn't immediately abort
    // already?
    // https://docs.oracle.com/en/java/javase/11/docs/specs/jni/invocation.html#jni_createjavavm
    vmArgs.version = JNI_VERSION_1_8;
    vmArgs.nOptions = 1;
    vmArgs.options = options;
    vmArgs.ignoreUnrecognized = false;
    jint err = JNI_CreateJavaVM(&jvm, reinterpret_cast<void**>(&env), &vmArgs);
    delete[] options;
    if (err != JNI_OK) {
      printf("Fatal: JNI_CreateJavaVM() initialization failed: %" PRId32 "\n",
             (int32_t)err);
      abort();
    }

    fuzzClass = env->FindClass(fuzzClassName.data());
    if (fuzzClass == nullptr) {
      printf("Fatal: Unable to load %s class definition\n",
             fuzzClassName.data());
      env->ExceptionDescribe();
      abort();
    }
    jmethodID fuzzCtor = env->GetMethodID(fuzzClass, "<init>", "(ZZ)V");
    if (fuzzCtor == nullptr) {
      printf("Fatal: Unable to locate fuzz class constructor\n");
      env->ExceptionDescribe();
      abort();
    }
    // bool params correspond to useMainnetConfig, disable_bls flags
    fuzzInstance = env->NewObject(fuzzClass, fuzzCtor, JNI_TRUE, bls_disabled);
    if (fuzzInstance == nullptr) {
      printf("Fatal: Unable to construct fuzz class instance.\n");
      env->ExceptionDescribe();
      abort();
    }
    // TODO(gnattishness) get method string via parameter
    fuzzMethod = env->GetMethodID(fuzzClass, fuzzMethodName.data(),
                                  "([B)Ljava/util/Optional;");
    if (fuzzMethod == nullptr) {
      printf("Fatal: Unable to find method: %s.\n", fuzzMethodName.data());
      env->ExceptionDescribe();
      abort();
    }
    // we keep a reference to this so subsequent methodIds remain valid
    // see
    // https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html#accessing-fields-and-methods
    optionalClass = env->FindClass("java/util/Optional");
    if (optionalClass == nullptr) {
      printf("Fatal: Unable to locate \"Optional\" class\n");
      env->ExceptionDescribe();
      abort();
    }
    optionalIsPresent = env->GetMethodID(optionalClass, "isPresent", "()Z");
    if (optionalIsPresent == nullptr) {
      printf("Fatal: Unable to locate Optional.isPresent() method\n");
      env->ExceptionDescribe();
      abort();
    }
    // NOTE: for the types here, get should return a jbyteArray "()[B", but this
    // is not enforced at runtime
    optionalGet =
        env->GetMethodID(optionalClass, "get", "()Ljava/lang/Object;");
    if (optionalGet == nullptr) {
      printf("Fatal: Unable to locate Optional.get() method\n");
      env->ExceptionDescribe();
      abort();
    }
  }

  std::optional<std::vector<uint8_t>> Run(const std::vector<uint8_t>& data) {
    std::optional<std::vector<uint8_t>> ret = std::nullopt;
    if (data.empty()) {
      // NOTE: assumes empty input is invalid and returns an error
      // this is the case for all current ssz-based fuzzing, but not true in
      // general. A simplification and optimization to avoid having to worry
      // about empty arrays.
      // TODO(gnattishness) rework to pass empty arrays to the Java harness.
      return ret;
    }
    jbyteArray input = env->NewByteArray(data.size());
    if (input == nullptr) {
      printf("Fatal: Unable to create input jarray.\n");
      env->ExceptionDescribe();
      abort();
    }
    // TODO(gnattishness) maybe want to cast size etc to other jtypes here?
    env->SetByteArrayRegion(input, 0, data.size(), (const jbyte*)data.data());
    // NOTE: type checking is not performed here
    jobject maybeResult =
        env->CallObjectMethod(fuzzInstance, fuzzMethod, input);
    if (env->ExceptionCheck() == JNI_TRUE) {
      printf("Uncaught Java exception:\n");
      env->ExceptionDescribe();
      abort();
    }
    env->DeleteLocalRef(input);  // no longer need this

    if (env->CallBooleanMethod(maybeResult, optionalIsPresent) == JNI_TRUE) {
      // bytes were returned
      jbyteArray result =
          (jbyteArray)env->CallObjectMethod(maybeResult, optionalGet);
      jsize size = env->GetArrayLength(result);
      ret.emplace(size);
      if (size != 0) {
        env->GetByteArrayRegion(result, 0, size,
                                reinterpret_cast<jbyte*>(ret->data()));
      }
      if (env->ExceptionCheck() == JNI_TRUE) {
        // NOTE: better practice to check for pending exceptions after each
        // call, as later calls may have undefined behavior, but we are ok to
        // abort if any exception occurs in the above
        printf("Fatal: Unexpected exception extracting Java result.\n");
        env->ExceptionDescribe();
        abort();
      }
      env->DeleteLocalRef(result);
    } else {
      // optional result is empty, do nothing
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
    env->DeleteLocalRef(maybeResult);
    return ret;
  }

  ~Impl(void) {
    env->DeleteLocalRef(fuzzInstance);
    env->DeleteLocalRef(fuzzClass);
    env->DeleteLocalRef(optionalClass);
    // TODO(gnattishness) should the classes and be global references? - only if
    // we need to detach the thread
    // TODO(gnattishness) handle whether it is the main jvm in the case of 2
    // class instances want to only have 1 JVM globally
    jvm->DestroyJavaVM();
  }

 private:
  JavaVM*
      jvm;  // Pointer to the JVM TODO(gnattishness) have as a global unique?
  JNIEnv* env;  // Pointer to native interface
  jclass fuzzClass;
  jobject fuzzInstance;
  jmethodID fuzzMethod;
  jclass optionalClass;
  jmethodID optionalIsPresent;
  jmethodID optionalGet;
  // class pointer;
  // method pointer
  // jvm env pointer
  // any extra default args?
};

Java::Java(const std::string& fuzzClass, const std::string& fuzzMethod,
           const std::string& classPath, const std::string& name,
           const bool bls_disabled)
    : Base(),
      pimpl_{std::make_unique<Impl>(fuzzClass, fuzzMethod, classPath,
                                    bls_disabled)} {
  name_ = name;
}

std::optional<std::vector<uint8_t>> Java::Run(
    const std::vector<uint8_t>& data) {
  return pimpl_->Run(data);
}

const std::string& Java::name() { return this->name_; }

Java::~Java() = default;

} /* namespace fuzzing */
