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
  explicit Impl(bool bls_disabled) {
    // TODO(gnattishness) Java-level initialization e.g. instantiate FuzzUtil
    // class? classpath as parameter and class name, method as parameter?
    // TODO(gnattishness) config details optionally via Environment to allow
    // classes to be moved around after compilation
    JavaVMInitArgs vmArgs;
    std::string classPath(
        "-Djava.class.path=/eth2/teku/build/install/teku/lib/"
        "artemis-0.8.2-SNAPSHOT.jar:/eth2/teku/build/install/teku/lib/"
        "artemis-0.8.2-SNAPSHOT.jar:/eth2/teku/build/install/teku/lib/"
        "artemis-services-beaconchain-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-services-powchain-0.8.2-SNAPSHOT.jar:/eth2/"
        "teku/build/install/teku/lib/"
        "artemis-services-chainstorage-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-sync-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-networking-eth2-0.8.2-SNAPSHOT.jar:/eth2/"
        "teku/build/install/teku/lib/"
        "artemis-data-beaconrestapi-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-networking-p2p-0.8.2-SNAPSHOT.jar:/eth2/teku/"
        "build/install/teku/lib/"
        "artemis-validator-coordinator-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-ethereum-statetransition-0.8.2-SNAPSHOT.jar:/"
        "eth2/teku/build/install/teku/lib/"
        "artemis-services-serviceutils-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-events-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-data-recorder-0.8.2-SNAPSHOT.jar:/eth2/teku/"
        "build/install/teku/lib/artemis-validator-client-0.8.2-SNAPSHOT.jar:/"
        "eth2/teku/build/install/teku/lib/"
        "artemis-data-provider-0.8.2-SNAPSHOT.jar:/eth2/teku/build/install/"
        "teku/lib/artemis-data-0.8.2-SNAPSHOT.jar:/eth2/teku/build/install/"
        "teku/lib/artemis-data-metrics-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-storage-0.8.2-SNAPSHOT.jar:/eth2/teku/build/"
        "install/teku/lib/artemis-ethereum-datastructures-0.8.2-SNAPSHOT.jar:/"
        "eth2/teku/build/install/teku/lib/artemis-pow-0.8.2-SNAPSHOT.jar:/eth2/"
        "teku/build/install/teku/lib/artemis-util-0.8.2-SNAPSHOT.jar:/eth2/"
        "teku/build/install/teku/lib/tuweni-plumtree-0.9.0.jar:/eth2/teku/"
        "build/install/teku/lib/tuweni-ssz-0.9.0.jar:/eth2/teku/build/install/"
        "teku/lib/tuweni-rlpx-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-crypto-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-units-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "jvm-libp2p-minimal-0.3.2-RELEASE.jar:/eth2/teku/build/install/teku/"
        "lib/tuweni-kv-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-rlp-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-bytes-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-config-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "milagro-crypto-java-0.4.0.jar:/eth2/teku/build/install/teku/lib/"
        "metrics-core-1.3.4.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-io-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-concurrent-coroutines-0.9.0.jar:/eth2/teku/build/install/teku/"
        "lib/tuweni-concurrent-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "mapdb-3.0.7.jar:/eth2/teku/build/install/teku/lib/"
        "kotlinx-coroutines-guava-1.1.1.jar:/eth2/teku/build/install/teku/lib/"
        "guava-28.1-jre.jar:/eth2/teku/build/install/teku/lib/"
        "log4j-slf4j-impl-2.12.1.jar:/eth2/teku/build/install/teku/lib/"
        "log4j-core-2.12.1.jar:/eth2/teku/build/install/teku/lib/"
        "gson-2.8.6.jar:/eth2/teku/build/install/teku/lib/"
        "tuweni-toml-0.9.0.jar:/eth2/teku/build/install/teku/lib/"
        "picocli-4.0.4.jar:/eth2/teku/build/install/teku/lib/"
        "vertx-web-3.8.3.jar:/eth2/teku/build/install/teku/lib/"
        "vertx-web-common-3.8.3.jar:/eth2/teku/build/install/teku/lib/"
        "vertx-auth-common-3.8.3.jar:/eth2/teku/build/install/teku/lib/"
        "vertx-core-3.8.3.jar:/eth2/teku/build/install/teku/lib/"
        "log4j-api-2.12.1.jar:/eth2/teku/build/install/teku/lib/"
        "plugin-api-1.3.4.jar:/eth2/teku/build/install/teku/lib/"
        "failureaccess-1.0.1.jar:/eth2/teku/build/install/teku/lib/"
        "listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar:/eth2/"
        "teku/build/install/teku/lib/jsr305-3.0.2.jar:/eth2/teku/build/install/"
        "teku/lib/checker-qual-2.8.1.jar:/eth2/teku/build/install/teku/lib/"
        "error_prone_annotations-2.3.2.jar:/eth2/teku/build/install/teku/lib/"
        "j2objc-annotations-1.3.jar:/eth2/teku/build/install/teku/lib/"
        "animal-sniffer-annotations-1.18.jar:/eth2/teku/build/install/teku/lib/"
        "swagger-core-2.1.1.jar:/eth2/teku/build/install/teku/lib/"
        "commons-lang3-3.9.jar:/eth2/teku/build/install/teku/lib/"
        "reactor-core-3.3.0.RELEASE.jar:/eth2/teku/build/install/teku/lib/"
        "bson4jackson-2.9.2.jar:/eth2/teku/build/install/teku/lib/"
        "core-4.5.6.jar:/eth2/teku/build/install/teku/lib/crypto-4.5.6.jar:/"
        "eth2/teku/build/install/teku/lib/jackson-module-kotlin-2.10.2.jar:/"
        "eth2/teku/build/install/teku/lib/jackson-datatype-jsr310-2.10.1.jar:/"
        "eth2/teku/build/install/teku/lib/jackson-databind-2.10.1.jar:/eth2/"
        "teku/build/install/teku/lib/snappy-java-1.1.7.3.jar:/eth2/teku/build/"
        "install/teku/lib/bcpkix-jdk15on-1.62.jar:/eth2/teku/build/install/"
        "teku/lib/abi-4.5.6.jar:/eth2/teku/build/install/teku/lib/"
        "rlp-4.5.6.jar:/eth2/teku/build/install/teku/lib/utils-4.5.6.jar:/eth2/"
        "teku/build/install/teku/lib/bcprov-jdk15on-1.64.jar:/eth2/teku/build/"
        "install/teku/lib/jackson-dataformat-yaml-2.10.1.jar:/eth2/teku/build/"
        "install/teku/lib/quartz-2.3.2.jar:/eth2/teku/build/install/teku/lib/"
        "json-simple-1.1.jar:/eth2/teku/build/install/teku/lib/"
        "jnr-unixsocket-0.21.jar:/eth2/teku/build/install/teku/lib/"
        "jnr-enxio-0.19.jar:/eth2/teku/build/install/teku/lib/"
        "jnr-posix-3.0.47.jar:/eth2/teku/build/install/teku/lib/"
        "jnr-ffi-2.1.9.jar:/eth2/teku/build/install/teku/lib/"
        "kotlinx-coroutines-jdk8-1.1.1.jar:/eth2/teku/build/install/teku/lib/"
        "kotlinx-coroutines-core-1.3.0-M1.jar:/eth2/teku/build/install/teku/"
        "lib/logging-interceptor-3.8.1.jar:/eth2/teku/build/install/teku/lib/"
        "okhttp-4.2.2.jar:/eth2/teku/build/install/teku/lib/javalin-3.7.0.jar:/"
        "eth2/teku/build/install/teku/lib/kotlin-stdlib-jdk8-1.3.61.jar:/eth2/"
        "teku/build/install/teku/lib/kotlin-reflect-1.3.61.jar:/eth2/teku/"
        "build/install/teku/lib/okio-2.2.2.jar:/eth2/teku/build/install/teku/"
        "lib/kotlin-stdlib-jdk7-1.3.61.jar:/eth2/teku/build/install/teku/lib/"
        "kotlin-stdlib-1.3.61.jar:/eth2/teku/build/install/teku/lib/"
        "antlr4-runtime-4.7.1.jar:/eth2/teku/build/install/teku/lib/"
        "netty-all-4.1.36.Final.jar:/eth2/teku/build/install/teku/lib/"
        "protobuf-java-3.11.0.jar:/eth2/teku/build/install/teku/lib/"
        "commons-codec-1.13.jar:/eth2/teku/build/install/teku/lib/"
        "jaxb-api-2.3.1.jar:/eth2/teku/build/install/teku/lib/"
        "netty-handler-proxy-4.1.42.Final.jar:/eth2/teku/build/install/teku/"
        "lib/netty-codec-http2-4.1.42.Final.jar:/eth2/teku/build/install/teku/"
        "lib/netty-codec-http-4.1.42.Final.jar:/eth2/teku/build/install/teku/"
        "lib/netty-handler-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-resolver-dns-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-codec-socks-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-codec-dns-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-codec-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-transport-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-buffer-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-resolver-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "netty-common-4.1.42.Final.jar:/eth2/teku/build/install/teku/lib/"
        "jackson-core-2.10.1.jar:/eth2/teku/build/install/teku/lib/"
        "vertx-bridge-common-3.8.3.jar:/eth2/teku/build/install/teku/lib/"
        "HikariCP-java7-2.4.13.jar:/eth2/teku/build/install/teku/lib/"
        "slf4j-api-1.7.28.jar:/eth2/teku/build/install/teku/lib/"
        "logl-api-0.3.1.jar:/eth2/teku/build/install/teku/lib/"
        "rxjava-2.2.2.jar:/eth2/teku/build/install/teku/lib/"
        "reactive-streams-1.0.3.jar:/eth2/teku/build/install/teku/lib/"
        "swagger-models-2.1.1.jar:/eth2/teku/build/install/teku/lib/"
        "jackson-annotations-2.10.2.jar:/eth2/teku/build/install/teku/lib/"
        "swagger-ui-3.24.3.jar:/eth2/teku/build/install/teku/lib/"
        "classgraph-4.8.34.jar:/eth2/teku/build/install/teku/lib/"
        "snakeyaml-1.24.jar:/eth2/teku/build/install/teku/lib/"
        "commons-math3-3.6.1.jar:/eth2/teku/build/install/teku/lib/"
        "simpleclient_pushgateway-0.7.0.jar:/eth2/teku/build/install/teku/lib/"
        "simpleclient_common-0.7.0.jar:/eth2/teku/build/install/teku/lib/"
        "simpleclient_hotspot-0.7.0.jar:/eth2/teku/build/install/teku/lib/"
        "simpleclient-0.7.0.jar:/eth2/teku/build/install/teku/lib/"
        "tuples-4.5.6.jar:/eth2/teku/build/install/teku/lib/"
        "Java-WebSocket-1.3.8.jar:/eth2/teku/build/install/teku/lib/"
        "jffi-1.2.17.jar:/eth2/teku/build/install/teku/lib/"
        "jffi-1.2.17-native.jar:/eth2/teku/build/install/teku/lib/"
        "asm-commons-5.0.3.jar:/eth2/teku/build/install/teku/lib/"
        "asm-analysis-5.0.3.jar:/eth2/teku/build/install/teku/lib/"
        "asm-util-5.0.3.jar:/eth2/teku/build/install/teku/lib/"
        "asm-tree-5.0.3.jar:/eth2/teku/build/install/teku/lib/asm-5.0.3.jar:/"
        "eth2/teku/build/install/teku/lib/jnr-a64asm-1.0.0.jar:/eth2/teku/"
        "build/install/teku/lib/jnr-x86asm-1.0.2.jar:/eth2/teku/build/install/"
        "teku/lib/kotlin-stdlib-common-1.3.61.jar:/eth2/teku/build/install/"
        "teku/lib/annotations-13.0.jar:/eth2/teku/build/install/teku/lib/"
        "javax.activation-api-1.2.0.jar:/eth2/teku/build/install/teku/lib/"
        "eclipse-collections-forkjoin-10.2.0.jar:/eth2/teku/build/install/teku/"
        "lib/eclipse-collections-10.2.0.jar:/eth2/teku/build/install/teku/lib/"
        "eclipse-collections-api-10.2.0.jar:/eth2/teku/build/install/teku/lib/"
        "lz4-1.3.0.jar:/eth2/teku/build/install/teku/lib/elsa-3.0.0-M5.jar:/"
        "eth2/teku/build/install/teku/lib/jetty-webapp-9.4.25.v20191220.jar:/"
        "eth2/teku/build/install/teku/lib/"
        "websocket-server-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/jetty-servlet-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/jetty-security-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/jetty-server-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/swagger-annotations-2.1.1.jar:/eth2/teku/build/install/teku/lib/"
        "validation-api-1.1.0.Final.jar:/eth2/teku/build/install/teku/lib/"
        "jnr-constants-0.9.11.jar:/eth2/teku/build/install/teku/lib/"
        "websocket-servlet-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/javax.servlet-api-3.1.0.jar:/eth2/teku/build/install/teku/lib/"
        "websocket-client-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/jetty-client-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/jetty-http-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/lib/"
        "websocket-common-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/"
        "lib/jetty-io-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/lib/"
        "jetty-xml-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/lib/"
        "jetty-util-9.4.25.v20191220.jar:/eth2/teku/build/install/teku/lib/"
        "websocket-api-9.4.25.v20191220.jar");
    JavaVMOption* options = new JavaVMOption[1];
    // do this instead of directly passing the literal, as optionString wants a
    // char* not a const char*
    options[0].optionString = classPath.data();
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

    fuzzClass =
        env->FindClass("tech/pegasys/artemis/statetransition/util/FuzzUtil");
    if (fuzzClass == nullptr) {
      printf("Fatal: Unable to locate \"FuzzUtil\" class\n");
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
    fuzzMethod =
        env->GetMethodID(fuzzClass, "fuzzShuffle", "([B)Ljava/util/Optional;");
    if (fuzzMethod == nullptr) {
      printf("Fatal: Unable to find method.\n");
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

Java::Java(const std::string& name, const bool bls_disabled)
    : Base(), pimpl_{std::make_unique<Impl>(bls_disabled)} {
  name_ = name;
}

std::optional<std::vector<uint8_t>> Java::Run(
    const std::vector<uint8_t>& data) {
  return pimpl_->Run(data);
}

const std::string& Java::name() { return this->name_; }

Java::~Java() = default;

} /* namespace fuzzing */
