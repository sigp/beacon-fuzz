import java.util.Optional;

// TODO convert to testdata

public class DummyFuzzUtil {
  // NOTE: alternatively could also have these all in separate classes, which implement a
  // "FuzzHarness" interface

  // Size of ValidatorIndex returned by shuffle
  private static final int OUTPUT_INDEX_BYTES = Long.BYTES;

  private final boolean disable_bls;

  // NOTE: this uses primitive values as parameters to more easily call via JNI
  public DummyFuzzUtil(final boolean useMainnetConfig, final boolean disable_bls) {
    initialize(useMainnetConfig, disable_bls);
    this.disable_bls = disable_bls;
  }

  public static void initialize(final boolean useMainnetConfig, final boolean disable_bls) {
    System.out.println("Initializing in Java");
  }

  public Optional<byte[]> fuzzAttestation(final byte[] input) {
    System.out.println("Calling Java fuzzAttestation!");
    //Just return the input
    //return Optional.of(input);
    return Optional.empty();
  }
}
