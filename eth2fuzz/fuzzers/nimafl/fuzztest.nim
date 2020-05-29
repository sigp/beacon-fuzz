import streams, posix, strutils, chronicles, macros, stew/ranges/ptr_arith

template fuzz(body) =
  # For code we want to fuzz, SIGSEGV is needed on unwanted exceptions.
  # However, this is only needed when fuzzing with afl.
  when defined(afl):
    try:
      body
    except Exception as e:
      error "Fuzzer input created exception", exception=e.name, trace=e.repr,
        msg=e.msg
      discard kill(getpid(), SIGSEGV)
  else:
    body

proc readStdin(): seq[byte] =
  # Read input from stdin (fastest for AFL)
  let s = newFileStream(stdin)
  if s.isNil:
    error "Error opening stdin"
    discard kill(getpid(), SIGSEGV)
  # We use binary files as with hex we can get lots of "not hex" failures
  var input = s.readAll()
  s.close()
  # Remove newline if it is there
  input.removeSuffix
  result = cast[seq[byte]](input)

proc NimMain() {.importc: "NimMain".}

# The default init, gets redefined when init template is used.
template initImpl(): untyped =
  when not defined(libFuzzer):
    discard
  else:
    proc fuzzerInit(): cint {.exportc: "LLVMFuzzerInitialize".} =
      NimMain()

      return 0

template init*(body: untyped) =
  ## Init block to do any initialisation for the fuzzing test.
  ##
  ## For AFL this is currently only cosmetic and will be run each time, before
  ## the test block.
  ##
  ## For libFuzzer this will only be run once. So only put data which is
  ## stateless or make sure everything gets properply reset for each new run in
  ## the test block.
  when not defined(libFuzzer):
    template initImpl(): untyped = fuzz: `body`
  else:
    template initImpl() =
      proc fuzzerInit(): cint {.exportc: "LLVMFuzzerInitialize".} =
        NimMain()

        `body`

        return 0

template test*(body: untyped): untyped =
  ## Test block to do the actual test that will be fuzzed in a loop.
  ##
  ## Within this test block there is access to the payload OpenArray which
  ## contains the payload provided by the fuzzer.
  mixin initImpl
  initImpl()
  when not defined(libFuzzer):
    var payload {.inject.} = readStdin()

    fuzz: `body`
  else:
    proc fuzzerCall(data: ptr byte, len: csize):
        cint {.exportc: "LLVMFuzzerTestOneInput".} =
      template payload(): auto =
        makeOpenArray(data, len)

      `body`

when defined(clangfast):
  ## Can be used for deferred instrumentation.
  ## Should be placed on a suitable location in the code where the delayed
  ## cloning can take place (e.g. NOT after creation of threads)
  proc aflInit*() {.importc: "__AFL_INIT", noDecl.}
  ## Can be used for persistent mode.
  ## Should be used as value for controlling a loop around a test case.
  ## Test case should be able to handle repeated inputs. No repeated fork() will
  ## be done.
  # TODO: Lets use this in the test block when afl-clang-fast is used?
  proc aflLoopImpl(count: cuint): cint {.importc: "__AFL_LOOP", noDecl.}
  template aflLoop*(body: untyped): untyped =
    while aflLoopImpl(1000) != 0:
      `body`
else:
  proc aflInit*() = discard
  template aflLoop*(body: untyped): untyped = `body`
