---
name: Identified Fuzz Crash
about: Report an identified fuzzing crasher.
title: "[FUZZ]"
labels: ''
assignees: ''

---

I've identified a fuzzer crash and am contributing to the security of Ethereum 2!

## I've done and provided the following:
- [ ] Checked to see if any other `[FUZZ]` issue already refers to that crasher
- [ ] Attached the crashing input (either attached to the issue as a .zip or .gz, or as a link to a file sharing service)
- [ ] Noted the `beacon-fuzz` version or commit used.
- [ ] Provided crash output
- [ ] Noted the command or fuzzer used to generate the crash
- [ ] Name of the original crash file
- [ ] (Optional but optimal) Checked if the crash can be consistently replicated by re-running the input. <!-- Don't worry if you are not sure how to do this -->

## Info to Reproduce
* Command run: e.g. `make fuzz-all`
* Crasher file name: <!--- e.g. crash-e7a78510d1324f48fc6014764e08e06b1bef8bbd -->
* Client exercised: <!--- e.g. lighthouse, nimbus -->
* Fuzzing engine used (if applicable):

## Crash output and stacktrace

```console
...
#73721231       REDUCE ft: 1888 corp: 403/19Kb lim: 4096 exec/s: 6368 rss: 55Mb L: 104/3598 MS: 2 CMP-EraseBytes- DE: "\x00\x04"-
panic: runtime error: index out of range [0] with length 0

goroutine 17 [running, locked to thread]:
github.com/XXXX/XXXX/XXXX.(*Struct).Method(0xc00020bbf8, 0x3141c80, 0xc00035a420, 0x3141c80, 0xc00035a420)
        rest of stack trace
....
NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 2 ChangeASCIIInt-InsertByte-; base unit: bc7c01b009b645a2c8546b1c4fef3574746b6196
0x83,0x83,0x85,0x80,0x80,0x80,0x82,0x82,0x89,0x31,0x42,0x0,0x4,0x55,0x2,0x85,0x80,0x84,0x5b,0x57,0x0,0x2,0x85,0x80,0x84,0x32,0x55,0x2,0x85,0x3a,0x80,0x5b,0x83,0x85,0x80,0x0,0x55,0x0,0x85,0x80,0x0,0x55,0x0,0x0,0x0,0x1,0x2,0x7c,0x80,0x84,0x1b,0x57,0x84,0x5b,0x21,0x85,0x80,0x0,0x55,0x0
artifact_prefix='./'; Test unit written to ./crash-e34438510d1324f48fc6014764e08e06b1bef8ded
Base64: g4OFgICAgoMUIABFUC
```

## Your Environment
<!--- Include as many relevant details about the environment you identified the crash in -->
* Fuzzer ran:
* Version/Commit used:
* Operating System and version:
