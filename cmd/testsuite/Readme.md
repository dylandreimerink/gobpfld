# Test suite

This test suite attempts to test GoBPFLD, which consists of a few different kinds of tests:
- Integration tests - Execute a series of common BPF scenarios to see if we crash or get unexpected errors. This includes the loading of all sorts of programs and maps. We want a much coverage as possible.
- Compatibility tests - Execute the same tests on multiple architectures and kernel versions. GoBPFLD should be able to work on any architecture, and give proper warnings if features are not available on older kernels.
- Fuzzing - Call GoBPFLD with semi-random input in an attempt to break it. GoBPFLD should never panic in bad input, just return errors which users can handle. Focus areas are ELF parsing and decoding(including BTF, Program, and Map).


## TODO / The plan

* Provide pre-compiled kernelBz + initrd images for a few kernel version (before and after notable BPF changes) via bpfci repo/project
* Provide pre-compiled kernelBz + initrd images for x86_64, i386, arm64 and RISC-V (maybe just the newest kernel versions for now) via bpfci repo/project
* Create `go test` compatible eBPF/XDP tests
* Create go program which automates environment setup and tests
  * Pick which tests to run via the sub-commands
  * Execute C/BPF recompilation(not needed if .o files are already committed)
  * Execute go test/go build command for tests (add flag to only compile a specific test(for during debugging))
    * (cross) compile for x86_64, i386, arm64 and RISC-V if requested (command line flag)
    * Compile with coverage if requested (command line flag)
    * Compile with race condition checking if requested (command line flag)
    * Compile with profiling options if requested (command line flags)
    * Compile with JSON output (always, for automatic test checking)
  * Run tests in QEMU for arch under test
    * Make a mountable disk image on host (.qcow2 or raw)
      * Place `run.sh` or `exec.sh` (known name called by bpfci `init` on load) in image
        * script will execute generated test executable with requested cli arguments
        * All outputs(exit code, stdout, stderr, coverage, profiles) are written to the mounted image
        * After running tests, make the script poweroff the VM to indicate to the host we are done
      * Place the unit test binary on the image
    * Start VM which will start the tests once ready
    * Mount or unpack the disk image and extract the test results
  * Post process results
    * Evaluate test results(json output) and display human readable errors.
    * Generate HTML coverage reports(include raw data and HTML version)
    * Generate SVGs of profiles
    * Make .zip/.tar.gz of all results in run(may be multiple kernel versions / architectures)
    * Display short and detailed test report (in markdown to be included in git)
  * Run fuzzer (TODO research how to go about this)