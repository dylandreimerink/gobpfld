package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dylandreimerink/gocovmerge"
	"github.com/dylandreimerink/tarp"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/tools/cover"
)

func main() {
	//nolint:errcheck // can't do anything about an error, cobra prints it already
	rootCmd().Execute()
}

func rootCmd() *cobra.Command {
	c := &cobra.Command{}

	c.AddCommand(
		testCmd(),
	)

	return c
}

var (
	flagVerbose bool
	flagKeepTmp bool

	flagOutputDir  string
	flagCover      bool
	flagCoverMode  string
	flagHTMLReport bool

	flagShort    bool
	flagFailFast bool
	flagRun      string
	flagTestEnvs []string
)

func testCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "test",
		Short: "Build and run unit/integration tests",
		RunE:  buildAndRunTests,
	}

	f := c.Flags()
	f.BoolVarP(&flagVerbose, "verbose", "v", false, "If set, both this command will output verbosely and all called "+
		"commands will be called verbosely as well, thus outputting extra information")
	f.BoolVar(&flagKeepTmp, "keep-tmp", false, "If set, the temporary directories will not be deleted after the test"+
		"run so intermediate files can be inspected")

	f.StringVarP(&flagOutputDir, "output-dir", "o", "./gobpfld-test-results", "Path to the directory where the result "+
		"files are stored (report, coverage, profiling, tracing)")
	f.BoolVar(&flagCover, "cover", false, "Enable coverage analysis")
	f.StringVar(&flagCoverMode, "covermode", "set", "set,count,atomic. Set the mode for coverage analysis for the"+
		" package[s] being tested. The default is \"set\" unless -race is enabled, in which case it is \"atomic\".")
	f.BoolVar(&flagHTMLReport, "html-report", false, "If set, a HTML report will be created combining all available "+
		"data, including all results, coverage, and profiling")

	f.BoolVar(&flagShort, "short", false, "Tell long-running tests to shorten their run time.")
	f.BoolVar(&flagFailFast, "failfast", false, "Do not start new tests after the first test failure.")
	f.StringVar(&flagRun, "run", "", "Run only those tests and examples matching the regular expression."+
		"For tests, the regular expression is split by unbracketed slash (/) "+
		"characters into a sequence of regular expressions, and each part "+
		"of a test's identifier must match the corresponding element in "+
		"the sequence, if any. Note that possible parents of matches are "+
		"run too, so that -run=X/Y matches and runs and reports the result "+
		"of all tests matching X, even those without sub-tests matching Y, "+
		"because it must run them to look for those sub-tests.")
	f.StringArrayVar(&flagTestEnvs, "env", nil, "If set, tests will only be ran in the given environments")
	return c
}

// A list of packages to be included in the test suite
var packages = []string{
	"github.com/dylandreimerink/gobpfld",
	"github.com/dylandreimerink/gobpfld/bpfsys",
	"github.com/dylandreimerink/gobpfld/bpftypes",
	"github.com/dylandreimerink/gobpfld/ebpf",
	"github.com/dylandreimerink/gobpfld/kernelsupport",
	"github.com/dylandreimerink/gobpfld/perf",
	"github.com/dylandreimerink/gobpfld/internal/cstr",
	"github.com/dylandreimerink/gobpfld/internal/syscall",

	// this package may contain complex tests which have no other logical place.
	"github.com/dylandreimerink/gobpfld/cmd/testsuite/integration",
}

func printlnVerbose(args ...interface{}) {
	if !flagVerbose {
		return
	}

	fmt.Println(args...)
}

// testEnv represents a combination of factors to test for
type testEnv struct {
	arch       string
	kernel     string
	bzImageURL string
}

var availableEnvs = map[string]testEnv{
	"linux-5.15.5-amd64": {
		arch:       "amd64",
		kernel:     "5.15.5",
		bzImageURL: "https://github.com/dylandreimerink/bpfci/raw/master/dist/amd64-5.15.5-bzImage",
	},
	"linux-5.4.167-amd64": {
		arch:       "amd64",
		kernel:     "5.4.167",
		bzImageURL: "https://github.com/dylandreimerink/bpfci/raw/master/dist/amd64-5.4.167-bzImage",
	},
	// "linux-5.15.5-arm64": {
	// 	arch:   "arm64",
	// 	kernel: "5.15.5",
	// },
}

func buildAndRunTests(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	// We need to run as root for a lot of the steps involved like mounting disks
	err := elevate()
	if err != nil {
		return fmt.Errorf("error while elevating: %w", err)
	}

	environments := flagTestEnvs
	if len(environments) == 0 {
		for env := range availableEnvs {
			environments = append(environments, env)
		}
	} else {
		for _, env := range flagTestEnvs {
			if _, ok := availableEnvs[env]; !ok {
				var actualEnvNames []string
				for ae := range availableEnvs {
					actualEnvNames = append(actualEnvNames, ae)
				}

				return fmt.Errorf(
					"'%s' is not a valid test environment, pick from: %s",
					env,
					strings.Join(actualEnvNames, ", "),
				)
			}
		}
	}
	// Sort environments so we always execute them in the same order.
	sort.Strings(environments)

	results := make(map[string]map[string]testResult)
	for _, pkg := range packages {
		// Test* to exclude benchmarks(for now)
		testsStr, err := execCmd("go", "test", pkg, "-tags", "bpftests", "-list", "Test*")
		if err != nil {
			return fmt.Errorf("listing tests: %w", err)
		}

		lines := strings.Split(string(testsStr), "\n")
		if len(lines) > 2 {
			lines = lines[:len(lines)-2]
		} else {
			lines = nil
		}

		for _, env := range environments {
			testMap := results[env]
			if testMap == nil {
				testMap = make(map[string]testResult)
			}

			for _, test := range lines {
				testMap[test] = testResult{
					Name:   test,
					Status: statusUntested,
				}
			}
			results[env] = testMap
		}
	}

	// TODO run tests in goroutine and display progress bar (in non-verbose mode)

	envFailed := make(map[string]bool)

	for _, curEnvName := range environments {
		envResults, err := testEnvironment(&testCtx{
			envName: curEnvName,
		})
		for k, v := range envResults {
			results[curEnvName][k] = v
		}
		if err != nil {
			if !errors.Is(err, errTestsFailed) {
				return err
			}

			envFailed[curEnvName] = true

			// If we want to fail fast, don't test any other environments, report what we have
			if flagFailFast {
				break
			}
		}
	}

	if flagHTMLReport {
		htmlPath := path.Join(flagOutputDir, "report.html")
		printlnVerbose("OPEN:", htmlPath)
		htmlFile, err := os.Create(htmlPath)
		if err != nil {
			return fmt.Errorf("create html report: %w", err)
		}
		defer htmlFile.Close()

		err = renderHTMLReport(results, htmlFile)
		if err != nil {
			return fmt.Errorf("render html report: %w", err)
		}
	} else {
		for env, envResults := range results {
			if envFailed[env] {
				fmt.Println("FAIL:", env)
			} else {
				fmt.Println("PASS:", env)
			}

			for _, testResult := range envResults {
				fmt.Printf("  %s: %s (%s)\n", testResult.Status, testResult.Name, testResult.Duration)
			}
		}
	}

	// If there is at least one failed environment, return a non-0 exit code
	if len(envFailed) != 0 {
		os.Exit(2)
	}

	return nil
}

var errTestsFailed = errors.New("one or more tests failed")

type testCtx struct {
	// Set before testEnvironment
	envName string

	// Set by testEnvironment
	results     map[string]testResult
	curEnv      testEnv
	tmpDir      string
	executables []string

	// Set by buildVMDiskImg
	diskPath string

	// Set by downloadLinux
	bzPath     string
	initrdPath string
}

func testEnvironment(ctx *testCtx) (map[string]testResult, error) {
	ctx.curEnv = availableEnvs[ctx.envName]
	ctx.results = make(map[string]testResult)

	printlnVerbose("=== Running tests for", ctx.envName, "===")

	// example: /tmp/bpftestsuite-amd64-1099045701
	var err error
	ctx.tmpDir, err = os.MkdirTemp(os.TempDir(), strings.Join([]string{"bpftestsuite", ctx.curEnv.arch, "*"}, "-"))
	if err != nil {
		return ctx.results, fmt.Errorf("error while making a temporary directory: %w", err)
	}

	printlnVerbose("Using tempdir:", ctx.tmpDir)

	// cleanup the temp dir after we are done, unless the user wan't to keep it
	if !flagKeepTmp {
		defer func() {
			printlnVerbose("--- Cleaning up tmp dir ---")
			err := os.RemoveAll(ctx.tmpDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while cleaning up tmp dir '%s': %s", ctx.tmpDir, err.Error())
			}
			printlnVerbose("RM:", ctx.tmpDir)
		}()
	}

	err = buildTestBinaries(ctx)
	if err != nil {
		return ctx.results, fmt.Errorf("buildTestBinaries: %w", err)
	}

	err = genVMRunScript(ctx)
	if err != nil {
		return ctx.results, fmt.Errorf("genVMRunScript: %w", err)
	}

	err = buildVMDiskImg(ctx)
	if err != nil {
		return ctx.results, fmt.Errorf("buildVMDiskImg: %w", err)
	}

	err = downloadLinux(ctx)
	if err != nil {
		return ctx.results, fmt.Errorf("downloadLinux: %w", err)
	}

	err = runTestInVM(ctx)
	if err != nil {
		return ctx.results, fmt.Errorf("runTestInVM: %w", err)
	}

	err = extractData(ctx)
	if err != nil {
		return ctx.results, fmt.Errorf("extractData: %w", err)
	}

	err = processResults(ctx)
	if err != nil {
		return ctx.results, fmt.Errorf("processResults: %w", err)
	}

	return ctx.results, nil
}

func buildTestBinaries(ctx *testCtx) error {
	printlnVerbose("--- Build test binaries ---")

	envVars := append(
		os.Environ(),              // Append to existing ENV vars
		"GOARCH="+ctx.curEnv.arch, // Set target architecture
		"CGO_ENABLED=0",           // Disable CGO (to trigger static compilation)
	)

	buildFlags := []string{
		"test",              // invoke the test sub-command
		"-c",                // Compile the binary, but don't execute it
		"-tags", "bpftests", // Include tests that use the BPF syscall
	}

	// Include cover mode when building, because according to `go help testflag` coverage reporting annotates
	// the test binary.
	if flagCover {
		buildFlags = append(buildFlags, "-covermode", flagCoverMode)
		buildFlags = append(buildFlags, "-coverpkg", strings.Join(packages, ","))
	}

	if flagRun != "" {
		buildFlags = append(buildFlags, "-run", flagRun)
	}

	ctx.executables = make([]string, 0, len(packages))
	for _, pkg := range packages {
		pkgName := strings.Join([]string{path.Base(pkg), "test"}, ".")
		execPath := path.Join(ctx.tmpDir, pkgName)

		arguments := append(
			buildFlags,
			"-o", execPath, // Output test in the temporary directory
			pkg,
		)

		_, err := execEnvCmd(envVars, "go", arguments...)
		if err != nil {
			return fmt.Errorf("error while building tests: %w", err)
		}

		// If a package contains no tests, no executable is generated
		if _, err := os.Stat(execPath); err == nil {
			ctx.executables = append(ctx.executables, pkgName)
		}
	}

	return nil
}

func genVMRunScript(ctx *testCtx) error {
	printlnVerbose("--- Generate VM run script ---")

	// Make a buffer for the actual script which will execute the tests inside the VM
	scriptBuf := bytes.Buffer{}
	scriptBuf.WriteString("#!/bin/sh\n\n")

	// The the location where the disk will be mounted in the VM
	const vmPath = "/mnt/root"
	for _, execName := range ctx.executables {
		flags := []string{
			// Always return verbose output, it contains info about which tests actually ran or were skipped
			"-test.v",
		}

		if flagCover {
			flags = append(flags, "-test.coverprofile", path.Join(vmPath, execName+".cover"))
		}

		if flagFailFast {
			flags = append(flags, "-test.failfast")
		}

		if flagShort {
			flags = append(flags, "-test.short")
		}

		if flagRun != "" {
			flags = append(flags, "-test.run", flagRun)
		}

		// Run script, write stdout to "$exec.results", write stderr to "$exec.error" and the exit code to "$exec.exit"
		fmt.Fprintf(
			&scriptBuf,
			"%s %s > %s 2> %s\necho $? > %s\n",
			path.Join(vmPath, execName),
			strings.Join(flags, " "),
			path.Join(vmPath, execName+".results"),
			path.Join(vmPath, execName+".error"),
			path.Join(vmPath, execName+".exit"),
		)
	}

	// The last command is the poweroff command(busybox shutdown command), this will cause the VM to exit
	// after all tests have been ran.
	fmt.Fprintln(&scriptBuf, "poweroff -f")

	// Write the shell script
	printlnVerbose(scriptBuf.String())

	//nolint:gosec // Creating an executable on purpose
	err := os.WriteFile(path.Join(ctx.tmpDir, "run.sh"), scriptBuf.Bytes(), 0755)
	if err != nil {
		return fmt.Errorf("error while writing run script: %w", err)
	}

	return nil
}

const mntPath = "/mnt/bpftestdisk"

func buildVMDiskImg(ctx *testCtx) error {
	printlnVerbose("--- Build VM disk image ---")

	ctx.diskPath = path.Join(ctx.tmpDir, "disk.img")
	// Create a 256MB(should be plenty) raw disk which we will later use to add the test executables to the VM
	// and later get back the test results
	_, err := execCmd("qemu-img", "create", ctx.diskPath, "256M")
	if err != nil {
		return fmt.Errorf("error while creating qemu image: %w", err)
	}

	// Add master boot record partition table to raw image
	_, err = execCmd(
		"parted",
		"-s", ctx.diskPath,
		"mklabel msdos",
		"mkpart primary ext2 2048s 100%",
	)
	if err != nil {
		return fmt.Errorf("error while creating qemu image: %w", err)
	}

	// Create a loop device from the disk file which will allow us to mount it
	loopDevBytes, err := execCmd("losetup", "--partscan", "--show", "--find", ctx.diskPath)
	if err != nil {
		return fmt.Errorf("error while creating loop device: %w", err)
	}
	loopDev := strings.TrimSpace(string(loopDevBytes))

	printlnVerbose("MKDIR: ", mntPath)
	err = os.Mkdir(mntPath, 0755)
	if err != nil && err != fs.ErrExist {
		return fmt.Errorf("error while making mnt dir: %w", err)
	}
	defer func() {
		// Remove the mount path
		printlnVerbose("RM:", mntPath)
		err = os.Remove(mntPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while deleting mount dir '%s': %s", mntPath, err.Error())
		}
	}()

	// Make a EXT2 filesystem on the loop device's 1st partition
	_, err = execCmd("mkfs", "-t", "ext2", "-L", "bpfdisk", loopDev+"p1")
	if err != nil {
		return fmt.Errorf("error while creating FS on loop device: %w", err)
	}

	// Mount the first partion of the loop device
	_, err = execCmd("mount", loopDev+"p1", mntPath)
	if err != nil {
		return fmt.Errorf("error while mounting loop device: %w", err)
	}

	// Copy all executables and the run script to the new disk
	copyFiles := append(ctx.executables, "run.sh")
	for _, fileName := range copyFiles {
		tmpPath := path.Join(ctx.tmpDir, fileName)
		mntPath := path.Join(mntPath, fileName)

		err = copyFile(tmpPath, mntPath)
		if err != nil {
			return err
		}
	}

	// Unmount the loop device
	_, err = execCmd("umount", mntPath)
	if err != nil {
		return fmt.Errorf("error while unmounting loop device: %w", err)
	}

	// Remove the loop device
	_, err = execCmd("losetup", "-d", loopDev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while deleting loop device '%s': %s", loopDev, err.Error())
	}

	return nil
}

func downloadLinux(ctx *testCtx) error {
	printlnVerbose("--- Checking/downloading bzImage and initrd ---")

	const cacheDir = "/var/cache/bpfld"
	printlnVerbose("MKDIR", cacheDir)
	err := os.MkdirAll(cacheDir, 0755)
	if err != nil {
		return fmt.Errorf("error while creating cache directory: %w", err)
	}

	bzFilename := fmt.Sprintf("%s-%s.bzImage", ctx.curEnv.arch, ctx.curEnv.kernel)
	ctx.bzPath = path.Join(cacheDir, bzFilename)
	dlBZ := false

	printlnVerbose("CHECKSUM:", ctx.bzPath)
	bzFile, err := os.Open(ctx.bzPath)
	if err != nil {
		dlBZ = true
	} else {
		// Calculate the sha256 hash of the existing bzImage
		h := sha256.New()

		_, err = io.Copy(h, bzFile)
		if err != nil {
			return fmt.Errorf("error while hashing bzImage: %w", err)
		}
		bzFile.Close()

		bzHash := h.Sum(nil)

		printlnVerbose("GET: ", ctx.curEnv.bzImageURL+".sha256")
		resp, err := http.Get(ctx.curEnv.bzImageURL + ".sha256")
		if err != nil {
			return fmt.Errorf("error while downloading bzImage hash: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error while reading bzImage hash: %w", err)
		}

		bodyStr := strings.TrimSpace(string(body))
		if bodyStr != hex.EncodeToString(bzHash) {
			printlnVerbose(
				"Remote =", bodyStr+",",
				"Local =", hex.EncodeToString(bzHash),
			)
			dlBZ = true
		}
	}

	// If we can't stat the bzImage in the cache dir, download it
	if dlBZ {
		err = func() error {
			printlnVerbose("DOWNLOAD: ", ctx.curEnv.bzImageURL)
			resp, err := http.Get(ctx.curEnv.bzImageURL)
			if err != nil {
				return fmt.Errorf("error while downloading bzImage: %w", err)
			}
			defer resp.Body.Close()

			bzFile, err = os.OpenFile(ctx.bzPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("error while creating bzImage: %w", err)
			}
			defer bzFile.Close()

			_, err = io.Copy(bzFile, resp.Body)
			if err != nil {
				return fmt.Errorf("error while copying bzImage: %w", err)
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	const initrdURL = "https://github.com/dylandreimerink/bpfci/raw/master/dist/initrd.gz"
	ctx.initrdPath = path.Join(cacheDir, "initrd.gz")
	dlInitrd := false

	printlnVerbose("CHECKSUM:", ctx.initrdPath)
	initrdFile, err := os.Open(ctx.initrdPath)
	if err != nil {
		dlInitrd = true
	} else {
		// Calculate the sha256 hash of the existing bzImage
		h := sha256.New()

		_, err = io.Copy(h, initrdFile)
		if err != nil {
			return fmt.Errorf("error while hashing initrd: %w", err)
		}
		bzFile.Close()

		initrdHash := h.Sum(nil)

		printlnVerbose("GET: ", initrdURL+".sha256")
		resp, err := http.Get(initrdURL + ".sha256")
		if err != nil {
			return fmt.Errorf("error while downloading initrd hash: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error while reading initrd hash: %w", err)
		}

		bodyStr := strings.TrimSpace(string(body))
		if bodyStr != hex.EncodeToString(initrdHash) {
			printlnVerbose(
				"Remote =", bodyStr+",",
				"Local =", hex.EncodeToString(initrdHash),
			)
			dlInitrd = true
		}
	}

	if dlInitrd {
		err = func() error {
			printlnVerbose("DOWNLOAD: ", initrdURL)
			resp, err := http.Get(initrdURL)
			if err != nil {
				return fmt.Errorf("error while downloading initrd: %w", err)
			}
			defer resp.Body.Close()

			initrdFile, err = os.OpenFile(ctx.initrdPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("error while creating initrd: %w", err)
			}
			defer initrdFile.Close()

			_, err = io.Copy(initrdFile, resp.Body)
			if err != nil {
				return fmt.Errorf("error while copying initrd: %w", err)
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	return nil
}

func runTestInVM(ctx *testCtx) error {
	// TODO setup bridge and tap devices
	printlnVerbose("--- Starting test run in VM ---")

	arguments := []string{
		"-m", "4G", // Give the VM 4GB RAM, should be plenty
		"-kernel", ctx.bzPath, // Start kernel for the given environment
		"-initrd", ctx.initrdPath, // Use this initial ram disk (which will call our run.sh after setup)
		"-drive", "format=raw,file=" + ctx.diskPath, // Use the created disk as a drive
		"-netdev", "tap,id=bpfnet0,ifname=bpfci-tap1,script=no,downscript=no",
		"-device", "e1000,mac=de:ad:be:ef:00:01,netdev=bpfnet0", // Add a E1000 NIC
		"-append", "root=/dev/sda1",
		// TODO run with no-graphics and capture kernel output
	}
	_, err := execCmd("qemu-system-x86_64", arguments...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while starting VM: %s", err.Error())
	}

	return nil
}

func extractData(ctx *testCtx) error {
	printlnVerbose("--- Remounting disk ---")

	// Create a loop device from the disk file which will allow us to mount it
	loopDevBytes, err := execCmd("losetup", "--partscan", "--show", "--find", ctx.diskPath)
	if err != nil {
		return fmt.Errorf("error while creating loop device: %w", err)
	}
	loopDev := strings.TrimSpace(string(loopDevBytes))
	defer func() {
		// Remove the loop device
		_, err = execCmd("losetup", "-d", loopDev)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while deleting loop device '%s': %s", loopDev, err.Error())
		}
	}()

	printlnVerbose("MKDIR: ", mntPath)
	err = os.Mkdir(mntPath, 0755)
	if err != nil && err != fs.ErrExist {
		return fmt.Errorf("error while making mnt dir: %w", err)
	}
	defer func() {
		// Remove the mount path
		printlnVerbose("RM:", mntPath)
		err = os.Remove(mntPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while deleting mount dir '%s': %s", mntPath, err.Error())
		}
	}()

	// Mount the first partion of the loop device
	_, err = execCmd("mount", loopDev+"p1", mntPath)
	if err != nil {
		return fmt.Errorf("error while mounting loop device: %w", err)
	}
	defer func() {
		// Unmount the loop device
		_, err = execCmd("umount", mntPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while unmounting loop device: %s", err.Error())
		}
	}()

	copyFiles := []string{}
	for _, execName := range ctx.executables {
		copyFiles = append(copyFiles, execName+".results")
		copyFiles = append(copyFiles, execName+".error")
		copyFiles = append(copyFiles, execName+".exit")

		if flagCover {
			copyFiles = append(copyFiles, execName+".cover")
		}
	}

	for _, fileName := range copyFiles {
		err = copyFile(path.Join(mntPath, fileName), path.Join(ctx.tmpDir, fileName))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error while copying:", err.Error())
		}
	}

	// Merge all .cover files
	if flagCover {
		var merged []*cover.Profile
		for _, execName := range ctx.executables {
			profiles, err := cover.ParseProfiles(path.Join(ctx.tmpDir, execName+".cover"))
			if err != nil {
				fmt.Fprintln(os.Stderr, "failed to parse profiles:", err.Error())
				continue
			}
			for _, p := range profiles {
				merged = gocovmerge.AddProfile(merged, p)
			}
		}

		coverPath := path.Join(ctx.tmpDir, "gobpfld.cover")
		coverFile, err := os.Create(path.Join(ctx.tmpDir, "gobpfld.cover"))
		if err != nil {
			return fmt.Errorf("make combined coverfile: %w", err)
		}

		gocovmerge.DumpProfiles(merged, coverFile)

		err = coverFile.Close()
		if err != nil {
			return fmt.Errorf("close combined coverfile: %w", err)
		}

		if flagHTMLReport {
			err = tarp.GenerateHTMLReport([]string{coverPath}, path.Join(ctx.tmpDir, "gobpfld.cover.html"))
			if err != nil {
				return fmt.Errorf("make html coverage report: %w", err)
			}
		}
	}

	copyFiles = []string{}
	if flagCover {
		copyFiles = append(copyFiles, "gobpfld.cover")
		if flagHTMLReport {
			copyFiles = append(copyFiles, "gobpfld.cover.html")
		}
	}

	// If there are no output files
	if len(copyFiles) == 0 {
		return nil
	}

	outDir := path.Join(flagOutputDir, ctx.envName)

	printlnVerbose("STAT:", outDir)
	// If the directory exists, remove it
	if _, err = os.Stat(outDir); err == nil {
		printlnVerbose("RM:", outDir)
		os.RemoveAll(outDir)
	}

	printlnVerbose("MKDIR:", outDir)
	err = os.MkdirAll(outDir, 0755)
	if err != nil {
		return fmt.Errorf("make output dir: %w", err)
	}

	for _, fileName := range copyFiles {
		err = copyFile(path.Join(ctx.tmpDir, fileName), path.Join(outDir, fileName))
		if err != nil {
			return err
		}
	}

	return nil
}

func processResults(ctx *testCtx) error {
	printlnVerbose("--- Processing results ---")

	exitWithErr := false

	for _, execName := range ctx.executables {
		exitPath := path.Join(ctx.tmpDir, execName+".exit")
		errCodeBytes, err := os.ReadFile(exitPath)
		if err != nil {
			return fmt.Errorf("read exit code file '%s': %w", exitPath, err)
		}

		exitCode, err := strconv.Atoi(strings.TrimSpace(string(errCodeBytes)))
		if err != nil {
			return fmt.Errorf("exit code file atoi '%s': %w", exitPath, err)
		}

		resultPath := path.Join(ctx.tmpDir, execName+".results")
		testResults, err := os.ReadFile(resultPath)
		if err != nil {
			return fmt.Errorf("read results file '%s': %w", resultPath, err)
		}

		// Get back the package name from the executable name
		pkg := strings.TrimSuffix(execName, ".test")

		// If error code == 0, the executable returned without errors
		if exitCode != 0 {
			printlnVerbose(fmt.Sprintf("%s FAIL\nTests exited with code '%d'", pkg, exitCode))
			exitWithErr = true

			errorPath := path.Join(ctx.tmpDir, execName+".error")
			testError, err := os.ReadFile(errorPath)
			if err != nil {
				return fmt.Errorf("read error file '%s': %w", errorPath, err)
			}

			fmt.Printf("Stdout:\n%s\n", string(testResults))
			fmt.Printf("Stderr:\n%s\n", string(testError))
		}

		for _, line := range strings.Split(string(testResults), "\n") {
			const (
				passPrefix = "--- PASS:"
				failPrefix = "--- FAIL:"
				skipPrefix = "--- SKIP:"
			)

			var status testStatus

			if strings.HasPrefix(line, passPrefix) {
				line = strings.TrimSpace(strings.TrimPrefix(line, passPrefix))
				status = statusPass
			} else if strings.HasPrefix(line, failPrefix) {
				line = strings.TrimSpace(strings.TrimPrefix(line, failPrefix))
				status = statusFail
			} else if strings.HasPrefix(line, skipPrefix) {
				line = strings.TrimSpace(strings.TrimPrefix(line, skipPrefix))
				status = statusSkip
			} else {
				continue
			}

			parts := strings.Split(line, " ")
			if len(parts) < 2 {
				fmt.Fprintln(os.Stderr, "unexpected test results(parts < 2)")
				continue
			}

			testName := parts[0]
			durationStr := strings.Trim(parts[1], "()")
			duration, err := time.ParseDuration(durationStr)
			if err != nil {
				fmt.Fprintln(os.Stderr, "unexpected test results:", err.Error())
				continue
			}

			ctx.results[testName] = testResult{
				Name:     testName,
				Status:   status,
				Duration: duration,
			}
		}
	}

	if exitWithErr {
		return errTestsFailed
	}

	return nil
}

type testStatus string

const (
	// has not (yet) been run
	statusUntested testStatus = "UNTESTED"
	// tested and passed
	statusPass testStatus = "PASS"
	// tested and failed
	statusFail testStatus = "FAIL"
	// skipped testing, due to -short flag or kernel incompatibility
	statusSkip testStatus = "SKIP"
)

type testResult struct {
	Name     string
	Status   testStatus
	Duration time.Duration
	// TODO return sub-test data?
}

func copyFile(from, to string) error {
	printlnVerbose("CP:", from, "->", to)
	fromFile, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("error while opening file: %w", err)
	}

	toFile, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("error while creating file: %w", err)
	}

	_, err = io.Copy(toFile, fromFile)
	if err != nil {
		return fmt.Errorf("error while copying file: %w", err)
	}

	err = toFile.Close()
	if err != nil {
		return fmt.Errorf("error while closing file: %w", err)
	}

	err = fromFile.Close()
	if err != nil {
		return fmt.Errorf("error while closing file: %w", err)
	}

	return nil
}

func execCmd(name string, args ...string) ([]byte, error) {
	return execEnvCmd(nil, name, args...)
}

func execEnvCmd(env []string, name string, args ...string) ([]byte, error) {
	// we have to do this bullshit because you can't explode a ...string to a ...interface{}
	// so we have to joint into as single string which can be passed to a ...interface{}
	printlnVerbose(strings.Join(append([]string{"EXEC:", name}, args...), " "))

	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, string(output))
		if ee, ok := err.(*exec.ExitError); ok {
			fmt.Fprintln(os.Stderr, string(ee.Stderr))
		}
		return nil, err
	}

	return output, nil
}

// elevate checks if we are currently running as root, if not we will request the user to elevate the program
func elevate() error {
	curUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("error while getting user: %w", err)
	}

	// If we are user 0(root), we don't need to elevate
	if curUser.Uid == "0" {
		return nil
	}

	fmt.Println("This testsuit requires root privileges, attempting to elevate via sudo...")

	// TODO: this does make the assumption sudo always lives at /usr/bin/sudo, we should search the PATH env var instead
	// but could not find functionality in stdlib or a quick library to do this.

	// Elevate to root by execve'ing sudo with the current args. This should prompt the user for their sudo password
	// and then continue executing this program(again from the start, since this process will be replaced)
	// NOTE: The `--preserve-env=PATH` will make sure that the current PATH is preserved which is important since most
	// users will not have setup root with the correct go environment variables.
	err = unix.Exec("/usr/bin/sudo", append([]string{"sudo", "--preserve-env=PATH"}, os.Args...), os.Environ())
	if err != nil {
		return fmt.Errorf("error execve'ing into sudo: %w", err)
	}

	return nil
}
