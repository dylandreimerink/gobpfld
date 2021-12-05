package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func main() {
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
	flagVerbose   bool
	flagCover     bool
	flagCoverMode string
	flagRun       string
	flagTestEnvs  []string
	flagKeepTmp   bool
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
	f.BoolVar(&flagCover, "cover", false, "Enable coverage analysis")
	f.StringVar(&flagCoverMode, "covermode", "set", "Set the mode for coverage analysis for the package[s]"+
		" being tested. The default is \"set\" unless -race is enabled, in which case it is \"atomic\".")
	f.StringVar(&flagRun, "run", "", "Run only those tests and examples matching the regular expression."+
		"For tests, the regular expression is split by unbracketed slash (/) "+
		"characters into a sequence of regular expressions, and each part "+
		"of a test's identifier must match the corresponding element in "+
		"the sequence, if any. Note that possible parents of matches are "+
		"run too, so that -run=X/Y matches and runs and reports the result "+
		"of all tests matching X, even those without sub-tests matching Y, "+
		"because it must run them to look for those sub-tests.")
	f.StringArrayVar(&flagTestEnvs, "test-env", nil, "If set, tests will only be ran in the given environments")
	f.BoolVar(&flagKeepTmp, "keep-tmp", false, "If set, the temporary directories will not be deleted after the test"+
		"run so intermediate files can be inspected")
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
	"github.com/dylandreimerink/gobpfld/cmd/testsuite",
}

func printlnVerbose(args ...interface{}) {
	if !flagVerbose {
		return
	}

	fmt.Println(args...)
}

// testEnv represents a combination of factors to test for
type testEnv struct {
	arch   string
	kernel string
}

var availableEnvs = map[string]testEnv{
	"linux-5.15.5-amd64": {
		arch:   "amd64",
		kernel: "5.15.5",
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

	buildFlags := []string{
		"test",              // invoke the test sub-command
		"-c",                // Compile the binary, but don't execute it
		"-tags", "bpftests", // Include tests that use the BPF syscall
	}

	if flagVerbose {
		buildFlags = append(buildFlags, "-v")
	}

	if flagCover {
		buildFlags = append(buildFlags, "-cover")
	}

	if flagCoverMode != "" {
		buildFlags = append(buildFlags, "-covermode", flagCoverMode)
	}

	if flagRun != "" {
		buildFlags = append(buildFlags, "-run", flagRun)
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

	for _, curEnvName := range environments {
		err := testEnvironment(curEnvName, buildFlags)
		if err != nil {
			return err
		}
	}

	return nil
}

func testEnvironment(envName string, buildFlags []string) error {
	curEnv := availableEnvs[envName]

	printlnVerbose("=== Running tests for", envName, "===")

	// example: /tmp/bpftestsuite-amd64-1099045701
	tmpDir, err := os.MkdirTemp(os.TempDir(), strings.Join([]string{"bpftestsuite", curEnv.arch, "*"}, "-"))
	if err != nil {
		return fmt.Errorf("error while making a temporary directory: %w", err)
	}

	printlnVerbose("Using tempdir:", tmpDir)

	// cleanup the temp dir after we are done, unless the user wan't to keep it
	if !flagKeepTmp {
		defer func() {
			printlnVerbose("--- Cleaning up tmp dir ---")
			err := os.RemoveAll(tmpDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while cleaning up tmp dir '%s': %s", tmpDir, err.Error())
			}
			printlnVerbose("RM:", tmpDir)
		}()
	}

	envVars := append(
		os.Environ(),          // Append to existing ENV vars
		"GOARCH="+curEnv.arch, // Set target architecture
		"CGO_ENABLED=0",       // Disable CGO (to trigger static compilation)
	)

	printlnVerbose("--- Build test binaries ---")

	executables := make([]string, 0, len(packages))
	for _, pkg := range packages {
		pkgName := strings.Join([]string{path.Base(pkg), "test"}, ".")
		execPath := path.Join(tmpDir, pkgName)

		arguments := append(
			buildFlags,
			"-o", execPath, // Output test in the temporary directory
			pkg,
		)

		_, err = execEnvCmd(envVars, "go", arguments...)
		if err != nil {
			return fmt.Errorf("error while building tests: %w", err)
		}

		// If a package contains no tests, no executable is generated
		if _, err := os.Stat(execPath); err == nil {
			executables = append(executables, pkgName)
		}
	}

	// Make a buffer for the actual script which will execute the tests inside the VM
	scriptBuf := bytes.Buffer{}
	scriptBuf.WriteString("#!/bin/sh\n\n")

	// The the location where the disk will be mounted in the VM
	const vmPath = "/mnt/root"
	for _, execName := range executables {
		flags := make([]string, 0)

		// TODO generate runtime flags

		fmt.Fprintf(
			&scriptBuf,
			"%s %s > %s\n",
			path.Join(vmPath, execName),
			strings.Join(flags, ", "),
			path.Join(vmPath, execName+".results"),
		)
	}

	// The last command is the poweroff command(busybox shutdown command), this will cause the VM to exit
	// after all tests have been ran.
	fmt.Fprintln(&scriptBuf, "poweroff -f")

	// Write the shell script
	printlnVerbose("--- Generate VM run script ---")
	printlnVerbose(scriptBuf.String())
	err = os.WriteFile(path.Join(tmpDir, "run.sh"), scriptBuf.Bytes(), 0755)
	if err != nil {
		return fmt.Errorf("error while writing run script: %w", err)
	}

	printlnVerbose("--- Build VM disk image ---")

	diskPath := path.Join(tmpDir, "disk.img")
	// Create a 256MB(should be plenty) raw disk which we will later use to add the test executables to the VM
	// and later get back the test results
	_, err = execCmd("qemu-img", "create", diskPath, "256M")
	if err != nil {
		return fmt.Errorf("error while creating qemu image: %w", err)
	}

	// Add master boot record partition table to raw image
	_, err = execCmd(
		"parted",
		"-s", diskPath,
		"mklabel msdos",
		"mkpart primary ext2 2048s 100%",
	)
	if err != nil {
		return fmt.Errorf("error while creating qemu image: %w", err)
	}

	// Create a loop device from the disk file which will allow us to mount it
	loopDevBytes, err := execCmd("losetup", "--partscan", "--show", "--find", diskPath)
	if err != nil {
		return fmt.Errorf("error while creating loop device: %w", err)
	}
	loopDev := strings.TrimSpace(string(loopDevBytes))

	const mntPath = "/mnt/bpftestdisk"

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
	copyFiles := append(executables, "run.sh")
	for _, fileName := range copyFiles {
		tmpPath := path.Join(tmpDir, fileName)
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

	// TODO download kernelBz and initrd from bpfci project for the current environment
	// TODO setup bridge and tap devices

	printlnVerbose("--- Starting test run in VM ---")

	arguments := []string{
		"-m", "4G", // Give the VM 4GB RAM, should be plenty
		"-kernel", "bzImage", // Start kernel for the given environment
		"-initrd", "initrd.gz", // Use this initial ram disk (which will call our run.sh after setup)
		"-drive", "format=raw,file=" + diskPath, // Use the created disk as a drive
		"-netdev", "tap,id=bpfnet0,ifname=bpfci-tap1,script=no,downscript=no",
		"-device", "e1000,mac=de:ad:be:ef:00:01,netdev=bpfnet0", // Add a E1000 NIC
		"-append", "root=/dev/sda1",
		// TODO run with no-graphics and capture kernel output
	}
	_, err = execCmd("qemu-system-x86_64", arguments...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while starting VM: %s", err.Error())
	}

	printlnVerbose("--- Remounting disk ---")

	// Create a loop device from the disk file which will allow us to mount it
	loopDevBytes, err = execCmd("losetup", "--partscan", "--show", "--find", diskPath)
	if err != nil {
		return fmt.Errorf("error while creating loop device: %w", err)
	}
	loopDev = strings.TrimSpace(string(loopDevBytes))
	defer func() {
		// Remove the loop device
		_, err = execCmd("losetup", "-d", loopDev)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while deleting loop device '%s': %s", loopDev, err.Error())
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

	printlnVerbose("--- Processing results ---")

	copyFiles = []string{}
	for _, execName := range executables {
		copyFiles = append(copyFiles, execName+".results")

		// TODO add files depending on flags
	}

	// TODO move results to in memory zip file for this environment, instead of tmp dir
	for _, fileName := range copyFiles {
		err = copyFile(path.Join(mntPath, fileName), path.Join(tmpDir, fileName))
		if err != nil {
			return err
		}
	}

	// TODO give user feedback based on results

	return nil
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
