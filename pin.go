package gobpfld

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/internal/cstr"
)

// BPFSysPath is the path to the bpf FS used to pin objects to
const BPFSysPath = "/sys/fs/bpf/"

// PinFD pins an eBPF object(map, program, link) identified by the given `fd` to the given `relativePath`
// relative to the `BPFSysPath` on the BPF FS.
//
// This function is exposed so custom program or map implementations can use outside of this library.
// However, it is recommendd to use the BPFProgram.Pin and AbstractMap.Pin functions if gobpfld types are used.
func PinFD(relativePath string, fd bpfsys.BPFfd) error {
	sysPath := fmt.Sprint(BPFSysPath, relativePath)

	// Create directories if any are missing
	err := os.MkdirAll(path.Dir(sysPath), 0644)
	if err != nil {
		return fmt.Errorf("error while making directories: %w, make sure bpffs is mounted at '%s'", err, BPFSysPath)
	}

	cPath := cstr.StringToCStrBytes(sysPath)

	err = bpfsys.ObjectPin(&bpfsys.BPFAttrObj{
		BPFfd:    fd,
		Pathname: uintptr(unsafe.Pointer(&cPath[0])),
	})
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}

// UnpinFD gets the fd of an eBPF object(map, program, link) which is pinned at the given `relativePath`
// relative to the `BPFSysPath` on the BPF FS.
// If `deletePin` is true, this function will remove the pin from the BPF FS after successfully getting it.
//
// This function is exposed so custom program or map implementations can use outside of this library.
// However, it is recommend to use the BPFProgram.Unpin and AbstractMap.Unpin functions if gobpfld types are used.
//
// TODO make this function unexported and create an UnpinMap and UnpinProgram function which will automatically recreate
//  the proper maps. (also necessary to handle map registration properly)
func UnpinFD(relativePath string, deletePin bool) (bpfsys.BPFfd, error) {
	sysPath := fmt.Sprint(BPFSysPath, relativePath)
	cpath := cstr.StringToCStrBytes(sysPath)

	fd, err := bpfsys.ObjectGet(&bpfsys.BPFAttrObj{
		Pathname: uintptr(unsafe.Pointer(&cpath[0])),
	})
	if err != nil {
		return fd, fmt.Errorf("bpf obj get syscall error: %w", err)
	}

	if deletePin {
		err = os.Remove(sysPath)
		if err != nil {
			return fd, fmt.Errorf("error while deleting pin: %w", err)
		}

		// Get the directories in the relative path
		dirs := path.Dir(relativePath)
		if dirs == "." || dirs == "/" {
			dirs = ""
		}

		// get array of dirs
		relDirs := strings.Split(dirs, string(os.PathSeparator))
		// If there is at least one directory
		if relDirs[0] != "" {
			// Loop over all directories
			for _, dir := range relDirs {
				dirPath := fmt.Sprint(BPFSysPath, dir)
				files, err := ioutil.ReadDir(dirPath)
				if err != nil {
					return fd, fmt.Errorf("error while reading dir: %w", err)
				}

				// If the dir is empty, remove it
				if len(files) == 0 {
					err = os.Remove(dirPath)
					if err != nil {
						return fd, fmt.Errorf("error while deleting empty dir: %w", err)
					}
				}
			}
		}
	}

	return fd, nil
}
