package bpftypes

import (
	"strings"
	"unsafe"
)

const (
	// BPF_OBJ_NAME_LEN the max length of an object name as defined by the linux kernel
	// The actual size of the string is 16 bytes, but the last byte must always be 0x00
	BPF_OBJ_NAME_LEN = 16
)

// BPFCommand is a enum which describes a number of different commands which can be sent to the kernel
// via the bpf syscall.
// From bpf_cmd https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L96
type BPFCommand int

const (
	// BPF_MAP_CREATE creates a new map
	BPF_MAP_CREATE BPFCommand = iota
	// BPF_MAP_LOOKUP_ELEM looks up the value stored in a map for a given key
	BPF_MAP_LOOKUP_ELEM
	// BPF_MAP_UPDATE_ELEM changes the value in a map for a given key
	BPF_MAP_UPDATE_ELEM
	// BPF_MAP_DELETE_ELEM deletes a key and value form a map
	BPF_MAP_DELETE_ELEM
	// BPF_MAP_GET_NEXT_KEY is used to iterate over all keys in a map one key at a time
	BPF_MAP_GET_NEXT_KEY
	// BPF_PROG_LOAD loads a program into the kernel
	BPF_PROG_LOAD
	// BPF_OBJ_PIN pins a eBPF object(map, program, BTF, link) to the bpf filesystem
	BPF_OBJ_PIN
	// BPF_OBJ_GET gets a file descriptor for a pinned object
	BPF_OBJ_GET
	// BPF_PROG_ATTACH attaches certain program types to a specified location
	BPF_PROG_ATTACH
	// BPF_PROG_DETACH detaches certain program types from their attached locations
	BPF_PROG_DETACH
	// BPF_PROG_TEST_RUN test a loaded program without attaching it
	BPF_PROG_TEST_RUN
	// BPF_PROG_GET_NEXT_ID is used to iterate over loaded programs
	BPF_PROG_GET_NEXT_ID
	// BPF_MAP_GET_NEXT_ID is used to iterate over loaded maps
	BPF_MAP_GET_NEXT_ID
	// BPF_PROG_GET_FD_BY_ID returns a file descriptor of a loaded program by its ID
	BPF_PROG_GET_FD_BY_ID
	// BPF_MAP_GET_FD_BY_ID returns a file descriptor of a loaded map by its ID
	BPF_MAP_GET_FD_BY_ID
	// BPF_OBJ_GET_INFO_BY_FD returns info about loaded eBPF objects by their file descriptor
	BPF_OBJ_GET_INFO_BY_FD
	// BPF_PROG_QUERY is used to query program information in relation to cgroups
	// https://patchwork.ozlabs.org/project/netdev/patch/20171002234857.3707580-3-ast@fb.com/
	BPF_PROG_QUERY
	// BPF_RAW_TRACEPOINT_OPEN is used to attach a raw tracepoint program to a tracepoint
	// https://patchwork.ozlabs.org/project/netdev/cover/20180328190540.370956-1-ast@kernel.org/
	BPF_RAW_TRACEPOINT_OPEN
	// BPF_BTF_LOAD is used to load BTF(debug symbols) into the kernel
	BPF_BTF_LOAD
	// BPF_BTF_GET_FD_BY_ID is used to get a file descriptor for a loaded BTF object by ID
	BPF_BTF_GET_FD_BY_ID
	// BPF_TASK_FD_QUERY us used to get information about the attachment point of tracing programs by their fd
	// https://patchwork.ozlabs.org/project/netdev/patch/20180524001844.1175727-3-yhs@fb.com/
	BPF_TASK_FD_QUERY
	// BPF_MAP_LOOKUP_AND_DELETE_ELEM get the value of a key in a map and deletes it at the same time
	// like in pop operations of a stack or queue
	BPF_MAP_LOOKUP_AND_DELETE_ELEM
	// BPF_MAP_FREEZE freezes a map so its contents can't be changed anymore
	BPF_MAP_FREEZE
	// BPF_BTF_GET_NEXT_ID is used to iterate over loaded BTF objects
	BPF_BTF_GET_NEXT_ID
	// BPF_MAP_LOOKUP_BATCH is used to lookup a batch of keys/values in one syscall
	BPF_MAP_LOOKUP_BATCH
	// BPF_MAP_LOOKUP_AND_DELETE_BATCH is used to dequeue/pop a batch of values in one syscall
	BPF_MAP_LOOKUP_AND_DELETE_BATCH
	// BPF_MAP_UPDATE_BATCH is used to update a batch of values in one syscall
	BPF_MAP_UPDATE_BATCH
	// BPF_MAP_DELETE_BATCH is used to delete a btach of keys/values in one syscall
	BPF_MAP_DELETE_BATCH
	// BPF_LINK_CREATE is yet another way to attach bpf programs, a link links a program
	// to an attachment point and generates its own file descriptor which with to manage
	// the link in the future.
	// https://patchwork.ozlabs.org/project/netdev/patch/20200427201240.2994985-1-yhs@fb.com/
	BPF_LINK_CREATE
	// BPF_LINK_UPDATE is used to update the program of a link
	BPF_LINK_UPDATE
	// BPF_LINK_GET_FD_BY_ID is used to get a file descriptor of a link by its id
	BPF_LINK_GET_FD_BY_ID
	// BPF_LINK_GET_NEXT_ID is used to iterate over all links
	BPF_LINK_GET_NEXT_ID
	// BPF_ENABLE_STATS is used to enable/disable eBPF statistics collection by the kernel
	BPF_ENABLE_STATS
	// BPF_ITER_CREATE creates a kernel data iterator (custom /proc)
	BPF_ITER_CREATE
	// BPF_LINK_DETACH is used to detach a link
	BPF_LINK_DETACH
	// BPF_PROG_BIND_MAP binds a map to a program even when the program doesn't use that map.
	BPF_PROG_BIND_MAP
)

var bpfCommandToStr = map[BPFCommand]string{
	BPF_MAP_CREATE:                  "BPF_MAP_CREATE",
	BPF_MAP_LOOKUP_ELEM:             "BPF_MAP_LOOKUP_ELEM",
	BPF_MAP_UPDATE_ELEM:             "BPF_MAP_UPDATE_ELEM",
	BPF_MAP_DELETE_ELEM:             "BPF_MAP_DELETE_ELEM",
	BPF_MAP_GET_NEXT_KEY:            "BPF_MAP_GET_NEXT_KEY",
	BPF_PROG_LOAD:                   "BPF_PROG_LOAD",
	BPF_OBJ_PIN:                     "BPF_OBJ_PIN",
	BPF_OBJ_GET:                     "BPF_OBJ_GET",
	BPF_PROG_ATTACH:                 "BPF_PROG_ATTACH",
	BPF_PROG_DETACH:                 "BPF_PROG_DETACH",
	BPF_PROG_TEST_RUN:               "BPF_PROG_TEST_RUN",
	BPF_PROG_GET_NEXT_ID:            "BPF_PROG_GET_NEXT_ID",
	BPF_MAP_GET_NEXT_ID:             "BPF_MAP_GET_NEXT_ID",
	BPF_PROG_GET_FD_BY_ID:           "BPF_PROG_GET_FD_BY_ID",
	BPF_MAP_GET_FD_BY_ID:            "BPF_MAP_GET_FD_BY_ID",
	BPF_OBJ_GET_INFO_BY_FD:          "BPF_OBJ_GET_INFO_BY_FD",
	BPF_PROG_QUERY:                  "BPF_PROG_QUERY",
	BPF_RAW_TRACEPOINT_OPEN:         "BPF_RAW_TRACEPOINT_OPEN",
	BPF_BTF_LOAD:                    "BPF_BTF_LOAD",
	BPF_BTF_GET_FD_BY_ID:            "BPF_BTF_GET_FD_BY_ID",
	BPF_TASK_FD_QUERY:               "BPF_TASK_FD_QUERY",
	BPF_MAP_LOOKUP_AND_DELETE_ELEM:  "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
	BPF_MAP_FREEZE:                  "BPF_MAP_FREEZE",
	BPF_BTF_GET_NEXT_ID:             "BPF_BTF_GET_NEXT_ID",
	BPF_MAP_LOOKUP_BATCH:            "BPF_MAP_LOOKUP_BATCH",
	BPF_MAP_LOOKUP_AND_DELETE_BATCH: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
	BPF_MAP_UPDATE_BATCH:            "BPF_MAP_UPDATE_BATCH",
	BPF_MAP_DELETE_BATCH:            "BPF_MAP_DELETE_BATCH",
	BPF_LINK_CREATE:                 "BPF_LINK_CREATE",
	BPF_LINK_UPDATE:                 "BPF_LINK_UPDATE",
	BPF_LINK_GET_FD_BY_ID:           "BPF_LINK_GET_FD_BY_ID",
	BPF_LINK_GET_NEXT_ID:            "BPF_LINK_GET_NEXT_ID",
	BPF_ENABLE_STATS:                "BPF_ENABLE_STATS",
	BPF_ITER_CREATE:                 "BPF_ITER_CREATE",
	BPF_LINK_DETACH:                 "BPF_LINK_DETACH",
	BPF_PROG_BIND_MAP:               "BPF_PROG_BIND_MAP",
}

func (cmd BPFCommand) String() string {
	str := bpfCommandToStr[cmd]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// BPFMapType is an enum type which describes a type of map
// From bpf_map_type https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L136
//
// There are generic map types which allow a user to use any key and value type they wish (within limits) and
// specialized map types which typically have only one or a few purposes, must have specific keys or values, and/or
// can only be used in conjunction with specific helper functions.
type BPFMapType uint32

const (
	// BPF_MAP_TYPE_UNSPEC is a invalid map type with the numeric value of 0, so map types are always unspecified
	// if not initialized.
	BPF_MAP_TYPE_UNSPEC BPFMapType = iota
	// BPF_MAP_TYPE_HASH is a generic map type which has no key or value memory layout restrictions. Memory for
	// this map is not pre-allocated unless requested with an additional flag. The value of the key is hashed
	// and looked up in a hashmap.
	BPF_MAP_TYPE_HASH
	// BPF_MAP_TYPE_ARRAY is a generic map type which has no key or value memory layout restrictions. Memory for
	// this map is pre-allocated in a contiguous memory region. The value of key is interpreted as an offset aka
	// index.
	BPF_MAP_TYPE_ARRAY
	// BPF_MAP_TYPE_PROG_ARRAY is a specialized map type which is used in conjunction with the bpf_tail_call
	// helper function to "tail call" into another eBPF program.
	// The key of this map is an array index (0 to 'max_entries').
	// The value of this map is a eBPF program file descriptor gotten from the bpf syscall
	BPF_MAP_TYPE_PROG_ARRAY
	// BPF_MAP_TYPE_PERF_EVENT_ARRAY is a specialized map type that is used in conjunction with the
	// bpf_perf_event_read, bpf_perf_event_output, bpf_perf_event_read_value, bpf_skb_output, or bpf_xdp_output
	// helper functions. This allows eBPF programs to generate events in the 'perf' linux profiler which can be
	// read by a userspace program. The key is an array inex (0 to 'max_entires')
	// The value is a file descriptor returned by the perf_event_open syscall
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	// BPF_MAP_TYPE_PERCPU_HASH is a generic map type which has no key or value memory layout restrictions.
	// It is similar to the BPF_MAP_TYPE_HASH map type, however, for every logical CPU a separate map is created
	// and maintained. A eBPF program can only interact with the version of the map allocated to the CPU it is
	// running on.The advantage of this scheme is that no race conditions can ever occur so no locking is required and
	// no CPUcaches have to be kept in sync, this makes it very fast. The downside is that since every CPU has a unique
	// copy the memory usage is multiplied by the CPU core count of the machine (trading of speed for memory usage).
	//
	// When interacting with this map from the syscall/userspace side all values for every version of the map is
	// returned at once as an array. This may seem confusing since the buffer size in userspace needs to be way larger
	// than the value size in the map definition indicates. Getting a u8 values from a per cpu map on a 16 logical CPU
	// core machine takes 16 bytes. The returned array is indexed by CPU number.
	BPF_MAP_TYPE_PERCPU_HASH
	// BPF_MAP_TYPE_PERCPU_ARRAY is a generic map type which has no key or value memory layout restrictions.
	// It works the same as the BPF_MAP_TYPE_PERCPU_HASH map except it has been pre-allocated and the key is
	// interpreted as an array index so from 0 to 'max_entires'
	BPF_MAP_TYPE_PERCPU_ARRAY
	// BPF_MAP_TYPE_STACK_TRACE is a specialized map type which is used to store a stacktrace which can be accessed
	// by eBPF programs to to tracing or make metrics.
	//
	// TODO figure out the key and value types of this maps. The kernel samples seem to suggest this map is
	// automatically when a program is called and has to be cleaned by a userspace application which also has
	// a chance to access the trace.
	BPF_MAP_TYPE_STACK_TRACE
	// BPF_MAP_TYPE_CGROUP_ARRAY is a specialized map type that is used in conjunction with the bpf_skb_under_cgroup
	// or bpf_current_task_under_cgroup helper functions. It can be used to check if the eBPF program is running in
	// the context of a specific cgroup.
	// The key is an array index (0 to 'max_entries').
	// The value is a cgroup file descriptor.
	BPF_MAP_TYPE_CGROUP_ARRAY
	// BPF_MAP_TYPE_LRU_HASH is a generic map type which has no key or value memory layout restrictions. It is
	// similar to the BPF_MAP_TYPE_HASH type with one exception. When the map is full and a value is written to it
	// the least recently used element of the map is replaced with the new element.
	// This is useful for use cases like caches or statistics where losing data is not the end of the world.
	BPF_MAP_TYPE_LRU_HASH
	// BPF_MAP_TYPE_LRU_PERCPU_HASH is a generic map type which has no key or value memory layout restrictions.
	// It is the per cpu variant of the BPF_MAP_TYPE_LRU_HASH map type and combines both features.
	// Please look at the description of the BPF_MAP_TYPE_PERCPU_HASH type for the per cpu features and
	// the BPF_MAP_TYPE_LRU_HASH map type for lru features
	BPF_MAP_TYPE_LRU_PERCPU_HASH
	// BPF_MAP_TYPE_LPM_TRIE is a specialized map type which uses longest prefix matching when looking up elements
	// in the map. This is mainly useful for IP range lookups where more specific IP prefixes take precedence over
	// less specific IP prefixes.
	// The key must start with a unsigned 32 bit integer which denotes the amount of bits to consider followed by
	// a user determined number of bytes containing the actual data to be matches.
	// The value type is arbitrary.
	BPF_MAP_TYPE_LPM_TRIE
	// BPF_MAP_TYPE_ARRAY_OF_MAPS is a specialized map type that refers to other maps.
	// The key of this map type is an array index(0 to 'max_entires').
	// The value of this map type is a pointer to another map.
	BPF_MAP_TYPE_ARRAY_OF_MAPS
	// BPF_MAP_TYPE_HASH_OF_MAPS is a specialized map type that refers to other maps.
	// The key of this map type is hashed and can my any type.
	// The value of this map is a pointer to another map.
	BPF_MAP_TYPE_HASH_OF_MAPS
	// BPF_MAP_TYPE_DEVMAP is a specialized map type that is used in conjunction with the bpf_redirect_map
	// helper function to redirect a XDP frame to a specific network device which sends it out of its associated
	// port. This allows us to implement driver level switching.
	// The key of a devmap is an array index (0 to 'max_entries')
	// The value of a devmap must follow the bpf_devmap_val memory layout
	// https://elixir.bootlin.com/linux/v5.11.15/source/include/uapi/linux/bpf.h#L4390
	BPF_MAP_TYPE_DEVMAP
	// BPF_MAP_TYPE_SOCKMAP is a specialized map type that is used in conjunction with the bpf_sk_redirect_map or
	// bpf_msg_redirect_map map helper functions to redirect packets to sockets.
	// The key of a sockmap is an array index (0 to 'max_entries')
	// The value of a sockmap is a file descriptor to a socket, returned by the socket(2) syscall
	BPF_MAP_TYPE_SOCKMAP
	// BPF_MAP_TYPE_CPUMAP is a specialized map type that is used in conjunction with the bpf_redirect_map
	// helper function to redirect a XDP frame to a specific CPU for further processing by the kernel
	// network stack. This essentially allows an XDP to do RPS(Receive Packet Steering).
	// Example: https://github.com/torvalds/linux/blob/master/samples/bpf/xdp_redirect_cpu_kern.c
	// The key of a cpumap is an array index (0 to 'max_entries')
	// The value of a cpumap must follow the bpf_cpumap_val memory layout
	// https://elixir.bootlin.com/linux/v5.11.15/source/include/uapi/linux/bpf.h#L4403
	BPF_MAP_TYPE_CPUMAP
	// BPF_MAP_TYPE_XSKMAP is a specialized map type that is used in conjunction with the bpf_redirect_map
	// helper function to pass a XDP frame to a AF_XDP socket thus bypassing the kernel network stack.
	// Using AF_XDP is complicated and requires a lot of setup from the loader.
	// https://github.com/torvalds/linux/blob/master/Documentation/networking/af_xdp.rst
	BPF_MAP_TYPE_XSKMAP
	// BPF_MAP_TYPE_SOCKHASH is a specialized map type that is used in conjunction with the bpf_sk_redirect_hash
	// and bpf_msg_redirect_hash helper function to redirect packets to sockets. It is almost identical to
	// BPF_MAP_TYPE_SOCKMAP but is implemented with a hashmap instead of an array.
	BPF_MAP_TYPE_SOCKHASH
	// BPF_MAP_TYPE_CGROUP_STORAGE is a specialized map type that is used in conjunction with the bpf_get_local_storage
	// helper function. This map is used to store arbitrary data in a memory area linked to the cgroup.
	// The key of the map is the cgroup_inode_id(uint64) or bpf_cgroup_storage_key.
	// The value of the map is arbitrary.
	// https://github.com/torvalds/linux/blob/master/Documentation/bpf/map_cgroup_storage.rst
	BPF_MAP_TYPE_CGROUP_STORAGE
	// BPF_MAP_TYPE_REUSEPORT_SOCKARRAY is a specialized map type that is used in conjunction with the
	// sk_select_reuseport helper function to redirect a packet to a specific socket which is bound to the a port
	// using the SO_REUSEPORT socket option. The SO_REUSEPORT socket option allows multiple sockets to listen on
	// the same port which are typically placed on different threads, this scheme can improve performance.
	// https://lwn.net/Articles/542629/.
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	// BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE is the per cpu version of BPF_MAP_TYPE_CGROUP_STORAGE.
	// https://github.com/torvalds/linux/blob/master/Documentation/bpf/map_cgroup_storage.rst
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	// BPF_MAP_TYPE_QUEUE is a specialized map type that is used in conjunction with the bpf_map_push_elem,
	// bpf_map_pop_elem, and bpf_map_peek_elem helper functions. This map type implements a LIFO/FIFO queue
	// which does not allow for arbitrary access and does not use keys.
	// The value of the map is arbitrary.
	BPF_MAP_TYPE_QUEUE
	// BPF_MAP_TYPE_STACK is a specialized map type that is used in conjunction with the bpf_map_push_elem,
	// bpf_map_pop_elem, and bpf_map_peek_elem helper functions. This map type implements a stack
	// which does not allow for arbitrary access and does not use keys.
	// The value of the map is arbitrary.
	BPF_MAP_TYPE_STACK
	// BPF_MAP_TYPE_SK_STORAGE is a specialized map type that is used in conjunction with the bpf_sk_storage_get
	// helper function. This map allows a program to attach stored data to a socket. This has the advantage
	// of not having to manage this memory since it will be freed when the socket closes.
	// The key of the map is not used since a program can only access data for the socket on which
	// it was triggered.
	// The value type is arbitrary.
	BPF_MAP_TYPE_SK_STORAGE
	// BPF_MAP_TYPE_DEVMAP_HASH is a specialized map type that is used in conjunction with the bpf_redirect_map
	// helper function. It it almost the same as the BPF_MAP_TYPE_DEVMAP type except the key is hashed so
	// non-contiguous keys can be used without wasting memory.
	BPF_MAP_TYPE_DEVMAP_HASH
	// BPF_MAP_TYPE_STRUCT_OPS is used in BPF_PROG_TYPE_STRUCT_OPS programs.
	// TODO figure out how BPF_PROG_TYPE_STRUCT_OPS programs work and how the map should be used
	BPF_MAP_TYPE_STRUCT_OPS
	// BPF_MAP_TYPE_RINGBUF is a specialized map type that is used in conjunction with the bpf_ringbuf_output,
	// bpf_ringbuf_reserve, bpf_ringbuf_submit, bpf_ringbuf_discard, and bpf_ringbuf_query helper function.
	// https://github.com/torvalds/linux/blob/master/Documentation/bpf/ringbuf.rst
	BPF_MAP_TYPE_RINGBUF
	// BPF_MAP_TYPE_INODE_STORAGE is a specialized map type that is used in conjunction with the bpf_inode_storage_get
	// and bpf_inode_storage_delete helper functions. This can be used to attach data to a inode. This is especially
	// useful for eBPF programs that deal with files like LSM programs. When the inode is deleted, the associated data
	// is also deleted.
	BPF_MAP_TYPE_INODE_STORAGE
	// BPF_MAP_TYPE_TASK_STORAGE is a specialized map type that is used in conjunction with the bpf_task_storage_get
	// and bpf_task_storage_delete helper functions. This can be used to attach data to a task.
	// When the task ends, the data is deleted.
	BPF_MAP_TYPE_TASK_STORAGE
)

var bpfMapTypeToStr = map[BPFMapType]string{
	BPF_MAP_TYPE_UNSPEC:                "BPF_MAP_TYPE_UNSPEC",
	BPF_MAP_TYPE_HASH:                  "BPF_MAP_TYPE_HASH",
	BPF_MAP_TYPE_ARRAY:                 "BPF_MAP_TYPE_ARRAY",
	BPF_MAP_TYPE_PROG_ARRAY:            "BPF_MAP_TYPE_PROG_ARRAY",
	BPF_MAP_TYPE_PERF_EVENT_ARRAY:      "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
	BPF_MAP_TYPE_PERCPU_HASH:           "BPF_MAP_TYPE_PERCPU_HASH",
	BPF_MAP_TYPE_PERCPU_ARRAY:          "BPF_MAP_TYPE_PERCPU_ARRAY",
	BPF_MAP_TYPE_STACK_TRACE:           "BPF_MAP_TYPE_STACK_TRACE",
	BPF_MAP_TYPE_CGROUP_ARRAY:          "BPF_MAP_TYPE_CGROUP_ARRAY",
	BPF_MAP_TYPE_LRU_HASH:              "BPF_MAP_TYPE_LRU_HASH",
	BPF_MAP_TYPE_LRU_PERCPU_HASH:       "BPF_MAP_TYPE_LRU_PERCPU_HASH",
	BPF_MAP_TYPE_LPM_TRIE:              "BPF_MAP_TYPE_LPM_TRIE",
	BPF_MAP_TYPE_ARRAY_OF_MAPS:         "BPF_MAP_TYPE_ARRAY_OF_MAPS",
	BPF_MAP_TYPE_HASH_OF_MAPS:          "BPF_MAP_TYPE_HASH_OF_MAPS",
	BPF_MAP_TYPE_DEVMAP:                "BPF_MAP_TYPE_DEVMAP",
	BPF_MAP_TYPE_SOCKMAP:               "BPF_MAP_TYPE_SOCKMAP",
	BPF_MAP_TYPE_CPUMAP:                "BPF_MAP_TYPE_CPUMAP",
	BPF_MAP_TYPE_XSKMAP:                "BPF_MAP_TYPE_XSKMAP",
	BPF_MAP_TYPE_SOCKHASH:              "BPF_MAP_TYPE_SOCKHASH",
	BPF_MAP_TYPE_CGROUP_STORAGE:        "BPF_MAP_TYPE_CGROUP_STORAGE",
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:   "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
	BPF_MAP_TYPE_QUEUE:                 "BPF_MAP_TYPE_QUEUE",
	BPF_MAP_TYPE_STACK:                 "BPF_MAP_TYPE_STACK",
	BPF_MAP_TYPE_SK_STORAGE:            "BPF_MAP_TYPE_SK_STORAGE",
	BPF_MAP_TYPE_DEVMAP_HASH:           "BPF_MAP_TYPE_DEVMAP_HASH",
	BPF_MAP_TYPE_STRUCT_OPS:            "BPF_MAP_TYPE_STRUCT_OPS",
	BPF_MAP_TYPE_RINGBUF:               "BPF_MAP_TYPE_RINGBUF",
	BPF_MAP_TYPE_INODE_STORAGE:         "BPF_MAP_TYPE_INODE_STORAGE",
	BPF_MAP_TYPE_TASK_STORAGE:          "BPF_MAP_TYPE_TASK_STORAGE",
}

func (mt BPFMapType) String() string {
	str := bpfMapTypeToStr[mt]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// BPFProgType describes what kind of eBPF program we are dealing with. The type of program will restrict
// where it can be attached, which attributes go into the program, what helper functions can be executed
// in the program, and what the meaning of the return value is.
type BPFProgType uint32

//nolint:revive // not every program type is known to me yet, until then ignore missing comments
const (
	// BPF_PROG_TYPE_UNSPEC is the default/zero value and is invalid in most cases
	BPF_PROG_TYPE_UNSPEC BPFProgType = iota
	// BPF_PROG_TYPE_SOCKET_FILTER program type can be attached to a socket using the SO_ATTACH_BPF
	// option via the setsockopt syscall. The program is called for inbound packet and can be used to filter,
	// trim, and modify packets. The program is given a pointer to __sk_buff and should return the amount of
	// bytes of the packet to keep, all remaining bytes will be trimmed. A return value of 0 means drop.
	BPF_PROG_TYPE_SOCKET_FILTER
	// BPF_PROG_TYPE_KPROBE program type can be attached to kprobes and uprobes.
	// The main purpose of this is to collect information and/or to debug the kernel. The program is executed
	// every time the breakpoint it is attached to is hit while that breakpoint is enabled.
	// You can find more info about kprobes here: https://lwn.net/Articles/132196/
	BPF_PROG_TYPE_KPROBE
	// BPF_PROG_TYPE_SCHED_CLS program type can be attached to tc(traffic control) and acts as a traffic
	// classifier. For more details on this program type check out the tc-bpf manpage
	// https://man7.org/linux/man-pages/man8/tc-bpf.8.html
	BPF_PROG_TYPE_SCHED_CLS
	// BPF_PROG_TYPE_SCHED_ACT program type can be attached to tc(traffic control) and can tell tc to perform
	// a certain action on. For more details on this program type check out the tc-bpf manpage
	// https://man7.org/linux/man-pages/man8/tc-bpf.8.html
	BPF_PROG_TYPE_SCHED_ACT
	// BPF_PROG_TYPE_TRACEPOINT program type can be attached to kernel tracepoints. Tracepoints are predefined
	// places in the kernel which are interesting to monitor. The program is called every time the kernel executes
	// code with a enabled tracepoint to which the eBPF program is attached.
	// You can read more about this program type here: https://lwn.net/Articles/683504/
	BPF_PROG_TYPE_TRACEPOINT
	// BPF_PROG_TYPE_XDP program type can be attached to network interfaces. A XDP program is triggered for every
	// incoming data frame that is received on the network interface the program is attached to. The program is
	// typically called from a network driver as soon as possible, before the kernel network stack.
	// XDP programs can modify, redirect, or pass frames which can be used for very high performance network programs.
	BPF_PROG_TYPE_XDP
	// BPF_PROG_TYPE_PERF_EVENT program type can be attached to perf events. The program is triggered for every perf
	// event it is attached to within a given scope. It is mainly used for collecting information and monitoring.
	// You can read more about perf and perf_events here: http://www.brendangregg.com/perf.html
	BPF_PROG_TYPE_PERF_EVENT
	// BPF_PROG_TYPE_CGROUP_SKB program type can be attached to cgroups and is triggered on IP ingress/egress.
	// The program can then allow or deny the ip packet to pass thus restricting network access for programs running
	// in that cgroup programmatically.
	BPF_PROG_TYPE_CGROUP_SKB
	// BPF_PROG_TYPE_CGROUP_SOCK program type can be attached to cgroups and is triggered when a new socket is
	// requested. The program can then allow or deny for example a program in a cgroup from listening on a specific
	// network port.
	BPF_PROG_TYPE_CGROUP_SOCK
	// BPF_PROG_TYPE_LWT_IN program type can be attached to specific network routes. The program is called for every
	// incoming packet to that route to decapsulate it. This allows a eBPF program to implement a tunneling
	// protocol which is not supported by default by linux or to dynamically change its behavior using maps.
	BPF_PROG_TYPE_LWT_IN
	BPF_PROG_TYPE_LWT_OUT
	BPF_PROG_TYPE_LWT_XMIT
	// BPF_PROG_TYPE_SOCK_OPS program type can be attached to cgroups and is triggered on a number of socket
	// operations like TCP connection state changes, connection timeout, and new listening sockets.
	// This program type can change the options of the socket with the bpf_setsockopt helper function,
	// for example to change MTU or buffer sizes of the socket.
	BPF_PROG_TYPE_SOCK_OPS
	BPF_PROG_TYPE_SK_SKB
	BPF_PROG_TYPE_CGROUP_DEVICE
	BPF_PROG_TYPE_SK_MSG
	BPF_PROG_TYPE_RAW_TRACEPOINT
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	BPF_PROG_TYPE_LWT_SEG6LOCAL
	BPF_PROG_TYPE_LIRC_MODE2
	BPF_PROG_TYPE_SK_REUSEPORT
	BPF_PROG_TYPE_FLOW_DISSECTOR
	BPF_PROG_TYPE_CGROUP_SYSCTL
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
	BPF_PROG_TYPE_CGROUP_SOCKOPT
	BPF_PROG_TYPE_TRACING
	BPF_PROG_TYPE_STRUCT_OPS
	BPF_PROG_TYPE_EXT
	BPF_PROG_TYPE_LSM
	BPF_PROG_TYPE_SK_LOOKUP
)

var bpfProgTypeToStr = map[BPFProgType]string{
	BPF_PROG_TYPE_UNSPEC:                  "BPF_PROG_TYPE_UNSPEC",
	BPF_PROG_TYPE_SOCKET_FILTER:           "BPF_PROG_TYPE_SOCKET_FILTER",
	BPF_PROG_TYPE_KPROBE:                  "BPF_PROG_TYPE_KPROBE",
	BPF_PROG_TYPE_SCHED_CLS:               "BPF_PROG_TYPE_SCHED_CLS",
	BPF_PROG_TYPE_SCHED_ACT:               "BPF_PROG_TYPE_SCHED_ACT",
	BPF_PROG_TYPE_TRACEPOINT:              "BPF_PROG_TYPE_TRACEPOINT",
	BPF_PROG_TYPE_XDP:                     "BPF_PROG_TYPE_XDP",
	BPF_PROG_TYPE_PERF_EVENT:              "BPF_PROG_TYPE_PERF_EVENT",
	BPF_PROG_TYPE_CGROUP_SKB:              "BPF_PROG_TYPE_CGROUP_SKB",
	BPF_PROG_TYPE_CGROUP_SOCK:             "BPF_PROG_TYPE_CGROUP_SOCK",
	BPF_PROG_TYPE_LWT_IN:                  "BPF_PROG_TYPE_LWT_IN",
	BPF_PROG_TYPE_LWT_OUT:                 "BPF_PROG_TYPE_LWT_OUT",
	BPF_PROG_TYPE_LWT_XMIT:                "BPF_PROG_TYPE_LWT_XMIT",
	BPF_PROG_TYPE_SOCK_OPS:                "BPF_PROG_TYPE_SOCK_OPS",
	BPF_PROG_TYPE_SK_SKB:                  "BPF_PROG_TYPE_SK_SKB",
	BPF_PROG_TYPE_CGROUP_DEVICE:           "BPF_PROG_TYPE_CGROUP_DEVICE",
	BPF_PROG_TYPE_SK_MSG:                  "BPF_PROG_TYPE_SK_MSG",
	BPF_PROG_TYPE_RAW_TRACEPOINT:          "BPF_PROG_TYPE_RAW_TRACEPOINT",
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR:        "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
	BPF_PROG_TYPE_LWT_SEG6LOCAL:           "BPF_PROG_TYPE_LWT_SEG6LOCAL",
	BPF_PROG_TYPE_LIRC_MODE2:              "BPF_PROG_TYPE_LIRC_MODE2",
	BPF_PROG_TYPE_SK_REUSEPORT:            "BPF_PROG_TYPE_SK_REUSEPORT",
	BPF_PROG_TYPE_FLOW_DISSECTOR:          "BPF_PROG_TYPE_FLOW_DISSECTOR",
	BPF_PROG_TYPE_CGROUP_SYSCTL:           "BPF_PROG_TYPE_CGROUP_SYSCTL",
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
	BPF_PROG_TYPE_CGROUP_SOCKOPT:          "BPF_PROG_TYPE_CGROUP_SOCKOPT",
	BPF_PROG_TYPE_TRACING:                 "BPF_PROG_TYPE_TRACING",
	BPF_PROG_TYPE_STRUCT_OPS:              "BPF_PROG_TYPE_STRUCT_OPS",
	BPF_PROG_TYPE_EXT:                     "BPF_PROG_TYPE_EXT",
	BPF_PROG_TYPE_LSM:                     "BPF_PROG_TYPE_LSM",
	BPF_PROG_TYPE_SK_LOOKUP:               "BPF_PROG_TYPE_SK_LOOKUP",
}

func (pt BPFProgType) String() string {
	str := bpfProgTypeToStr[pt]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// BPFAttachType describes to what type of hook the eBPF program will attach to.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L211
type BPFAttachType uint32

//nolint:revive // I don't know the meaning of all of these consts yet
const (
	// BPF_CGROUP_INET_INGRESS is used to attach a BPF_PROG_TYPE_CGROUP_SKB program to the ingress IP traffic
	// of a cgroup
	BPF_CGROUP_INET_INGRESS BPFAttachType = iota
	// BPF_CGROUP_INET_EGRESS is used to attach a BPF_PROG_TYPE_CGROUP_SKB program to the egress IP traffic
	// of a cgroup
	BPF_CGROUP_INET_EGRESS
	// BPF_CGROUP_INET_SOCK_CREATE is used to attach a BPF_PROG_TYPE_CGROUP_SOCK program to the socket create
	// operation of a cgroup. Meaning the program will be called for every socket to be created.
	BPF_CGROUP_INET_SOCK_CREATE
	BPF_CGROUP_SOCK_OPS
	BPF_SK_SKB_STREAM_PARSER
	BPF_SK_SKB_STREAM_VERDICT
	BPF_CGROUP_DEVICE
	BPF_SK_MSG_VERDICT
	BPF_CGROUP_INET4_BIND
	BPF_CGROUP_INET6_BIND
	BPF_CGROUP_INET4_CONNECT
	BPF_CGROUP_INET6_CONNECT
	BPF_CGROUP_INET4_POST_BIND
	BPF_CGROUP_INET6_POST_BIND
	BPF_CGROUP_UDP4_SENDMSG
	BPF_CGROUP_UDP6_SENDMSG
	BPF_LIRC_MODE2
	BPF_FLOW_DISSECTOR
	BPF_CGROUP_SYSCTL
	BPF_CGROUP_UDP4_RECVMSG
	BPF_CGROUP_UDP6_RECVMSG
	BPF_CGROUP_GETSOCKOPT
	BPF_CGROUP_SETSOCKOPT
	BPF_TRACE_RAW_TP
	BPF_TRACE_FENTRY
	BPF_TRACE_FEXIT
	BPF_MODIFY_RETURN
	BPF_LSM_MAC
	BPF_TRACE_ITER
	BPF_CGROUP_INET4_GETPEERNAME
	BPF_CGROUP_INET6_GETPEERNAME
	BPF_CGROUP_INET4_GETSOCKNAME
	BPF_CGROUP_INET6_GETSOCKNAME
	// BPF_XDP_DEVMAP is set in the expectred attach type of a XDP program when it wants to use a BPF_XDP_DEVMAP.
	BPF_XDP_DEVMAP
	// BPF_CGROUP_INET_SOCK_RELEASE is used to attach a BPF_PROG_TYPE_CGROUP_SOCK program to the socket release
	// operation of a cgroup. Meaning the program will be called for every socket that is released.
	BPF_CGROUP_INET_SOCK_RELEASE
	// BPF_XDP_CPUMAP is set in the expectred attach type of a XDP program when it wants to use a BPF_MAP_TYPE_CPUMAP.
	BPF_XDP_CPUMAP
	BPF_SK_LOOKUP
	// BPF_XDP is used to attach a BPF_PROG_TYPE_XDP program using a link.
	BPF_XDP
)

var bpfAttachTypeToStr = map[BPFAttachType]string{
	BPF_CGROUP_INET_INGRESS:      "BPF_CGROUP_INET_INGRESS",
	BPF_CGROUP_INET_EGRESS:       "BPF_CGROUP_INET_EGRESS",
	BPF_CGROUP_INET_SOCK_CREATE:  "BPF_CGROUP_INET_SOCK_CREATE",
	BPF_CGROUP_SOCK_OPS:          "BPF_CGROUP_SOCK_OPS",
	BPF_SK_SKB_STREAM_PARSER:     "BPF_SK_SKB_STREAM_PARSER",
	BPF_SK_SKB_STREAM_VERDICT:    "BPF_SK_SKB_STREAM_VERDICT",
	BPF_CGROUP_DEVICE:            "BPF_CGROUP_DEVICE",
	BPF_SK_MSG_VERDICT:           "BPF_SK_MSG_VERDICT",
	BPF_CGROUP_INET4_BIND:        "BPF_CGROUP_INET4_BIND",
	BPF_CGROUP_INET6_BIND:        "BPF_CGROUP_INET6_BIND",
	BPF_CGROUP_INET4_CONNECT:     "BPF_CGROUP_INET4_CONNECT",
	BPF_CGROUP_INET6_CONNECT:     "BPF_CGROUP_INET6_CONNECT",
	BPF_CGROUP_INET4_POST_BIND:   "BPF_CGROUP_INET4_POST_BIND",
	BPF_CGROUP_INET6_POST_BIND:   "BPF_CGROUP_INET6_POST_BIND",
	BPF_CGROUP_UDP4_SENDMSG:      "BPF_CGROUP_UDP4_SENDMSG",
	BPF_CGROUP_UDP6_SENDMSG:      "BPF_CGROUP_UDP6_SENDMSG",
	BPF_LIRC_MODE2:               "BPF_LIRC_MODE2",
	BPF_FLOW_DISSECTOR:           "BPF_FLOW_DISSECTOR",
	BPF_CGROUP_SYSCTL:            "BPF_CGROUP_SYSCTL",
	BPF_CGROUP_UDP4_RECVMSG:      "BPF_CGROUP_UDP4_RECVMSG",
	BPF_CGROUP_UDP6_RECVMSG:      "BPF_CGROUP_UDP6_RECVMSG",
	BPF_CGROUP_GETSOCKOPT:        "BPF_CGROUP_GETSOCKOPT",
	BPF_CGROUP_SETSOCKOPT:        "BPF_CGROUP_SETSOCKOPT",
	BPF_TRACE_RAW_TP:             "BPF_TRACE_RAW_TP",
	BPF_TRACE_FENTRY:             "BPF_TRACE_FENTRY",
	BPF_TRACE_FEXIT:              "BPF_TRACE_FEXIT",
	BPF_MODIFY_RETURN:            "BPF_MODIFY_RETURN",
	BPF_LSM_MAC:                  "BPF_LSM_MAC",
	BPF_TRACE_ITER:               "BPF_TRACE_ITER",
	BPF_CGROUP_INET4_GETPEERNAME: "BPF_CGROUP_INET4_GETPEERNAME",
	BPF_CGROUP_INET6_GETPEERNAME: "BPF_CGROUP_INET6_GETPEERNAME",
	BPF_CGROUP_INET4_GETSOCKNAME: "BPF_CGROUP_INET4_GETSOCKNAME",
	BPF_CGROUP_INET6_GETSOCKNAME: "BPF_CGROUP_INET6_GETSOCKNAME",
	BPF_XDP_DEVMAP:               "BPF_XDP_DEVMAP",
	BPF_CGROUP_INET_SOCK_RELEASE: "BPF_CGROUP_INET_SOCK_RELEASE",
	BPF_XDP_CPUMAP:               "BPF_XDP_CPUMAP",
	BPF_SK_LOOKUP:                "BPF_SK_LOOKUP",
	BPF_XDP:                      "BPF_XDP",
}

func (at BPFAttachType) String() string {
	str := bpfAttachTypeToStr[at]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// BPFLinkType describes how a program should be link in attributes for the BPF_LINK_* commands
type BPFLinkType uint32

const (
	// BPF_LINK_TYPE_UNSPEC zero/default value which is invalid
	BPF_LINK_TYPE_UNSPEC BPFLinkType = iota
	// BPF_LINK_TYPE_RAW_TRACEPOINT a program should be attached to a raw tracepoint
	BPF_LINK_TYPE_RAW_TRACEPOINT
	// BPF_LINK_TYPE_TRACING a program should be attached as tracing program.
	// Can be a few program types like kprobe and LSM.
	BPF_LINK_TYPE_TRACING
	// BPF_LINK_TYPE_CGROUP a program should be attached to a cGroup
	BPF_LINK_TYPE_CGROUP
	// BPF_LINK_TYPE_ITER a program should be attached as a kernel structure iterator
	BPF_LINK_TYPE_ITER
	// BPF_LINK_TYPE_NETNS a program should be attached to a network namespace
	BPF_LINK_TYPE_NETNS
	// BPF_LINK_TYPE_XDP a program should be attached to a network device
	BPF_LINK_TYPE_XDP
)

var bpfLinkTypeToStr = map[BPFLinkType]string{
	BPF_LINK_TYPE_UNSPEC:         "BPF_LINK_TYPE_UNSPEC",
	BPF_LINK_TYPE_RAW_TRACEPOINT: "BPF_LINK_TYPE_RAW_TRACEPOINT",
	BPF_LINK_TYPE_TRACING:        "BPF_LINK_TYPE_TRACING",
	BPF_LINK_TYPE_CGROUP:         "BPF_LINK_TYPE_CGROUP",
	BPF_LINK_TYPE_ITER:           "BPF_LINK_TYPE_ITER",
	BPF_LINK_TYPE_NETNS:          "BPF_LINK_TYPE_NETNS",
	BPF_LINK_TYPE_XDP:            "BPF_LINK_TYPE_XDP",
}

func (lt BPFLinkType) String() string {
	str := bpfLinkTypeToStr[lt]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

type BPFTaskFDType uint32

//nolint:revive // i don't fully understand the meaning of these consts yet
const (
	BPF_FD_TYPE_RAW_TRACEPOINT BPFTaskFDType = iota
	BPF_FD_TYPE_TRACEPOINT
	BPF_FD_TYPE_KPROBE
	BPF_FD_TYPE_KRETPROBE
	BPF_FD_TYPE_UPROBE
	BPF_FD_TYPE_URETPROBE
)

var bpfTaskFDTypeToStr = map[BPFTaskFDType]string{
	BPF_FD_TYPE_RAW_TRACEPOINT: "BPF_FD_TYPE_RAW_TRACEPOINT",
	BPF_FD_TYPE_TRACEPOINT:     "BPF_FD_TYPE_TRACEPOINT",
	BPF_FD_TYPE_KPROBE:         "BPF_FD_TYPE_KPROBE",
	BPF_FD_TYPE_KRETPROBE:      "BPF_FD_TYPE_KRETPROBE",
	BPF_FD_TYPE_UPROBE:         "BPF_FD_TYPE_UPROBE",
	BPF_FD_TYPE_URETPROBE:      "BPF_FD_TYPE_URETPROBE",
}

func (ft BPFTaskFDType) String() string {
	str := bpfTaskFDTypeToStr[ft]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

/* BPFProgAttachFlags cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * With BPF_F_ALLOW_MULTI a new program is added to the end of the list of
 * programs for a cgroup. Though it's possible to replace an old program at
 * any position by also specifying BPF_F_REPLACE flag and position itself in
 * replace_bpf_fd attribute. Old program at this position will be released.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
type BPFProgAttachFlags uint32

const (
	// BPFProgAttachAllowOverride if a sub-cgroup installs some bpf program, the program in this cgroup yields
	// to sub-cgroup program.
	BPFProgAttachAllowOverride BPFProgAttachFlags = 1 << iota
	// BPFProgAttachAllowMulti If a sub-cgroup installs some bpf program,
	// that cgroup program gets run in addition to the program in this cgroup.
	BPFProgAttachAllowMulti
	// BPFProgAttachReplace with BPF_F_ALLOW_MULTI a new program is added to the end of the list of
	// programs for a cgroup. Though it's possible to replace an old program at
	// any position by also specifying BPF_F_REPLACE flag and position itself in
	// replace_bpf_fd attribute. Old program at this position will be released.
	BPFProgAttachReplace
)

// BPFLogLevel the verifier log level
// https://github.com/torvalds/linux/blob/master/include/linux/bpf_verifier.h#L360
type BPFLogLevel uint32

const (
	// BPFLogLevelDisabled disables the verifier log
	BPFLogLevelDisabled BPFLogLevel = iota
	// BPFLogLevelBasic instructs the verifier to output basic logs
	BPFLogLevelBasic
	// BPFLogLevelVerbose the most verbose log level available
	BPFLogLevelVerbose
)

type BPFProgLoadFlags uint32

const (
	/* BPFProgLoadStrictAlignment is used in BPF_PROG_LOAD command, the
	* verifier will perform strict alignment checking as if the kernel
	* has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
	* and NET_IP_ALIGN defined to 2.
	 */
	BPFProgLoadStrictAlignment BPFProgLoadFlags = 1 << iota

	/* BPFProgLoadAnyAlignment is used in BPF_PROF_LOAD command, the
	 * verifier will allow any alignment whatsoever.  On platforms
	 * with strict alignment requirements for loads ands stores (such
	 * as sparc and mips) the verifier validates that all loads and
	 * stores provably follow this requirement.  This flag turns that
	 * checking and enforcement off.
	 *
	 * It is mostly used for testing when we want to validate the
	 * context and memory access aspects of the verifier, but because
	 * of an unaligned access the alignment check would trigger before
	 * the one we are interested in.
	 */
	BPFProgLoadAnyAlignment

	/* BPFProgLoadTestRndHI32 is used in BPF_PROG_LOAD command for testing purpose.
	 * Verifier does sub-register def/use analysis and identifies instructions whose
	 * def only matters for low 32-bit, high 32-bit is never referenced later
	 * through implicit zero extension. Therefore verifier notifies JIT back-ends
	 * that it is safe to ignore clearing high 32-bit for these instructions. This
	 * saves some back-ends a lot of code-gen. However such optimization is not
	 * necessary on some arches, for example x86_64, arm64 etc, whose JIT back-ends
	 * hence hasn't used verifier's analysis result. But, we really want to have a
	 * way to be able to verify the correctness of the described optimization on
	 * x86_64 on which testsuites are frequently exercised.
	 *
	 * So, this flag is introduced. Once it is set, verifier will randomize high
	 * 32-bit for those instructions who has been identified as safe to ignore them.
	 * Then, if verifier is not doing correct analysis, such randomization will
	 * regress tests to expose bugs.
	 */
	BPFProgLoadTestRndHI32

	/* BPFProgLoadTestStateFreq is the verifier internal test flag. Behavior is undefined */
	BPFProgLoadTestStateFreq

	/* BPFProgLoadSleepable can be used in BPF_PROG_LOAD command, the verifier will
	 * restrict map and helper usage for such programs. Sleepable BPF programs can
	 * only be attached to hooks where kernel execution context allows sleeping.
	 * Such programs are allowed to use helpers that may sleep like
	 * bpf_copy_from_user().
	 */
	BPFProgLoadSleepable
)

const BPF_TAG_SIZE = 8

// BPFProgInfoSize is the size of BPFProgInfo in bytes
var BPFProgInfoSize = int(unsafe.Sizeof(BPFProgInfo{}))

// BPFProgInfo is the structure used by the kernel to communicate program information back to
// userspace when calling the BPF_OBJ_GET_INFO_BY_FD command with a program file descriptor. Based on
// https://github.com/torvalds/linux/blob/e49d033bddf5b565044e2abe4241353959bc9120/include/uapi/linux/bpf.h#L4548
type BPFProgInfo struct {
	Type                 BPFProgType
	ID                   uint32
	Tag                  [BPF_TAG_SIZE]byte
	JitedProgLen         uint32
	XlatedProgLen        uint32
	JitedProgInsns       uintptr
	XlatedProgInsns      uintptr
	LoadTime             uint64
	CreatedByUID         uint32
	NumMapIDs            uint32
	MapIDs               uintptr
	Name                 [BPF_OBJ_NAME_LEN]byte
	IfIndex              uint32
	Flags                BPFProgInfoFlags
	NetNSDev             uint64
	NetNSIno             uint64
	NumJitedKSyms        uint32
	NumJitedFuncLens     uint32
	JitedKsyms           uintptr
	JitedFuncLens        uintptr
	BTFID                uint32
	FuncInfoRecSize      uint32
	FuncInfo             uintptr
	NumFuncInfo          uint32
	NumLineInfo          uint32
	LineInfo             uintptr
	JitedLineInfo        uintptr
	NumJitedLineInfo     uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
	NumProgTags          uint32
	ProgTags             uintptr
	RunTimeNs            uint64
	RunCnt               uint64
	RecursionMisses      uint64
}

// BPFProgInfoFlags a alignment hole was used for additional flags, since the comment says
// this value may contain extra flags in the future this custom type was created.
// This will hopefully allow for more compatibility
// https://github.com/torvalds/linux/commit/b85fab0e67b162014cd328cb4e2a8e8ae382cb8a
type BPFProgInfoFlags uint32

const (
	// ProgInfoFlagGPLCompatible indicates that a program is GPL compatible
	ProgInfoFlagGPLCompatible BPFProgInfoFlags = 1 << iota
)

// BPFMapInfoSize is the size of the BPFMapInfo struct in bytes
var BPFMapInfoSize = int(unsafe.Sizeof(BPFMapInfo{}))

type BPFMapInfo struct {
	Type       BPFMapType
	ID         uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       [BPF_OBJ_NAME_LEN]byte
	IfIndex    uint32
	NetNSDev   uint64
	NetNSIno   uint64
}

type BPFFuncInfo struct {
	InstructionOffset uint32
	TypeID            uint32
}

type BPFLineInfo struct {
	InstructionOffset uint32
	FileNameOffset    uint32
	LineOffset        uint32
	ColumnOffset      uint32
}

type BPFMapFlags uint32

const (
	// BPFMapFlagsNoPreAlloc is a flag that signals that the memory for a map should not be allocated when it is
	// created but rather at runtime. NOTE this only works for non-array maps
	BPFMapFlagsNoPreAlloc BPFMapFlags = 1 << iota
	// BPFMapFlagsNoCommonLRU is a flag that signals that instead of having one common LRU list in the
	// BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list which can scale and perform better.
	// Note, the LRU nodes (including free nodes) cannot be moved across different LRU lists.
	BPFMapFlagsNoCommonLRU
	// BPFMapFlagsNUMANode is a flag that signals that a numa node may be specified during map creation
	BPFMapFlagsNUMANode
	// BPFMapFlagsReadOnly is a flag that signals that the userspace may not write to this map
	BPFMapFlagsReadOnly
	// BPFMapFlagsWriteOnly is a flag that signals that the userspace may not read from this map
	BPFMapFlagsWriteOnly
	// BPFMapFlagsStackBuildID is a flag for stack_map that signals to store build_id+offset instead of pointer
	BPFMapFlagsStackBuildID
	// BPFMapFlagsZeroSeed is a flag that signals to zero-initialize hash function seed.
	// This should only be used for testing.
	BPFMapFlagsZeroSeed
	// BPFMapFlagsReadOnlyProg is a flag that signals that the eBPF program may not write to this map
	BPFMapFlagsReadOnlyProg
	// BPFMapFlagsWriteOnlyProg is a flag that signals that the eBPF program may not write to this map
	BPFMapFlagsWriteOnlyProg
	// BPFMapFlagsClone is a flag that signals to clone the map from listener for newly accepted socket
	BPFMapFlagsClone
	// BPFMapFlagsMMapable is a flag that enables memory-mapping BPF map
	BPFMapFlagsMMapable
	// BPFMapFlagsPreserveElems is a flag that signals the kernel to share perf_event among processes
	BPFMapFlagsPreserveElems
	// BPFMapFlagsInnerMap  is a flag that signals the kernel to create a map that is suitable to be an inner map
	// with dynamic max entries
	BPFMapFlagsInnerMap
	// BPFMapFlagsMax is a pseudo flag used for iteration within the library and should not be used
	BPFMapFlagsMax
)

var mapDefFlagToStr = map[BPFMapFlags]string{
	BPFMapFlagsNoPreAlloc:    "BPFMapFlagsNoPreAlloc",
	BPFMapFlagsNoCommonLRU:   "BPFMapFlagsNoCommonLRU",
	BPFMapFlagsNUMANode:      "BPFMapFlagsNUMANode",
	BPFMapFlagsReadOnly:      "BPFMapFlagsReadOnly",
	BPFMapFlagsWriteOnly:     "BPFMapFlagsWriteOnly",
	BPFMapFlagsStackBuildID:  "BPFMapFlagsStackBuildID",
	BPFMapFlagsZeroSeed:      "BPFMapFlagsZeroSeed",
	BPFMapFlagsReadOnlyProg:  "BPFMapFlagsReadOnlyProg",
	BPFMapFlagsWriteOnlyProg: "BPFMapFlagsWriteOnlyProg",
	BPFMapFlagsClone:         "BPFMapFlagsClone",
	BPFMapFlagsMMapable:      "BPFMapFlagsMMapable",
	BPFMapFlagsPreserveElems: "BPFMapFlagsPreserveElems",
	BPFMapFlagsInnerMap:      "BPFMapFlagsInnerMap",
}

func (f BPFMapFlags) String() string {
	var flags []string

	for flag := BPFMapFlagsNoPreAlloc; flag < BPFMapFlagsInnerMap; flag = flag << 1 {
		if f&flag > 0 {
			flags = append(flags, mapDefFlagToStr[flag])
		}
	}

	return strings.Join(flags, "|")
}
