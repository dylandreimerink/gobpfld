package ebpf

import "fmt"

var _ Instruction = (*CallHelper)(nil)

type CallHelper struct {
	Function int32
}

func (c *CallHelper) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_CALL | BPF_JMP, Reg: NewReg(0, 0), Imm: c.Function},
	}, nil
}

func (c *CallHelper) String() string {
	return fmt.Sprintf("call %d#%s", c.Function, BPFHelperFuncNumToStr[c.Function])
}

// CallHelperIndirect is illegal in the linux kernel, but we have it here to support non-kernel eBPF implementation.
// This instruction is generated by clang when optimizations are disabled.
type CallHelperIndirect struct {
	Register Register
}

func (c *CallHelperIndirect) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_CALLX | BPF_JMP, Reg: NewReg(0, 0), Imm: int32(c.Register)},
	}, nil
}

func (c *CallHelperIndirect) String() string {
	return fmt.Sprintf("callx r%s", c.Register)
}

// BPFHelperFuncNumToStr is a translation tables from the helper function ids/numbers to their string form.
// These are based on https://github.com/libbpf/libbpf/blob/master/src/bpf_helper_defs.h
var BPFHelperFuncNumToStr = map[int32]string{
	1:   "bpf_map_lookup_elem",
	2:   "bpf_map_update_elem",
	3:   "bpf_map_delete_elem",
	4:   "bpf_probe_read",
	5:   "bpf_ktime_get_ns",
	6:   "bpf_trace_printk",
	7:   "bpf_get_prandom_u32",
	8:   "bpf_get_smp_processor_id",
	9:   "bpf_skb_store_bytes",
	10:  "bpf_l3_csum_replace",
	11:  "bpf_l4_csum_replace",
	12:  "bpf_tail_call",
	13:  "bpf_clone_redirect",
	14:  "bpf_get_current_pid_tgid",
	15:  "bpf_get_current_uid_gid",
	16:  "bpf_get_current_comm",
	17:  "bpf_get_cgroup_classid",
	18:  "bpf_skb_vlan_push",
	19:  "bpf_skb_vlan_pop",
	20:  "bpf_skb_get_tunnel_key",
	21:  "bpf_skb_set_tunnel_key",
	22:  "bpf_perf_event_read",
	23:  "bpf_redirect",
	24:  "bpf_get_route_realm",
	25:  "bpf_perf_event_output",
	26:  "bpf_skb_load_bytes",
	27:  "bpf_get_stackid",
	28:  "bpf_csum_diff",
	29:  "bpf_skb_get_tunnel_opt",
	30:  "bpf_skb_set_tunnel_opt",
	31:  "bpf_skb_change_proto",
	32:  "bpf_skb_change_type",
	33:  "bpf_skb_under_cgroup",
	34:  "bpf_get_hash_recalc",
	35:  "bpf_get_current_task",
	36:  "bpf_probe_write_user",
	37:  "bpf_current_task_under_cgroup",
	38:  "bpf_skb_change_tail",
	39:  "bpf_skb_pull_data",
	40:  "bpf_csum_update",
	41:  "bpf_set_hash_invalid",
	42:  "bpf_get_numa_node_id",
	43:  "bpf_skb_change_head",
	44:  "bpf_xdp_adjust_head",
	45:  "bpf_probe_read_str",
	46:  "bpf_get_socket_cookie",
	47:  "bpf_get_socket_uid",
	48:  "bpf_set_hash",
	49:  "bpf_setsockopt",
	50:  "bpf_skb_adjust_room",
	51:  "bpf_redirect_map",
	52:  "bpf_sk_redirect_map",
	53:  "bpf_sock_map_update",
	54:  "bpf_xdp_adjust_meta",
	55:  "bpf_perf_event_read_value",
	56:  "bpf_perf_prog_read_value",
	57:  "bpf_getsockopt",
	58:  "bpf_override_return",
	59:  "bpf_sock_ops_cb_flags_set",
	60:  "bpf_msg_redirect_map",
	61:  "bpf_msg_apply_bytes",
	62:  "bpf_msg_cork_bytes",
	63:  "bpf_msg_pull_data",
	64:  "bpf_bind",
	65:  "bpf_xdp_adjust_tail",
	66:  "bpf_skb_get_xfrm_state",
	67:  "bpf_get_stack",
	68:  "bpf_skb_load_bytes_relative",
	69:  "bpf_fib_lookup",
	70:  "bpf_sock_hash_update",
	71:  "bpf_msg_redirect_hash",
	72:  "bpf_sk_redirect_hash",
	73:  "bpf_lwt_push_encap",
	74:  "bpf_lwt_seg6_store_bytes",
	75:  "bpf_lwt_seg6_adjust_srh",
	76:  "bpf_lwt_seg6_action",
	77:  "bpf_rc_repeat",
	78:  "bpf_rc_keydown",
	79:  "bpf_skb_cgroup_id",
	80:  "bpf_get_current_cgroup_id",
	81:  "bpf_get_local_storage",
	82:  "bpf_sk_select_reuseport",
	83:  "bpf_skb_ancestor_cgroup_id",
	84:  "bpf_sk_lookup_tcp",
	85:  "bpf_sk_lookup_udp",
	86:  "bpf_sk_release",
	87:  "bpf_map_push_elem",
	88:  "bpf_map_pop_elem",
	89:  "bpf_map_peek_elem",
	90:  "bpf_msg_push_data",
	91:  "bpf_msg_pop_data",
	92:  "bpf_rc_pointer_rel",
	93:  "bpf_spin_lock",
	94:  "bpf_spin_unlock",
	95:  "bpf_sk_fullsock",
	96:  "bpf_tcp_sock",
	97:  "bpf_skb_ecn_set_ce",
	98:  "bpf_get_listener_sock",
	99:  "bpf_skc_lookup_tcp",
	100: "bpf_tcp_check_syncookie",
	101: "bpf_sysctl_get_name",
	102: "bpf_sysctl_get_current_value",
	103: "bpf_sysctl_get_new_value",
	104: "bpf_sysctl_set_new_value",
	105: "bpf_strtol",
	106: "bpf_strtoul",
	107: "bpf_sk_storage_get",
	108: "bpf_sk_storage_delete",
	109: "bpf_send_signal",
	110: "bpf_tcp_gen_syncookie",
	111: "bpf_skb_output",
	112: "bpf_probe_read_user",
	113: "bpf_probe_read_kernel",
	114: "bpf_probe_read_user_str",
	115: "bpf_probe_read_kernel_str",
	116: "bpf_tcp_send_ack",
	117: "bpf_send_signal_thread",
	118: "bpf_jiffies64",
	119: "bpf_read_branch_records",
	120: "bpf_get_ns_current_pid_tgid",
	121: "bpf_xdp_output",
	122: "bpf_get_netns_cookie",
	123: "bpf_get_current_ancestor_cgroup_id",
	124: "bpf_sk_assign",
	125: "bpf_ktime_get_boot_ns",
	126: "bpf_seq_printf",
	127: "bpf_seq_write",
	128: "bpf_sk_cgroup_id",
	129: "bpf_sk_ancestor_cgroup_id",
	130: "bpf_ringbuf_output",
	131: "bpf_ringbuf_reserve",
	132: "bpf_ringbuf_submit",
	133: "bpf_ringbuf_discard",
	134: "bpf_ringbuf_query",
	135: "bpf_csum_level",
	136: "bpf_skc_to_tcp6_sock",
	137: "bpf_skc_to_tcp_sock",
	138: "bpf_skc_to_tcp_timewait_sock",
	139: "bpf_skc_to_tcp_request_sock",
	140: "bpf_skc_to_udp6_sock",
	141: "bpf_get_task_stack",
	142: "bpf_load_hdr_opt",
	143: "bpf_store_hdr_opt",
	144: "bpf_reserve_hdr_opt",
	145: "bpf_inode_storage_get",
	146: "bpf_inode_storage_delete",
	147: "bpf_d_path",
	148: "bpf_copy_from_user",
	149: "bpf_snprintf_btf",
	150: "bpf_seq_printf_btf",
	151: "bpf_skb_cgroup_classid",
	152: "bpf_redirect_neigh",
	153: "bpf_per_cpu_ptr",
	154: "bpf_this_cpu_ptr",
	155: "bpf_redirect_peer",
	156: "bpf_task_storage_get",
	157: "bpf_task_storage_delete",
	158: "bpf_get_current_task_btf",
	159: "bpf_bprm_opts_set",
	160: "bpf_ktime_get_coarse_ns",
	161: "bpf_ima_inode_hash",
	162: "bpf_sock_from_file",
	163: "bpf_check_mtu",
	164: "bpf_for_each_map_elem",
	165: "bpf_snprintf",
	166: "bpf_sys_bpf",
	167: "bpf_btf_find_by_name_kind",
	168: "bpf_sys_close",
	169: "bpf_timer_init",
	170: "bpf_timer_set_callback",
	171: "bpf_timer_start",
	172: "bpf_timer_cancel",
	173: "bpf_get_func_ip",
	174: "bpf_get_attach_cookie",
	175: "bpf_task_pt_regs",
	176: "bpf_get_branch_snapshot",
	177: "bpf_trace_vprintk",
	178: "bpf_skc_to_unix_sock",
	179: "bpf_kallsyms_lookup_name",
	180: "bpf_find_vma",
	181: "bpf_loop",
	182: "bpf_strncmp",
	183: "bpf_get_func_arg",
	184: "bpf_get_func_ret",
	185: "bpf_get_func_arg_cnt",
}
