#include <stddef.h>
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct map_val {
	__u64 cnt;
};

struct bpf_map_def SEC("maps") result_number = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 11,
};

struct bpf_map_def SEC("maps") result_string = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = 32,
	.max_entries = 5,
};

struct foo {
	__u8  a;
	__u32 b;
	__u64 c;
};

struct bpf_map_def SEC("maps") result_struct = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct foo),
	.max_entries = 5,
};


/* Relocation tests for __u64s. */
static       __u64 num0;
static       __u64 num1 = 42;
static const __u64 num2 = 24;
static       __u64 num3 = 0;
static       __u64 num4 = 0xffeeff;
static const __u64 num5 = 0xabab;
static const __u64 num6 = 0xab;

/* Relocation tests for strings. */
static const char str0[32] = "abcdefghijklmnopqrstuvwxyz";
static       char str1[32] = "abcdefghijklmnopqrstuvwxyz";
static       char str2[32];

/* Relocation tests for structs. */
static const struct foo struct0 = {
	.a = 42,
	.b = 0xfefeefef,
	.c = 0x1111111111111111ULL,
};
static struct foo struct1;
static const struct foo struct2;
static struct foo struct3 = {
	.a = 41,
	.b = 0xeeeeefef,
	.c = 0x2111111111111111ULL,
};

#define test_reloc(map, num, var)					\
	do {								\
		__u32 key = num;					\
		bpf_map_update_elem(&result_##map, &key, var, 0);	\
	} while (0)

SEC("xdp")
int load_static_data(struct xdp_md *ctx)
{
	static const __u64 bar = ~0;

	test_reloc(number, 0, &num0);
	test_reloc(number, 1, &num1);
	test_reloc(number, 2, &num2);
	test_reloc(number, 3, &num3);
	test_reloc(number, 4, &num4);
	test_reloc(number, 5, &num5);
	num4 = 1234;
	test_reloc(number, 6, &num4);
	test_reloc(number, 7, &num0);
	test_reloc(number, 8, &num6);

	test_reloc(string, 0, str0);
	test_reloc(string, 1, str1);
	test_reloc(string, 2, str2);
	str1[5] = 'x';
	test_reloc(string, 3, str1);
	__builtin_memcpy(&str2[2], "hello", sizeof("hello"));
	test_reloc(string, 4, str2);

	test_reloc(struct, 0, &struct0);
	test_reloc(struct, 1, &struct1);
	test_reloc(struct, 2, &struct2);
	test_reloc(struct, 3, &struct3);

	test_reloc(number,  9, &struct0.c);
	test_reloc(number, 10, &bar);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";