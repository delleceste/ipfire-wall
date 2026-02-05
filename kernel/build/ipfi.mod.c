#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

KSYMTAB_FUNC(packet_suitable_for_mss_change, "", "");
KSYMTAB_FUNC(tcpmss_mangle_packet, "", "");

SYMBOL_CRC(packet_suitable_for_mss_change, 0x5c4a2b17, "");
SYMBOL_CRC(tcpmss_mangle_packet, 0x41ef1f49, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x7696f8c7, "__list_add_valid_or_report" },
	{ 0xbe06a47e, "skb_copy_bits" },
	{ 0xdb1853fa, "__nlmsg_put" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xc26279c1, "skb_put" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0xb0e602eb, "memmove" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xa0caab03, "nf_register_sockopt" },
	{ 0x69acdf38, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0x2bba8948, "pcpu_hot" },
	{ 0x9c5b2dc3, "__netlink_kernel_create" },
	{ 0xb97ef805, "proc_create_data" },
	{ 0xdc0e4855, "timer_delete" },
	{ 0x82ee90dc, "timer_delete_sync" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0xe9e31982, "ip_route_output_flow" },
	{ 0xb19a5453, "__per_cpu_offset" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x190a49ac, "pskb_expand_head" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x92997ed8, "_printk" },
	{ 0x91d80641, "nf_unregister_sockopt" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xe46021ca, "_raw_spin_unlock_bh" },
	{ 0xaa02e0d8, "__alloc_skb" },
	{ 0xec52cd88, "nf_unregister_net_hook" },
	{ 0xdc67c7d9, "nf_register_net_hook" },
	{ 0x9ae026d4, "init_net" },
	{ 0x24d273d1, "add_timer" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0xba0759d5, "ip6_mtu" },
	{ 0xb5b40f49, "sk_skb_reason_drop" },
	{ 0xd06c3cff, "netlink_unicast" },
	{ 0xc38c83b8, "mod_timer" },
	{ 0x5a921311, "strncmp" },
	{ 0x9166fada, "strncpy" },
	{ 0xb34bef01, "skb_ensure_writable" },
	{ 0xab268d8b, "netlink_kernel_release" },
	{ 0x950eb34e, "__list_del_entry_valid_or_report" },
	{ 0x9ec6ca96, "ktime_get_real_ts64" },
	{ 0x53a1e8d9, "_find_next_bit" },
	{ 0x65f0c71, "inet_select_addr" },
	{ 0x449ad0a7, "memcmp" },
	{ 0x3c3fce39, "__local_bh_enable_ip" },
	{ 0xbcab6ee6, "sscanf" },
	{ 0xa93fc3ad, "default_llseek" },
	{ 0x81de4d0e, "proc_mkdir" },
	{ 0x310fa19e, "from_kuid" },
	{ 0x9e683f75, "__cpu_possible_mask" },
	{ 0x7a162c84, "skb_checksum" },
	{ 0xfb578fc5, "memset" },
	{ 0x94429940, "ip_defrag" },
	{ 0xa5315153, "param_ops_charp" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x17de3d5, "nr_cpu_ids" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x8a50975, "__pskb_pull_tail" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x9d0d6206, "unregister_netdevice_notifier" },
	{ 0xc9ec4e21, "free_percpu" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x28aa6a67, "call_rcu" },
	{ 0xd3d79e79, "ipv4_mtu" },
	{ 0xc25d94c1, "pcpu_alloc_noprof" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0xc37e1b03, "inet_proto_csum_replace4" },
	{ 0xce32b0d9, "init_user_ns" },
	{ 0x666e61e9, "remove_proc_entry" },
	{ 0xd8ba0fc0, "__kmalloc_cache_noprof" },
	{ 0xd2da1048, "register_netdevice_notifier" },
	{ 0xe0112fc4, "__x86_indirect_thunk_r9" },
	{ 0x5089f45f, "ip_send_check" },
	{ 0xcb4ded01, "dev_get_by_name" },
	{ 0xc3690fc, "_raw_spin_lock_bh" },
	{ 0x55484571, "dst_release" },
	{ 0x60a13e90, "rcu_barrier" },
	{ 0x754d539c, "strlen" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0x619cb7dd, "simple_read_from_buffer" },
	{ 0xe2c17b5d, "__SCT__might_resched" },
	{ 0xc4aa18f, "kmalloc_caches" },
	{ 0x609f1c7e, "synchronize_net" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xbf1981cb, "module_layout" },
};

MODULE_INFO(depends, "");

