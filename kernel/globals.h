#ifndef IPFI_GLOBALS_H
#define IPFI_GLOBALS_H

#include "ipfire.h"
#include "logging/log.h"
#include "ipfi_machine.h"
#include "../nat/nat.h"
#include "../nat/dnat/dnat.h"
#include "../nat/snat/snat.h"
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#ifndef timer_container_of
#define timer_container_of(ptr, timer, member) from_timer(ptr, timer, member)
#endif

/*
 * Internal pseudo-protocol for loginfo timer refresh.
 * Uses IANA-reserved value 254 (experimentation/testing).
 * This lets log entries reuse ipfi_entry_update_timer()
 * without needing a separate flat-timeout function.
 */
#define IPPROTO_IPFI_LOG 254

/* Netlink related PIDs and sockets */
extern pid_t userspace_control_pid;
extern pid_t userspace_data_pid;
extern uid_t userspace_uid;
extern struct sock *sknl_ipfi_control;
extern struct sock *sknl_ipfi_data;
extern struct sock *sknl_ipfi_gui_notifier;

/* Firewall options and status */
extern struct ipfire_options fwopts;
extern short default_policy;
extern short loguser_enabled;
extern short gui_notifier_enabled;

/* Statistics */
extern struct kernel_stats kstats;
extern struct kstats_light kslight;

/* Per-CPU Statistics */
extern struct ipfi_counters __percpu *ipfi_counters;
#define IPFI_STAT_INC(field) this_cpu_inc(ipfi_counters->field)

void ipfi_get_total_stats(struct kernel_stats *total);
void ipfi_get_light_stats(struct kstats_light *light);

/* Rulesets */
extern ipfire_rule in_drop;
extern ipfire_rule out_drop;
extern ipfire_rule fwd_drop;
extern ipfire_rule in_acc;
extern ipfire_rule out_acc;
extern ipfire_rule fwd_acc;
extern ipfire_rule translation_pre;
extern ipfire_rule translation_post;
extern ipfire_rule translation_out;
extern ipfire_rule masquerade_post;

/* State and NAT tables */

/* extern DECLARE_HASHTABLE(state_hashtable, STATE_HASH_BITS); TODO: restore
 * hash
 */
extern struct list_head state_list;

/* NAT tables now use arrays indexed by nat_type in nat_table.h.
 * Compatibility macros for existing callers: */
#define dnat_list       nat_lists[NAT_DNAT]
#define snat_list       nat_lists[NAT_SNAT]

/* Log info */
/* extern DECLARE_HASHTABLE(loginfo_hashtable, LOGINFO_HASH_BITS); TODO: restore
 * hash
 */
extern struct list_head active_logi_list;

/* Counters */
extern unsigned int table_id;
extern unsigned int state_tables_counter;
#define dnatted_entry_counter  nat_counters[NAT_DNAT]
#define snatted_entry_counter  nat_counters[NAT_SNAT]
extern unsigned int loginfo_entry_counter;

/* Timeouts and Limits */
extern unsigned int state_lifetime;
extern unsigned int setup_shutd_state_lifetime;
extern unsigned int loginfo_lifetime;
extern unsigned int max_loginfo_entries;
extern int (*smartlog_func)(const struct sk_buff *skb,
                            const struct response *res, const ipfi_flow *flow,
                            const struct info_flags *flags);
extern unsigned int max_state_entries;

/* Print limiting */
extern unsigned int moderate_print[MAXMODERATE_ARGS];
extern unsigned int moderate_print_limit[MAXMODERATE_ARGS];

/* Locks */
extern spinlock_t rulelist_lock;
extern spinlock_t state_list_lock;
extern spinlock_t loginfo_list_lock;
#define snat_list_lock  nat_locks[NAT_SNAT]
#define dnat_list_lock  nat_locks[NAT_DNAT]
extern struct workqueue_struct *ipfire_wq;

/* Other */
extern bool we_are_exiting;

#endif /* IPFI_GLOBALS_H */
