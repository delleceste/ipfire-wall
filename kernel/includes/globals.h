#ifndef IPFI_GLOBALS_H
#define IPFI_GLOBALS_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include "ipfi.h"
#include "ipfi_log.h"
#include "ipfi_machine.h"
#include "ipfi_translation.h"

/* Netlink related PIDs and sockets */
extern pid_t userspace_control_pid;
extern pid_t userspace_data_pid;
extern uid_t userspace_uid;
extern struct sock *sknl_ipfi_control;

/* Firewall options and status */
extern struct ipfire_options fwopts;
extern short default_policy;
extern short loguser_enabled;
extern short gui_notifier_enabled;

/* Statistics */
extern struct kernel_stats kstats;
extern struct kstats_light kslight;

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
extern struct state_table root_state_table;
extern struct dnatted_table root_dnatted_table;
extern struct snatted_table root_snatted_table;

/* Log info */
extern struct ipfire_loginfo packlist;

/* Counters */
extern unsigned int state_tables_counter;
extern int dnatted_entry_counter;
extern int snatted_entry_counter;
extern int loginfo_entry_counter;

/* Timeouts and Limits */
extern unsigned int state_lifetime;
extern unsigned int setup_shutd_state_lifetime;
extern unsigned int loginfo_lifetime;
extern int max_loginfo_entries;
extern unsigned int max_state_entries;

/* Print limiting */
#define MAXMODERATE_ARGS 16
extern unsigned int moderate_print[MAXMODERATE_ARGS];
extern unsigned int moderate_print_limit[MAXMODERATE_ARGS];

/* Locks */
extern spinlock_t rulelist_lock;
extern spinlock_t state_list_lock;
extern spinlock_t loginfo_list_lock;
extern spinlock_t snat_list_lock;
extern spinlock_t dnat_list_lock;

/* Other */
extern int we_are_exiting;

#endif /* IPFI_GLOBALS_H */
