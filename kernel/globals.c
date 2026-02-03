#include <linux/module.h>
#include <linux/spinlock.h>
#include "includes/globals.h"

/* Netlink related PIDs and sockets */
pid_t userspace_control_pid = 0;
pid_t userspace_data_pid = 0;
uid_t userspace_uid = 0;
struct sock *sknl_ipfi_control = NULL;

/* Firewall options and status */
struct ipfire_options fwopts;
short default_policy = IPFIRE_DEFAULT_POLICY;
short loguser_enabled = 1;
short gui_notifier_enabled = 0;

/* Statistics */
struct kernel_stats kstats;
struct kstats_light kslight;

/* Rulesets */
ipfire_rule in_drop;
ipfire_rule out_drop;
ipfire_rule fwd_drop;
ipfire_rule in_acc;
ipfire_rule out_acc;
ipfire_rule fwd_acc;
ipfire_rule translation_pre;
ipfire_rule translation_post;
ipfire_rule translation_out;
ipfire_rule masquerade_post;

/* State and NAT tables */
struct state_table root_state_table;
struct dnatted_table root_dnatted_table;
struct snatted_table root_snatted_table;

/* Log info */
struct ipfire_loginfo packlist;

/* Counters */
unsigned int state_tables_counter = 0;
int dnatted_entry_counter = 0;
int snatted_entry_counter = 0;
int loginfo_entry_counter = 0;

/* Timeouts and Limits */
unsigned int state_lifetime = 432000; /* 5 days in seconds */
unsigned int setup_shutd_state_lifetime = 120;
unsigned int loginfo_lifetime = 0;
int max_loginfo_entries = 0;
unsigned int max_state_entries = 0;

/* Print limiting */
unsigned int moderate_print[MAXMODERATE_ARGS];
unsigned int moderate_print_limit[MAXMODERATE_ARGS];

/* Locks */
spinlock_t rulelist_lock;
spinlock_t state_list_lock;
spinlock_t loginfo_list_lock;
spinlock_t snat_list_lock;
spinlock_t dnat_list_lock;

/* Other */
int we_are_exiting = 0;

/* Export symbols if needed by other modules, but here they are used within the same module */
