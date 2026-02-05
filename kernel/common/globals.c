#include <linux/module.h>
#include <linux/spinlock.h>
#include "globals.h"

/* Netlink related PIDs and sockets */
pid_t userspace_control_pid = 0;
pid_t userspace_data_pid = 0;
uid_t userspace_uid = 0;
struct sock *sknl_ipfi_control = NULL;
struct sock *sknl_ipfi_data = NULL;
struct sock *sknl_ipfi_gui_notifier = NULL;

/* Firewall options and status */
struct ipfire_options fwopts;
short default_policy = IPFIRE_DEFAULT_POLICY;
short loguser_enabled = 1;
short gui_notifier_enabled = 0;

/* Statistics */
struct kernel_stats kstats;
struct kstats_light kslight;

struct ipfi_counters __percpu *ipfi_counters = NULL;

void ipfi_get_total_stats(struct kernel_stats *total)
{
    int cpu;
    memset(total, 0, sizeof(struct kernel_stats));
    
    /* Aggregate counters from all CPUs */
    if (ipfi_counters) {
        for_each_possible_cpu(cpu) {
            struct ipfi_counters *c = per_cpu_ptr(ipfi_counters, cpu);
            total->in_rcv += c->in_rcv;
            total->out_rcv += c->out_rcv;
            total->pre_rcv += c->pre_rcv;
            total->post_rcv += c->post_rcv;
            total->fwd_rcv += c->fwd_rcv;
            total->sum += c->sum;
            total->total_lost += c->total_lost;
            
            /* Sum per-direction sent counters */
            /* Note: structural update: these are not in original struct kernel_stats 
             * BUT we might want to sum them somewhere or just provide them. 
             * For now, we sum them into the total kstats if we added them there.
             */
            total->sent_tou += c->sent_tou;
            total->last_failed += c->last_failed;
            
            total->in_acc += c->in_acc;
            total->in_drop += c->in_drop;
            total->in_drop_impl += c->in_drop_impl;
            total->in_acc_impl += c->in_acc_impl;
            
            total->out_acc += c->out_acc;
            total->out_drop += c->out_drop;
            total->out_drop_impl += c->out_drop_impl;
            total->out_acc_impl += c->out_acc_impl;
            
            total->fwd_acc += c->fwd_acc;
            total->fwd_drop += c->fwd_drop;
            total->fwd_drop_impl += c->fwd_drop_impl;
            total->fwd_acc_impl += c->fwd_acc_impl;
            
            total->not_sent += c->not_sent;
            total->bad_checksum_in += c->bad_checksum_in;
            total->bad_checksum_out += c->bad_checksum_out;
        }
    }
    
    /* Copy global metadata */
    total->kmod_load_time = kstats.kmod_load_time;
    total->policy = kstats.policy;
}

void ipfi_get_light_stats(struct kstats_light *light)
{
    int cpu;
    memset(light, 0, sizeof(struct kstats_light));
    
    if (ipfi_counters) {
        for_each_possible_cpu(cpu) {
            struct ipfi_counters *c = per_cpu_ptr(ipfi_counters, cpu);
            light->blocked += c->blocked;
            light->allowed += c->allowed;
        }
    }
}

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
DEFINE_HASHTABLE(state_hashtable, STATE_HASH_BITS);
DEFINE_HASHTABLE(dnat_hashtable, DNAT_HASH_BITS);
DEFINE_HASHTABLE(snat_hashtable, SNAT_HASH_BITS);

/* Log info */
struct ipfire_loginfo packlist;

/* Counters */
unsigned int table_id = 0;
unsigned int state_tables_counter = 0;
int dnatted_entry_counter = 0;
int snatted_entry_counter = 0;
int loginfo_entry_counter = 0;

/* Timeouts and Limits */
unsigned int state_lifetime = 432000; /* 5 days in seconds */
unsigned int setup_shutd_state_lifetime = 120;
unsigned int loginfo_lifetime = 0;
int max_loginfo_entries = 100;
int (*smartlog_func)(const struct sk_buff *skb, const struct response *res, const ipfi_flow *flow, const struct info_flags *flags) = NULL;
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

int we_are_exiting = 0;

/* Export symbols if needed by other modules, but here they are used within the same module */
