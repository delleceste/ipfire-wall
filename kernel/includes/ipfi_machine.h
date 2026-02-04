#ifndef IPFI_MACHINE_H
#define IPFI_MACHINE_H

/* See ipfi.c for details and 
 * use of this software.
 * (C) 2005 Giacomo S.
 */

#include <linux/timer.h>
#include "ipfi.h"
#include "ipfi_netl.h"
#include "ipfi_ftp.h"
#include "../../common/defs/ipfi_structures.h"
#include <linux/hashtable.h>
#include <linux/jhash.h>

#define STATE_HASH_BITS 12

/* ftp passive support */
#define FTP_NONE 0         /* not an ftp rule */
#define FTP_LOOK_FOR 1  /* look for port and ip */
#define FTP_DEFINED 2     /* port and ip determined */
/* after first packet is accepted going out, source port is corrected
 * and since then ftp becomes FTP_ESTABLISHED and all subsequent
 * checks will involve also source port. In FTP_DEFINED state in fact,
 * source port is not checked */
#define FTP_ESTABLISHED 3

struct state {
    __u8 reverse:1,
        notify:1,
        unused:6;
    struct state_t state;
};

struct state_table
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 direction:3,
        ftp:3, /* passive ftp support */
        notify:1,
        admin:1;
    uint32_t rule_id;  /* ID of the rule that originated this state */
    __u8 protocol;
    char in_devname[IFNAMSIZ];
    char out_devname[IFNAMSIZ];
    int in_ifindex, out_ifindex;

    /* Note: pkmanip removed - MSS mangling applied directly on rule match,
     * no need to store in state tables */

    struct timer_list timer_statelist;
    unsigned long last_timer_update;
    struct list_head list;
    struct state_t state;

    /* RCU */
    struct rcu_head state_rcuh;
    struct hlist_node hnode;
};

int init_machine(void);
void fini_machine(void);

struct response check_state(struct sk_buff* skb, const ipfi_flow *flow);
int skb_matches_state_table(const struct sk_buff* skb, const struct state_table* entry,
                short *reverse, const ipfi_flow *flow);

unsigned int get_timeout_by_state(int protocol, int state);

/* main filtering function: compares packet with each denial and 
 * permission rule. Returns < 0 if a denial rule is found matching
 * packet, > 0 if a permission rule matche packet, 0 if no explicit
 * rule is found. If a match is found, copies rulename from rule
 * to rulename field of packet, just to add info for user.
 * skb might be modified if mangling is required in input output or
 * forward directions - e.g. mss manipulation -.
 */
struct response ipfire_filter(const ipfire_rule *denied,
                              const ipfire_rule *allowed,
                              const struct ipfire_options* ipfiopts,
                              struct sk_buff* skb,
                              const ipfi_flow *flow,
                              struct info_flags *flags);

int port_match(const  struct tcphdr *tcph, const struct udphdr *udph,
               const ipfire_rule* r, short protocol);

int address_match(const struct iphdr *iph,
                  const ipfire_rule* r,
                  int direction,
                  const struct net_device *in,
                  const struct net_device *out);

#ifdef ENABLE_RULENAME
/* copies rulename from packet to state table */
inline void fill_table_with_name(struct state_table * state_t, 
                                 const ipfire_info_t *packet);

/* copies rule name in packet if it is specified in rule */
inline void fill_packet_with_name(ipfire_info_t* packet, 
                                  const ipfire_rule* r);

/* copies rulename field from state table to packet */
inline void fill_packet_with_table_rulename(ipfire_info_t* packet, 
                                            const struct state_table* stt);
#endif

inline int direction_filter(int direction, const ipfire_rule * r);

int device_filter(const ipfire_rule * r,
                  const struct net_device *in,
                  const struct net_device *out);

int ipfi_tcp_filter(const struct tcphdr *tcph, const ipfire_rule* r);

int udp_filter(const struct udphdr *udph, const ipfire_rule* r);

int icmp_filter(const struct icmphdr *icmph, const ipfire_rule* r);

int ip_layer_filter(const  struct iphdr *iph, const ipfire_rule* r, int direction,
                    const  struct net_device *in, const  struct net_device *out);

int direct_state_match(const  struct sk_buff *skb,
                       const struct state_table *entry,
                       const ipfi_flow *flow);

int reverse_state_match(const struct sk_buff *skb,
                        const struct state_table *entry,
                        const ipfi_flow *flow);

/* keep_state */
/* If a skb carries fields pertaining to a table already present
 * in the state table list, then NULL is returned, to indicate to the
 * caller that the entry derived from `skb' does not have to be
 * added. If `skb' is a skb not seen, a new entry of the
 * "state_table" kind is returned. nflags is used
 * just for passive ftp support for now.
 * keep_state is called by ipfire_filter with the rcu_read_lock
 * hold for static rules.
 * - include/linux/rcupdate.h says:
 * `RCU read-side critical sections may be nested.  Any deferred actions
 *   will be deferred until the outermost RCU read-side critical section
 *   completes.'
 */
struct state_table* keep_state(const struct sk_buff *skb,
                               const ipfire_rule* p_rule,
                               const ipfi_flow *flow);

/* Adds the new state table to the list. Takes a pointer to a memory allocated
 * structure.
 */
int add_state_table_to_list(struct state_table* newtable);

inline int ixmp_match(const ipfire_info_t* packet, const struct state_table* entry);

inline int
direct_transport_state_match(const ipfire_info_t * packet,
                             const struct state_table *entry);
inline int
reverse_transport_state_match(const ipfire_info_t * packet,
                              const struct state_table *entry);

/* fills in state table with network informations */
int fill_net_table_fields(struct state_table *state_t,
                          const struct sk_buff *skb,
                          const ipfi_flow *flow);

int fill_state_info(struct state_info *stinfo, const struct state_table* stt);

/* This function updates the timer of the entry passed as argument.
 * It is supposed that it has been called in a safe context, i.e.
 * with a lock held and with sw interrupts disabled, so that it does
 * not get interrupted by the timeout routine, or have in any way
 * deleted the object it operates on.
 */
inline void 
update_timer_of_state_entry(struct state_table *sttable);

void fill_timer_table_fields(struct state_table* state_t);

/* This routine acquires the write lock before deleting an item
 * on the list of the state connections.
 */
void handle_keep_state_timeout(struct timer_list *t);

/* compares two state table entries */
int compare_state_entries(const struct state_table *s1,
                          const struct state_table* s2);

/* scans root list looking for already present entries. 
 * Returns NULL if none is found, the pointer to the entry
 * if a match is found. If a match is found, befre returning,
 * the matching table will have its timer updated. The choice
 * to update timers here avoids putting another lock when
 * calling timer updating routine elsewhere.
 */
struct state_table *lookup_state_table_n_update_timer(const struct state_table *stt, int lock);

/* returns in *addr the internet address corresponding to 
 * ouput or input interface, depending on field "direction" of info
 * info packet. This is good for in and out directions, where
 * the context is clear when one says "my address".
 */
int get_dev_ifaddr( __u32* addr,
                    int direction,
                    const  struct net_device *in,
                    const  struct net_device *out);

/* returns in *addr the internet address having the name ifname */
int get_ifaddr_by_name(const char* ifname, __u32* addr);

int free_state_tables(void);

void update_ifindex_in_state_tables(const char *name, int new_index);

void register_ipfire_netdev_notifier(void);
void unregister_ipfire_netdev_notifier(void);


/* Passive FTP support */
/* 1. set the correct state of the new entry (NONE, packet not already seen,
        just the rule is ready for future connection);
    2. initialize timers;
    3. add the rule to the tail of the list just as any other rule
    4. :)
  */
int add_ftp_dynamic_rule(struct state_table* ftpt);

/* callback for freeing rcu elements */
void free_state_entry_rcu_call(struct rcu_head *head);

#endif
