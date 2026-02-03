#ifndef IPFI_TRANSLATION_H
#define IPFI_TRANSLATION_H

/* See ipfi.c for details and 
 * use of this software. 
 * (C) 2005 Giacomo S. 
 */

#include "../../common/defs/ipfi_structures.h"
#include <linux/timer.h>

#define SNAT_ENTRY 0
#define DNAT_ENTRY 1
 
typedef struct 
{
  __u32 saddr, daddr;
  __u16 sport, dport;
  /* 0 is not valid */
  short int valid;
}net_quadruplet;
 
struct pkt_manip_info
{
	__u8 sa:1,
	sp:1,
	da:1,
	dp:1,
	direction:4; /* 4 bits as in ipfire_rule */
};

/* the table contains information about destination adddress
 * translated connections. The list of dnatted tables must be
 * checked on arrival of a packet on the interface interested.
 */
struct dnatted_table
{
	__u32 old_saddr;
	__u16 old_sport;
	__u32 old_daddr;
	__u16 old_dport;
	__u32 new_daddr;
	__u16 new_dport;
	
	__u32 our_ifaddr;

	__u8 direction:4,external:4;
	__u8 protocol;
	
	/* From version 0.98.2 on, we keep the state of the NAT tables, just to
	 * apply the correct timeouts on them.
	 */
	__u8 state;

	unsigned int id;
	unsigned int position;

    int in_ifindex;
    int out_ifindex;
#ifdef ENABLE_RULENAME
	char rulename[RULENAMELEN];
#endif	
	struct timer_list timer_dnattedlist;
	struct list_head list;
	/* RCU */
	struct rcu_head dnat_rcuh;
};

/* the table contains information about source adddress
 * translated connections. The list of snatted tables must be
 * checked on arrival of a packet on the interface interested.
 */
struct snatted_table
{
	__u32 old_saddr;
	__u16 old_sport;
	__u32 old_daddr;
	__u16 old_dport;
	__u32 new_saddr;
	__u16 new_sport;

	__u8 direction:4,external:4;
	__u8 protocol;
	__u8 state;
	
	unsigned int id;
	unsigned int position;

    int in_ifindex;
    int out_ifindex;

	struct timer_list timer_snattedlist;
	struct list_head list;
	/* RCU */
	struct rcu_head snat_rcuh;
};

int init_translation(void);

void fini_translation(void);

int get_orig_from_dnat_entry(const struct dnatted_table* dnt, const net_quadruplet *n4, struct sockaddr_in* sin);

int  lookup_dnat_table_and_getorigdst(const net_quadruplet *n4, struct sockaddr_in* sin);

int get_original_dest(struct sock *sk, int optval, void __user *user, int *len);

/* translate destination address or destination port
 * Used in prerouting or output directions.
 */
int dnat_translation(struct sk_buff* skb,
                 ipfire_info_t* packet,
                 const ipfi_flow *flow,
                 const struct info_flags *flags);

/* skb contains the fields taken from sk_buff, r is the translation rule.
 * In this function, the skb must match the rule provided by user for
 * DNAT or SNAT (or MASQUERADE). 1 is returned on success, i.e. if the 
 * rule matches ip skb. Rule name is filled in in skb if a matcu
 * is found with a rule. */
int translation_rule_match(const ipfire_info_t *packet,
                           const ipfire_rule* r);

int dest_translate(struct sk_buff* skb, const ipfire_rule* transrule);

/* Looks up dnatted table, comparing each entry with the entry 
 * passed as argument. This happens while holding a read lock 
 * which also disables sw interrupts. We take advantage of such
 * lock to update here entry timer, instead of acquiring another
 * lock later elsewhere to update the timer.
 */
struct dnatted_table *
lookup_dnatted_table_n_update_timer(const struct dnatted_table *dne, ipfire_info_t* info);

int 
compare_dnat_entries(const struct dnatted_table* dne1, 
		     const struct dnatted_table* dne2);

int add_dnatted_entry(const struct sk_buff* skb, ipfire_info_t* original_pack, const ipfire_rule* dnat_rule);
int fill_entry_net_fields(struct dnatted_table  *dnentry, const ipfire_info_t* original_pack, 
				      const ipfire_rule* nat_rule);
				      
void fill_masquerade_rule_fields(ipfire_rule * ipfr, __u32 newsaddr);
void clear_masquerade_rule_fields(ipfire_rule *);
				      
void fill_timer_snat_entry(struct snatted_table *snt);
void fill_timer_dnat_entry(struct dnatted_table *snt);

#ifdef ENABLE_RULENAME
/* if rulename in src is specified, copy it to dest rulename */
inline void copy_rulename_from_rule_to_ipfire_info
		(ipfire_info_t* iit_dest, const ipfire_rule* rule_src);
				      
/* if not null, copies rulename from packet to dne */
inline void fill_rulename_dnat_entry(const ipfire_info_t* packet, 
			      struct dnatted_table* dne);

/* copies rulename field from state table to packet */
inline void fill_packet_with_dnentry_rulename(ipfire_info_t* packet, 
					      const struct dnatted_table* dnentry);
#endif
					      
/* de-nat function */
int denat_table_match(const struct dnatted_table* dnt, const ipfire_info_t* pack);
int de_dnat_translation(struct sk_buff* skb, ipfire_info_t *pack);

/* given a socket buffer skb, returns source and destination addresses and ports 
 * at the addresses of parameters passed as arguments, 1 in case of TCP and UDP
 * 0 in case of ICMP, -1 in case of invalid protocol.
 */
net_quadruplet get_quad_from_skb(const struct sk_buff* skb);
		       
/* given source and destination addresses and ports, this function sets them 
 * in socket buffer passed as parameter. In case of TCP or UDP protocols, 
 * returns 1, 0 for ICMP, -1 in case of errors 
 */
int manip_skb(struct sk_buff* skb, __u32 saddr, __u16 sport,
		     __u32 daddr, __u16 dport, struct pkt_manip_info pf);
		     
/** three pre de dnat functions */
int pre_de_dnat_translate(struct sk_buff* skb, const struct dnatted_table* dnt);

/* looks for matches in dynamic denatted tables. If a match is found,
 * rule name is copied to packet */
int pre_denat_table_match(const struct dnatted_table* dnt, 
			  const struct sk_buff* skb, ipfire_info_t* packet);
/* if a packet hits prerouting hook and comes back from a previously
 * dnatted connection, with ip address translation (i.e. has been forwarded),
 * it must be de-dnatted */
int pre_de_dnat(struct sk_buff* skb, ipfire_info_t* packet);
/** end of pre de dnat functions */
 
/** Source NAT functions */ 

/* Looks up in source address translated tables and if 
 * an entry is equal to the entry passed as parameter
 * its timer is updated and a pointer to it is returned.
 * See dnatted lookup function counterpart for further details.
 */
struct snatted_table *
lookup_snatted_table_n_update_timer(const struct snatted_table *sne, ipfire_info_t* info);

int snat_dynamic_translate(struct sk_buff* skb, struct dnatted_table* dnt);

/* looks for a match between skb fields and dynamic entries. If a match is
 * found, rule name is copied into packet */
int snat_dynamic_table_match(const struct dnatted_table* dnt, 
			     const struct sk_buff* skb,
			     ipfire_info_t* packet);

/* checks in dynamic entries in root nat table looking for a rule matching 
 * the packet in skb to source address-translate in postrouting hook, after
 * a packet has gone in forward hook. Only packets forwarded to another
 * machine should match in snat_dynamic_table_match() (see before).
 * In that case, source address of outgoing forwarded packet must be
 * our address, which we can find in entry->old_daddr (see snat_dynamic
 * _translate() ).
 */
int post_snat_dynamic(struct sk_buff* skb, ipfire_info_t* packet);

#ifdef ENABLE_RULENAME
/* if not null, copies rulename from packet to dynamic snentry */
inline void fill_rulename_snat_entry(const ipfire_info_t* packet, 
				     struct snatted_table* snentry);

/* copies rulename field from state table to packet */
inline void fill_packet_with_snentry_rulename(ipfire_info_t* packet, 
					      const struct snatted_table* snentry);
#endif

int add_snatted_entry(ipfire_info_t* original_pack, 
		      const ipfire_rule* snat_rule, ipfire_info_t* packet);

int masquerade_translation(struct sk_buff* skb, ipfire_info_t* post_packet);

int snat_translation(struct sk_buff* skb, ipfire_info_t* post_packet);

/* returns 1 if network address is a private one conforming
 * to rfc 1918, 0 otherwise */
inline int private_address(__u32 addr);

/* returns 1 if packet comes from a public host and 
 * gets redirected to an internal host. In this case,
 * the address of the remote host, shall not be substituted
 * with our address: receiving machine has the right to see
 * the real identity of the sender. */
 int public_to_private_address(const struct sk_buff* skb, 
 		const ipfire_rule* transrule);

__u32 get_ifaddr(const struct sk_buff* skb);

/* copies address in *address, looking for devices with name
 * equal to device name in skb. Returns 1 or -1 in case of failure  */
int get_ifaddr_by_skb(const struct sk_buff *skb, __u32* address);

int 
compare_snat_entries(const struct snatted_table* sne1, 
				     const struct snatted_table* sne2);
			
int pre_de_snat(struct sk_buff* skb, ipfire_info_t* packet);

/* restores original source address (changed by snat/masq) in
 * the destination address of coming back packet. We are in pre-
 * routing hook. */
int de_snat(struct sk_buff* skb, struct snatted_table* snt);

int do_source_nat(struct sk_buff* skb, ipfire_rule* ipfr);

int de_snat_table_match(struct snatted_table* snt, 
			struct sk_buff* skb, ipfire_info_t* packet);
			

/* checks ip and transport checksums, returning 0  if correct,
 * a negative value picked from enum checksum_errors (ipfi.h) otherwise */
int check_checksums(const struct sk_buff* skb);

/* prints the checksum error message according to the checksum_errore enum
 * defined in ipfi.h and returns -1. Introducted in 0.99.2
 */
int csum_error_message(const char *origin, int enum_code);

/* Two callback functions for freeng SNAT/DNAT entries. */
void free_dnat_entry_rcu_call(struct rcu_head *head);

void free_snat_entry_rcu_call(struct rcu_head *head);

void handle_dnatted_entry_timeout(struct timer_list *t);

void handle_snatted_entry_timeout(struct timer_list *t);

int de_dnat(struct sk_buff *skb, const struct dnatted_table *dnatt);

int de_dnat_table_match(const struct dnatted_table *dnt,
                        const struct sk_buff *skb, ipfire_info_t * packet);

#endif
