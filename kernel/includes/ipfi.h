#ifndef IPFI_H
#define IPFI_H

/* See ipfi.c for details and 
 * use of this software. 
 * (C) 2005 Giacomo S. 
 */

//#include <linux/config.h>
#include "../../common/defs/ipfi_structures.h"
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/stddef.h>
#include <linux/sched.h> /* for getting uid from pid */
#include <linux/netfilter.h>	/* for hook registering */
#include <linux/netfilter_ipv4.h>	/* for hook registering */
#include <linux/version.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <net/protocol.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>		/* for checksumming */

#include "ipfi_header_check.h"

#define IPFIRE_DEFAULT_POLICY 0 /* denial */

#define NETLINK_IPFI_DATA 		MAX_LINKS - 3
#define NETLINK_IPFI_CONTROL 		MAX_LINKS - 2
#define NETLINK_IPFI_GUI_NOTIFIER	MAX_LINKS - 1

/* network printk() should be guarded by net_ratelimit() function -- see net/core/utils.c */
#define IPFI_PRINTK(args...) do { if (net_ratelimit()) printk(args); } while(0)


#define MAXMODERATE_ARGS 	16
#define MODERATE_LIMIT		32

/* this macro avoids filling kernel log with the same message hundred of times.
 * There are MAXMODERATE_ARGS different messages that can be registered by means
 * of the enumeration moderate_print_sections below. The associated message is 
 * printed by printk only every MODERATE_LIMIT times.
 * The variable used by this macro must be globally declared in the file/module that 
 * uses it and its name must be `moderate_print. It must be an unsigned int array of
 * dimension MAXMODERATE_ARGS. An example is represented in ipfi_machine, where 
 * `moderate_print is declared at the beginning of the file and initialized to 0 values
 * in the initialization method `init_translation()' via the memset function.
 */
#define IPFI_MODERATE_PRINTK(id, args...) do \
{ \
  if(id < MAXMODERATE_ARGS) \
  { \
    if(moderate_print[id] % moderate_print_limit[id] == 0) \
    { \
      moderate_print[id]++; \
      IPFI_PRINTK(args); \
      IPFI_PRINTK("[message repeated %u times. Next repetition in %u events of the same type]\n", moderate_print[id], moderate_print_limit[id]); \
    } \
    else \
    { \
      moderate_print[id]++; \
    } \
  } \
}while(0)
    
enum moderate_print_sections
{
  PRINT_PROTO_UNSUPPORTED = 0,
  PRINT_SKB_ALLOC_FAILED,
  PRINT_TEST,
  /* register here other custom sections */
  
  END_MODERATE_LIST = MAXMODERATE_ARGS - 1,
};

enum checksum_errors { BAD_IP_CSUM = 1, BAD_TCPHEAD_CSUM,  BAD_TCPHEAD_CHECK,
  BAD_UDPHEAD_CHECK, BAD_UDPHEAD_CSUM };


#define BAD_CHECKSUM   INT_MIN


/* constant for updating statistic counters */
#define IPFI_FAILED_NETLINK_USPACE 10

/* every PRINTK_WARN_IPFI_DISABLED packets a warning is logged
 * telling IPFI is disabled */
#define PRINTK_WARN_IPFI_DISABLED 20

// /* linked list containing rules */
// struct rule_list {
// 	ipfire_rule rule;
// 	struct list_head list;
// 	
// 	struct rcu_head rulelist_rcuh;
// };

/* loguser: 
                 if loguser >= 2  implicit denial is sent back;
                 if loguser >= 4 implicit and explicit denial;
                 if loguser >= 5 all filtering is sent back;
                 if loguser >= 6 filtering and pre/post stuff is sent.
                 commands in do_control are always sent back: loguser
                 then decides to print or not information. To have information
                 printed on commands received _at_startup_ loguser
                 must be 7.
 */
 /* loglevel
    if loglevel > 3 printk of rule added in manage_rule() 
    (ipfi_netl.c );  
    if loglevel > 2 printk of command received in do_control
    (ipfi_netl.c);
  */
struct ipfire_options {
	u8 nat:1, masquerade:1, state:1, all_stateful:1, free:4;
	u8 user_allowed:1, noflush_on_exit:1, loglevel:3,	/* logging level by means of printk */
	 loguser:3;		/* sending information to userspace */
	 unsigned long int snatted_lifetime;
	 unsigned long int dnatted_lifetime;
	 unsigned long int state_lifetime;
	 unsigned long int setup_shutd_state_lifetime;
	 unsigned long int loginfo_lifetime;
	 unsigned long int max_loginfo_entries;
	 unsigned long int max_nat_entries;
	 unsigned long int max_state_entries;
};

/* functions to register with netfilter hooks */
int register_hooks(void);


unsigned int deliver_process_by_direction(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state);

/* ipfire functions */



inline int
allocate_headers(const struct sk_buff *skb, ipfire_info_t * fireinfo);


/* The following three functions extract from the socket buffer
 * skb the tcp/udp/icmp header.
 * Since allocate_headers() already extracts the IP header, 
 * allocate_headers() itself passes this header to build_xxxh_usermess()
 * for convenience
 */
inline int build_tcph_usermess(const struct sk_buff *skb,
	const struct iphdr *iph,
	ipfire_info_t * ipfi_info);
	
inline int build_udph_usermess(const struct sk_buff *skb,
	const struct iphdr *iph,
	ipfire_info_t * ipfi_info);
	
inline int build_icmph_usermess(const struct sk_buff *skb,
	const struct iphdr *iph,
	ipfire_info_t * ipfi_info);
				
inline int build_igmph_usermess(const struct sk_buff *skb,
				const struct iphdr *iph,
    ipfire_info_t * ipfi_info);
								
/* NF hooks pass input and output device. If not null,
 * we copy names into info */
inline int get_devnames(const struct sk_buff *skb,
			ipfire_info_t * ipfi_info, const struct net_device* in,
			const struct net_device* out);
			
int build_ipfire_info_from_skb(const struct sk_buff *skb,
			       ipfire_info_t * iit, int direction,
			       int packet_no, const struct net_device* in,
			       const struct net_device* out);

#ifdef ENABLE_RULENAME
/* if rulename in src is specified, copy it to dest rulename */
inline void copy_rulename(ipfire_info_t * iit_dest,
			  const ipfire_info_t * iit_src);
#endif

/* if *cnt reaches ULONG MAX, it must be reset to 0 */
inline void check_packet_num(unsigned long long *cnt);

int ipfi_response(struct sk_buff *skb, unsigned long long packet_num,
		  int direction, const struct net_device *in, const struct net_device *out);
int ipfi_pre_process(struct sk_buff *skb, unsigned long long packet_num,
		     int direction, const struct net_device *in);
int ipfi_post_process(struct sk_buff *skb, unsigned long long packet_num,
		      int direction, const struct net_device *out);
int get_cache_inh_in(const ipfire_info_t info);

int recalculate_ip_checksum(struct sk_buff *skb, int direction);

void init_packet(ipfire_info_t * iit);

/* updates sent counter, sends packet to userspace and calls
 * update_kernel_stats()
 */
inline int 
send_packet_to_userspace_and_update_counters(ipfire_info_t* 
		packet);

/* prints just tcp checksum, for debug. To remove */
void print_check(struct sk_buff* skb);

/* Callback to free a rule removed from the linked list. */
void free_rule_rcu_call(struct rcu_head* head);


#endif
