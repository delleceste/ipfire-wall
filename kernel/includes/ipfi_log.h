#ifndef IPFI_LOG_H
#define IPFI_LOG_H

/* See ipfi.c for details and 
 * use of this software. 
 * (C) 2005 Giacomo S. 
 */

#include "ipfi.h"

struct ipfire_loginfo
{
	ipfire_info_t info;
	struct list_head list;
	struct timer_list timer_loginfo;
	struct rcu_head rcuh;
};

int init_log(void);

void fini_log(void);

/* updates timer of a loginfo entry, when a packet is already
 * present il packlist list. Invoked by packet_not_seen() when
 * it has seen this packet in list */
inline void update_loginfo_timer(struct ipfire_loginfo* iplo);

inline void fill_timer_loginfo_entry(struct ipfire_loginfo* ipfilog);

int comp_pack(const ipfire_info_t* p1, const ipfire_info_t* p2);

/* compares two packets in the shape of ipfire_info_t. All
 * fields are compared, except packet_id, the last one */
inline int compare_loginfo_packets(const ipfire_info_t* packet1, const ipfire_info_t* packet2);

/* returns 1 if packet has never been seen,
 * 0 otherwise. If a packet is already in list, 
 * its timer is updated */
inline int packet_not_seen(const ipfire_info_t* packet, int chk_state);

/* Invoked when loglevel is 1, this function compares
 * packet with all other packets seen. If a packet has
 * already been seen, it's not logged and nothing is 
 * done, if it is the first packet, it is added to list of seen
 * packets and 1 is return, as to indicate that packet 
 * must be logged to userspace. This "smart logging"
 * reduces load in userspace communication via netlink
 * socket. 
 */
int smart_log(const ipfire_info_t* info);

/* This is registered when the log level is MART_LOG_WITH_STATE_CHECK.
 * Applies all the same procedures as the one above, but also
 * does checks against the state.
 */
 int smart_log_with_state_check(const ipfire_info_t* info);

/* copies a packet to info field of ipfire_loginfo, then initializes
 * timers and adds to packlist list */
inline int add_packet_to_infolist(const ipfire_info_t* info);


void handle_loginfo_entry_timeout(struct timer_list *t);

void free_entry_rcu_call(struct rcu_head *head);




#endif
