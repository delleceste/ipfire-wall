/* ipfi_log.c: a packet to be logged is really sent to userspace only if
 * it is not identical to a one previously sent. This reduces kernel/user
 * communication load */

/***************************************************************************
 *  Copyright  2005  Giacomo
 *  jacum@libero.it
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */
 
 /* see ipfi.c for details */

#include "includes/ipfi_netl.h"
#include "includes/ipfi.h"
#include "includes/ipfi_log.h"

struct ipfire_loginfo packlist;
int loginfo_entry_counter = 0;
int max_loginfo_entries;
unsigned int loginfo_lifetime;

/* spin lock for elements in linked lists */
spinlock_t loginfo_list_lock;

void free_entry_rcu_call(struct rcu_head *head)
{
    struct ipfire_loginfo *ipfl = 
	    container_of(head, struct ipfire_loginfo, rcuh);
    kfree(ipfl);
}

void handle_loginfo_entry_timeout(unsigned long data)
{
	struct ipfire_loginfo *ipfilog = (struct ipfire_loginfo *) data;
	/* lock list before deleting an entry */
	spin_lock_bh(&loginfo_list_lock);
	del_timer(&ipfilog->timer_loginfo);
	list_del_rcu(&ipfilog->list);	/* delete from list */
	// 	kfree(ipfilog);		/* free entry */
	call_rcu(&ipfilog->rcuh, free_entry_rcu_call);
	loginfo_entry_counter--;
	spin_unlock_bh(&loginfo_list_lock); /* unlock */
}

/* updates timer of a loginfo entry, when a packet is already
 * present il packlist list. Invoked by packet_not_seen() when
 * it has seen this packet in list.
 * This is called with read lock held and bh interrupts disabled.
 * So timer expiring should not interfere.
 */
inline void update_loginfo_timer(struct ipfire_loginfo *iplo)
{
	/* kernel/timer.c says:
	 * Note that if there are multiple unserialized concurrent users of the
	 * same timer, then mod_timer() is the only safe way to modify the timeout,
	 * since add_timer() cannot modify an already running timer...
	 * So a read_lock_rcu() is enough, since mod_timer manages concurrent
	 * timer users.
	 */
	mod_timer(&iplo->timer_loginfo, jiffies + HZ * loginfo_lifetime);
}

inline void fill_timer_loginfo_entry(struct ipfire_loginfo *ipfilog)
{
	init_timer(&ipfilog->timer_loginfo);
	ipfilog->timer_loginfo.expires = jiffies + HZ * loginfo_lifetime;
	ipfilog->timer_loginfo.data = (unsigned long) ipfilog;
	ipfilog->timer_loginfo.function = handle_loginfo_entry_timeout;
}

/* copies a packet to info field of ipfire_loginfo, then initializes
 * timers and adds to packlist list */
inline int add_packet_to_infolist(const ipfire_info_t * info)
{
	struct ipfire_loginfo *ipli;
	ipli = (struct ipfire_loginfo *) kmalloc(sizeof(struct ipfire_loginfo), GFP_ATOMIC);
	memcpy(&ipli->info, info, sizeof(ipfire_info_t));
	/* removed position in ipfire-wall 2 */
// 	ipli->position = loginfo_entry_counter;
	spin_lock_bh(&loginfo_list_lock);
	fill_timer_loginfo_entry(ipli);
	/* add timer */
	add_timer(&ipli->timer_loginfo);
	/* add entry to root table */
	INIT_LIST_HEAD(&ipli->list);
	list_add_rcu(&ipli->list, &packlist.list);
	loginfo_entry_counter++;
	spin_unlock_bh(&loginfo_list_lock);
	return 0;
}

inline int iph_compare(const ipfire_info_t * p1, const ipfire_info_t * p2)
{
  struct iphdr iph1, iph2;
  iph1 = p1->iphead;
  iph2 = p2->iphead;
  return (iph1.saddr == iph2.saddr) && (iph1.daddr == iph2.daddr);
}

inline int tcph_compare(const ipfire_info_t * p1, const ipfire_info_t * p2)
{
  struct tcphdr tcph1, tcph2;
  tcph1 = p1->transport_header.tcphead;
  tcph2 = p2->transport_header.tcphead;
  return (tcph1.source == tcph2.source) &&
	(tcph1.dest == tcph2.dest) &&
	(tcph1.fin == tcph2.fin) &&
	(tcph1.syn == tcph2.syn) &&
	(tcph1.ack == tcph2.ack) &&
	(tcph1.urg == tcph2.urg) &&
	(tcph1.rst == tcph2.rst) &&  
	(tcph1.psh == tcph2.psh);
}

inline int udph_compare(const ipfire_info_t * p1, const ipfire_info_t * p2)
{
  struct udphdr udph1, udph2;
  udph1 = p1->transport_header.udphead;
  udph2 = p2->transport_header.udphead;
	return (udph1.source == udph2.source) &&
		(udph1.dest == udph2.dest);
}

inline int icmph_compare(const ipfire_info_t * p1, const ipfire_info_t * p2)
{
  struct icmphdr ich1, ich2;
  ich1 = p1->transport_header.icmphead;
  ich2 = p2->transport_header.icmphead;
  return (ich1.type == ich2.type) && (ich1.code == ich2.code);
	/*&
	(ich1->un.echo.id == ich2->un.echo.id) &&
	(ich1->un.echo.sequence == ich2->un.echo.sequence) &&
	(ich1->un.frag.mtu == ich2->un.frag.mtu) */
}


inline int igmph_compare(const ipfire_info_t * p1, const ipfire_info_t * p2)
{
  struct igmphdr igh1, igh2;
  igh1 = p1->transport_header.igmphead;
  igh2 = p2->transport_header.igmphead;
	return (igh1.type == igh2.type) && (igh1.code == igh2.code) && (igh1.group == igh2.group);
}


/* returns -1 if packets are different, 0 if equal.
 * Called by compare_loginfo_packets(), which in turn is called by packet_not_seen(), while a 
 * read_lock_bh is held and p1 and p2 being kmallocated areas.
 */
int comp_pack(const ipfire_info_t * p1, const ipfire_info_t * p2)
{
	int ret;
	if (p1->protocol != p2->protocol)
		return -1;

	if (p1->st.state != p2->st.state)
		return -1;

	if ((p1->direction != p2->direction) || (p1->nat != p2->nat) || (p1->snat != p2->snat) || (p1->state != p2->state) ) 
		return -1;

	/* Compare responses */
	ret =  p1->response * p2->response;
	/* p1 has negative response and p2 has positive response
	 * or vice-versa 
	 */
	if(ret < 0) /* responses differ in sign */
		return -1;
	/* at least one of the two is 0 */	
	else if(ret == 0) 
	{
		if( (p1->response & p2->response) != 0 ) /* One of the two is nonzero */
			return -1;
		/* else they are both 0 and we can go on */	
	}
	/* else if the product result is positive, they are both positive or negative responses */

	if (strcmp(p1->devpar.in_devname, p2->devpar.in_devname))
		return -1;
	if (strcmp(p1->devpar.out_devname, p2->devpar.out_devname))
		return -1;
#ifdef ENABLE_RULENAME
	if (strcmp(p1->rulename, p2->rulename))
		return -1;
#endif

	/* ip header fields */
	if (!iph_compare(p1, p2))
		return -1;
	switch (p1->protocol)
	{
		case IPPROTO_TCP:
			if (!tcph_compare(p1, p2))
				return -1;
			break;
		case IPPROTO_UDP:
			if (!udph_compare(p1, p2))
				return -1;
			break;
		case IPPROTO_ICMP:
			if (!icmph_compare(p1, p2))
				return -1;
			break;
		case IPPROTO_IGMP:
			if (!igmph_compare(p1, p2))
				return -1;
			break;
		case IPPROTO_GRE:
		case IPPROTO_PIM:
			/* comparison is limited to the checks above, no GRE header comparison is done, no PIM info inspected */
			break;
		default:
			printk("IPFIRE: ipfi_log.c: comp_pack(): unsupported protocol %d.\n", p1->protocol);
	}
	return 0;
}

/* compares two packets in the shape of ipfire_info_t. All
 * fields are compared, except packet_id, the last one.
 * Called by packet_not_seen(), it executes inside a read_lock 
 * and packet1 and packet2 live in a kmallocated area.
 */
inline int compare_loginfo_packets(const ipfire_info_t * packet1,
		const ipfire_info_t * packet2)
{
	if (comp_pack(packet1, packet2) == 0)
		return 1;	/* success in comparison */
	/* comp_pack has returned -1, that is failure */
	return 0;
}

/* returns 1 if packet has never been seen,
 * 0 otherwise. If a packet is already in list, 
 * its timer is updated.
 * We do not update the timer, since every timeout
 * seconds we want the packet to be re printed.
 */
inline int packet_not_seen(const ipfire_info_t * packet, int chk_state)
{
	struct ipfire_loginfo *loginfo;
	rcu_read_lock_bh();
	list_for_each_entry_rcu(loginfo, &packlist.list, list)
	{
		/* NOTE: here loginfo is a pointer to dynamic memory. &loginfo->info points to an 
		 * area pertaining to loginfo, so we can pass it through subsequent calls 
		 * without losing it. Moreover, we are inside a lock.
		 */
		if (compare_loginfo_packets(packet, &loginfo->info))
		{
			if( (chk_state && (packet->st.state == loginfo->info.st.state) )
				|| !chk_state)
			{
				rcu_read_unlock_bh();
				return 0;	/* packet in list: already seen */
			}
		}
	}
	rcu_read_unlock_bh();
	return 1;
}

/* Invoked when loglevel is 1, this function compares
 * packet with all other packets seen. If a packet has
 * already been seen, it's not logged and nothing is 
 * done, if it is the first packet, it is added to list of seen
 * packets and 1 is return, as to indicate that packet 
 * must be logged to userspace. This "smart logging"
 * reduces load in userspace communication via netlink
 * socket. Must return 0 if match is found.
 */
int smart_log(const ipfire_info_t * info)
{
	if (packet_not_seen(info, 0))
	{
		add_packet_to_infolist(info);
		return 1;
	}
	return 0;
}

/* This is registered when the log level is MART_LOG_WITH_STATE_CHECK.
 * Applies all the same procedures as the one above, but also
 * does checks against the state.
 */
int smart_log_with_state_check(const ipfire_info_t* info)
{
	if (packet_not_seen(info, 1))
	{
		add_packet_to_infolist(info);
		return 1;
	}
	return 0;
}

int free_loginfo_entries(void)
{
	struct list_head *pos;
	struct list_head *q;
	struct ipfire_loginfo *ilo;
	int counter = 0;
	spin_lock_bh(&loginfo_list_lock);
	list_for_each_safe(pos, q, &packlist.list)
	{
		ilo = list_entry(pos, struct ipfire_loginfo, list);
		if(del_timer(&ilo->timer_loginfo) )
		{
			/* Invoke the call_rcu() to free the log table.
			 * So we must remember to call rcu_barrier() before
			 * leaving the exit function (see fini() ).
			 */
			list_del_rcu(&ilo->list);	/* delete from list */
			call_rcu(&ilo->rcuh, free_entry_rcu_call);
			counter++;
			loginfo_entry_counter--;
		}
		else
			printk("log info entry already expired!\n");	
	}
	spin_unlock_bh(&loginfo_list_lock);
	return counter;
}

//static int __init init(void)
int init_log(void)
{
	/* initialize loginfo list */
	INIT_LIST_HEAD(&packlist.list);
	return 0;
}

//static void __exit fini(void)
void fini_log(void)
{
	int ret;
	ret = free_loginfo_entries();
	printk("IPFIRE: log entries freed: %d.\n", ret);
	/* might_sleep(): see linux kernel sources/include/linux.h:
	 * this is a macro which will print a stack trace if it is executed in an atomic
	 * context (spinlock, irq-handler, ...).
	 *
	 * This is a useful debugging help to be able to catch problems early and not
	 * be biten later when the calling function happens to sleep when it is not
	 * supposed to.
	 */

	/* See the important comments on ipfi_machine.c fini() */
	might_sleep(); 
	/* free_state_tables() calls the timeout handler which
	 * schedules the rcu callback. We must wait until all
	 * the callbacks which free the state tables end.
	 */ 
	/**
	 * rcu_barrier - Wait until all the in-flight RCUs are complete.
	 * see linux kernel sources/kernel/rcupdate.c
	 */
	rcu_barrier();
}

MODULE_DESCRIPTION("IPFIRE smart logging module");
MODULE_AUTHOR("Giacomo S. <jacum@libero.it>");
MODULE_LICENSE("GPL");


