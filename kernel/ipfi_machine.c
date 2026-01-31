/* ip firewall Giacomo S. - IPFI MACHINE - */
/* Tracking of connections marked as stateful and main filtering activity. 
*/
 
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

#include <linux/module.h>
#include <linux/list.h>
#include "includes/ipfi.h"
#include "includes/ipfi_netl.h"
#include "includes/ipfi_machine.h"
#include "includes/ipfi_netl_packet_builder.h"
#include "includes/ipfi_mangle.h"
#include "includes/ipfi_state_machine.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

/* To tell lookup_.._and_update_timer if locking is needed or not */
#define NOLOCK 			0
#define ACQUIRE_LOCK		1

#define SECS 	1
#define MINS	(SECS * 60)
#define HOURS  	(MINS * 60)
#define DAYS	(HOURS * 24)

short do_keep_state = 1;
struct state_table root_state_table;

int we_are_exiting = 0;

short found_in_state_table;

/* TCP, UDP and ICMP timeouts. These are the defaults, they 
* can be changed by means of the configuration files by the root user
*/
unsigned int syn_lifetime = 2 * MINS;
unsigned int synack_lifetime = 60 * SECS;
unsigned int est_lifetime = 5 * DAYS;
unsigned int close_wait_lifetime = 60 * SECS;
unsigned int fin_wait_lifetime = 2 * MINS;
unsigned int last_ack_lifetime =  30 * SECS;
unsigned int time_wait_lifetime = 2 * MINS;
unsigned int close_lifetime = 10 * SECS;
unsigned int udp_new_lifetime = 30 * SECS;
unsigned int udp_lifetime = 180 * SECS;
unsigned int icmp_lifetime = 180 * SECS;
unsigned int igmp_lifetime = 180 * SECS;
unsigned int l3generic_proto_lifetime = 180 * SECS;
/* End of timeout definitions */

/* TO REMOVE */
unsigned int setup_shutd_state_lifetime = 120;
unsigned int state_lifetime = 5 * DAYS;


unsigned int table_id = 0;
unsigned int state_tables_counter = 0;

/* max number of connection tables allowed */
unsigned max_state_entries;

/* spin lock for elements in linked lists */
spinlock_t state_list_lock;

int direct_state_match(const ipfire_info_t * packet, const struct state_table *entry)
{
	switch (packet->protocol)
	{
		case IPPROTO_TCP:
			if(entry->ftp == FTP_DEFINED) /* ftp support: don't care on source port */
			{
				if(packet->transport_header.tcphead.dest == entry->dport)
					return 1;
			}
			if((packet->transport_header.tcphead.source == entry->sport) 	&& 
			  (packet->transport_header.tcphead.dest == entry->dport) 	&&
			  (packet->iphead.saddr == entry->saddr) 			&&
			  (packet->iphead.daddr == entry->daddr) 			&&
			  (strcmp(packet->devpar.in_devname, entry->in_devname) == 0) 	&&
			  (strcmp(packet->devpar.out_devname, entry->out_devname) == 0))
				return 1;
			break;
		case IPPROTO_UDP:
			if((packet->transport_header.udphead.source == entry->sport) 	&& 
			  (packet->transport_header.udphead.dest == entry->dport) 	&&
			  (packet->iphead.saddr == entry->saddr) 			&&
			  (packet->iphead.daddr == entry->daddr) 			&&
			  (strcmp(packet->devpar.in_devname, entry->in_devname) == 0) 	&&
			  (strcmp(packet->devpar.out_devname, entry->out_devname) == 0))
				return 1;
			break;
		/* ICMP and IGMP treated in l2l3match() */
	}
	return -1;
}

int reverse_state_match(const ipfire_info_t * packet,
		const struct state_table *entry)
{
	/* switch protocol type */
	switch (packet->protocol)
	{
		case IPPROTO_TCP:
			if((packet->transport_header.tcphead.source == entry->dport) 	&& 
			  (packet->transport_header.tcphead.dest == entry->sport)	&&
			  (packet->iphead.saddr == entry->daddr) 			&& 
			  (packet->iphead.daddr == entry->saddr) 			&&
			  (strcmp(packet->devpar.in_devname, entry->out_devname) == 0) 	&&
			  (strcmp(packet->devpar.out_devname, entry->in_devname) == 0))
				return 1;
			break;
		case IPPROTO_UDP:
			if((packet->transport_header.udphead.source == entry->dport) 	&& 
			  (packet->transport_header.udphead.dest == entry->sport)	&&
			  (packet->iphead.saddr == entry->daddr) 			&& 
			  (packet->iphead.daddr == entry->saddr) 			&&
			  (strcmp(packet->devpar.in_devname, entry->out_devname) == 0) 	&&
			  (strcmp(packet->devpar.out_devname, entry->in_devname) == 0))
				return 1;
			break;
		/* ICMP and IGMP treated in l2l3match() */
	}
	return -1;
}

/* matches network interface (l2) and ip addresses (l3) only.
 */
inline int l2l3match(const ipfire_info_t * packet, const struct state_table *entry)
{
   /* direct match: packet source == entry source and packet dest == entry dest 
    * and packet input iface == entry input iface 
    */
    if((packet->iphead.saddr == entry->saddr && packet->iphead.daddr == entry->daddr &&
	strcmp(packet->devpar.in_devname, entry->in_devname) == 0 && 
	strcmp(packet->devpar.out_devname, entry->out_devname) == 0)
      || /* reverse match, for the packet coming back */
      (packet->iphead.saddr == entry->daddr && packet->iphead.daddr == entry->saddr &&
       strcmp(packet->devpar.in_devname, entry->out_devname) == 0 &&
       strcmp(packet->devpar.out_devname, entry->in_devname) == 0 ) )
       return 1;
    else
      return -1;
}

int state_match(const ipfire_info_t * packet, const struct state_table *entry,
		short *reverse)
{
	short tr_match = 0;
	*reverse = -1;		/* negative means no match */

	/* First of all: check the protocol */
	if (packet->protocol != entry->protocol)
		return -1;

	/* ICMP and IGMP state machine inspects only ip addresses and so treat
	 * these protocols first of all.
	 */
	if(packet->protocol == IPPROTO_ICMP || packet->protocol == IPPROTO_IGMP || 
	  packet->protocol == IPPROTO_GRE || packet->protocol == IPPROTO_PIM)
		return l2l3match(packet, entry);
	
	if ((tr_match = direct_state_match(packet, entry)) > 0)
		*reverse = 0;
	else if ((tr_match = reverse_state_match(packet, entry)) > 0)
		*reverse = 1;

	if (packet->direction == IPFI_FWD)
		return tr_match; /* +1 or -1, returned by direct/reverse state_match */

	/* input or output directions */
	/* if the direction of the packet is the same, then direct_state_match must have had success */
	if (packet->direction == entry->direction && *reverse == 0)
	  return tr_match; /* sure it is 1 if *reverse == 0, anyway... */
	  
	/* if the direction of the packet is different, then reverse_state_match must have had success */
	else if (packet->direction != entry->direction && *reverse == 1)
	  return tr_match;
	/* direct/reverse_state_match() failed, *reverse remained initialized to -1 */
	return -1;
}

#ifdef ENABLE_RULENAME
/* copies rulename field from state table to packet */
inline void fill_packet_with_table_rulename(ipfire_info_t * packet,
		const struct state_table *stt)
{
	if (strlen(stt->rulename) > 0)
	{
		strncpy(packet->rulename, stt->rulename, RULENAMELEN);
	}
}
#endif

/* Callback function for freeing RCU elements. */
void free_state_entry_rcu_call(struct rcu_head *head)
{
	struct state_table* ipst = NULL;
	if(head == NULL)
	{
		IPFI_PRINTK("Callback: head is null.\n");
		return;
	}
	ipst = container_of(head, struct state_table, state_rcuh);
	if(ipst != NULL)
	{
	  if(ipst->pkmanip != NULL)
	  {
	    kfree(ipst->pkmanip);
	  }
	  /* free state table */
	  kfree(ipst);
	}
}

/* This function decides which is the timeout according to the protocol 
* of the packet and to its state.
*/
inline unsigned int get_timeout_by_state(int protocol, int state)
{
	unsigned int timeout = close_lifetime;

	/* Since version 0.98.2 the timeout is specific to the connection state */
	if(protocol == IPPROTO_TCP)
	{
		//IPFI_PRINTK("*TCP: ");
		switch(state)
		{
			case ESTABLISHED:
			case GUESS_ESTABLISHED:
			  timeout = est_lifetime;
			  break;
			case SYN_RECV:
			case GUESS_SYN_RECV:
				timeout = synack_lifetime;
				break;
			case SYN_SENT:
			/* FTP_NEW: before an ftp data connection is set up a control packet tells the client
			 * the port to connect to. Just after this control packet, the new ftp data connection
			 * starts data transfer. It can be assumed that the correct timeout is the same of the 
			 * syn sent state.
			 */
			case FTP_NEW:
				timeout = syn_lifetime;
				break;
			case CLOSE_WAIT:
				timeout = close_wait_lifetime;
				break;
			case IPFI_TIME_WAIT:
				timeout = time_wait_lifetime;
				break;
			case LAST_ACK:
				timeout = last_ack_lifetime;
				break;
			case FIN_WAIT:
				timeout = fin_wait_lifetime;
				break;
			case CLOSED:
			case GUESS_CLOSING:
			default:
				timeout = close_lifetime;
				break;	
		}
	}
	else if(protocol == IPPROTO_UDP)
	{
		//IPFI_PRINTK("*UDP: ");
		switch(state)
		{
			case UDP_ESTAB:
				timeout = udp_lifetime;
				break;

			case UDP_NEW:
			default:
				timeout = udp_new_lifetime;
				break;
		}
	}
	else if(protocol == IPPROTO_ICMP || protocol == IPPROTO_IGMP || 
	  protocol == IPPROTO_GRE || protocol == IPPROTO_PIM)
	{
		timeout = l3generic_proto_lifetime;
	}
	else
	{
	  printk("unsupported protocol: returning 0\n");
	  timeout = 0;
	}
	/* A different protocol... return after a close_time interval */
	//IPFI_PRINTK("  timeout: %u.\n", timeout);
	return timeout;

}

/* This function updates the timer of the entry passed as argument.
* It is supposed that it has been called in a safe context, i.e. 
* with a lock held and with sw interrupts disabled, so that it does
* not get interrupted by the timeout routine, or have in any way
* deleted the object it operates on.
*/ 
inline void update_timer_of_state_entry(struct state_table *sttable)
{
	unsigned int timeout = get_timeout_by_state(sttable->protocol, sttable->state.state);

	/* Modify the timer for TCP, UDP or ICMP tables */
	mod_timer(&sttable->timer_statelist,
			jiffies + HZ * timeout);
}

int check_state(ipfire_info_t * packet, struct sk_buff* skb)
{
// 	struct list_head *pos;
	struct state_table *table_entry=NULL, *new_ftp_entry=NULL;
	int ret = 0;
	unsigned counter = 0;
	short *reverse = (short *)kmalloc(sizeof(short), GFP_ATOMIC);
	if(!reverse)
	  return -1;
	/* acquire read lock on list */
	rcu_read_lock_bh();
	list_for_each_entry_rcu(table_entry, &root_state_table.list, list)
	{
		counter++;
		ret = state_match(packet, table_entry, reverse);
		if (ret > 0) /* a match was found! */
		{		
#ifdef ENABLE_RULENAME
			fill_packet_with_table_rulename(packet, table_entry);
#endif
			packet->notify = table_entry->notify;  /* notify enabled? (v. 0.98.7) */
			/* should ipfire_info_t readers be interested (such as tcpmss mangler), set reverse flag */
			packet->reverse = *reverse;
			/* set the correct state of the connection */
			if (set_state(packet, table_entry, *reverse) < 0)
			{
				IPFI_PRINTK("IPFIRE: failed to set state for entry %d! Returning failure.\n", counter);
				rcu_read_unlock_bh();
				kfree(reverse);
				return -1;
			}
			/* packet manipulation */
			if(reverse && table_entry->pkmanip != NULL)
			{
			  if(mangle_skb(table_entry->pkmanip, skb, packet) < 0)
			    IPFI_PRINTK("IPFIRE: check_state(): failed to mangle socket buffer in reverse state match\n");
			}
			/* ftp protocol support */
			if( (table_entry->ftp == FTP_LOOK_FOR) && (table_entry->protocol == IPPROTO_TCP) )
			{
				/* before an ftp data connection is set up a control packet tells the client
				 * the port to connect to. Just after this control packet, the new ftp data connection
				 * starts data transfer. ftp_support() returns not null only if the ftp control packet 
				 * contains ftp data parameters.
				 */ 
				new_ftp_entry = ftp_support(table_entry, skb, packet);   
				if(new_ftp_entry != NULL)
				{
					/* Lock on rcu list is already acquired */
					if (lookup_state_table_n_update_timer(new_ftp_entry, 
								NOLOCK) != NULL)
					{
						kfree(new_ftp_entry);
					}
					else
					{
						/* simply add the new rule into the list. Between our hands 
						* we have the handshake ftp packet, which must be treated
						* as any other packet which is to be filtered */
						add_ftp_dynamic_rule(new_ftp_entry);
						/* the function above initiates timer and state for the new entry,
						* and adds it to the list. If a new connection to ftp data will be 
						* started, it will find the new ftp entry ready! */
					}
				}
			}
			else if(table_entry->ftp == FTP_DEFINED)
			{
				table_entry->ftp = FTP_ESTABLISHED;
				/* correct source port after first packet seen */
				table_entry->sport = packet->transport_header.tcphead.source;
			}
			/* update timer for table_entry, while holding the read lock. */
			update_timer_of_state_entry(table_entry);
			rcu_read_unlock_bh();
			/* Since version 0.98.5 we return the originating rule, so it is easier to
			* compare the result with the rules inserted. With F5 it will be easy to
			* find out also the position of the state table in the list, if one was interested.
			*/
			kfree(reverse);
			return table_entry->originating_rule;
		} /* if(ret > 0) */
	}
	/* no match in any table entry */
	rcu_read_unlock_bh();
	kfree(reverse);
	return -1;
}

#ifdef ENABLE_RULENAME
/* copies rule name in packet if it is specified in rule */
inline void fill_packet_with_name(ipfire_info_t * packet,
		const ipfire_rule * r)
{
	if (r->rulename != 0)
	{
		strncpy(packet->rulename, r->rulename, RULENAMELEN);
	}
}
#endif

inline int direction_filter(const ipfire_info_t * packet,
		const ipfire_rule * r)
{
	if (r->nflags.direction)
	{
		if (r->direction != packet->direction)
			return -1;
		return 1;
	}
	return 0;
}

/* main filtering function: compares packet with each denial and 
*permission rule. Returns < 0 if a denial rule is found matching 
* packet, > 0 if a permission rule matche packet, 0 if no explicit
* rule is found. If a match is found, copies rulename from rule
* to rulename field of packet, just to add info for user. 
*/
	int
ipfire_filter(ipfire_info_t * packet,
		const ipfire_rule *dropped,
		const ipfire_rule *allowed,
		const struct ipfire_options *ipfi_opts,
		struct sk_buff* skb)
{
	unsigned i = 0;
// 	struct list_head *pos;
	ipfire_rule *rule;	
	short pass;
	short res;		/* partial result */
	short drop = 0;
	struct state_table* newtable = NULL;
	found_in_state_table = 0;


	/* check in connection state table first, if direction is INPUT or POST, for now... */
	if ((packet->direction == IPFI_INPUT)
			|| (packet->direction == IPFI_OUTPUT)
			|| (packet->direction == IPFI_FWD))
	{
		if ((pass = check_state(packet, skb)) > 0)
		{		/* we have found an already seen flow */
			/* if a match is found, check_state() invokes 
			* fill_packet_with_table_ rulename() to copy
			* the name of the rule to packet */
			found_in_state_table = 1;
			return pass;
		}
	}

	/* start with denial rules */
	rcu_read_lock(); /* read only lock */
	list_for_each_entry_rcu(rule, &dropped->list, list)
	{
		/* get the address of the rule */
		/* direction match */
		if ((res = direction_filter(packet, rule)) < 0)
			goto next_drop_rule;
		else if (res > 0)
			drop = 1;

		/* device match */
		if ((res = device_filter(packet, rule)) < 0)
			goto next_drop_rule;
		else if (res > 0)
			drop = 1;
		/* check if the rule contains ip fields. If yes, they must be verified */
		/* if packet does not match explicitly the fields of the rule, we
		* can return failure without going on.
		* Otherwise, if we can't say anything (e.g. because there are no
		* ip parameters specified in a rule) or if the ip layer parameters
		* do match, we have to go on looking at the transport layer fields
		*/
		if ((res = ip_layer_filter(packet, rule)) < 0)
			goto next_drop_rule;
		else if (res > 0)
			drop = 1;	/* if res = 0 leave pass unchanged */
		/* divide computation by protocol type */
		if (packet->protocol == IPPROTO_TCP)
		{
			if ((res = ipfi_tcp_filter(packet, rule)) < 0)
				goto next_drop_rule;
			else if (res > 0)
				drop = 1;
		} 
		else if (packet->protocol == IPPROTO_UDP)
		{
			if ((res = udp_filter(packet, rule)) < 0)
				goto next_drop_rule;
			else if (res > 0)
				drop = 1;
		} 
		else if (packet->protocol == IPPROTO_ICMP)
		{
			if ((res = icmp_filter(packet, rule)) < 0)
				goto next_drop_rule;
			else if (res > 0)
				drop = 1;
		}
		else if (packet->protocol == IPPROTO_IGMP)
		{
			/* do not touch res: for proto IGMP we do not evaluate anything
			* except the ip_layer
			*/
		}
		if (drop > 0)
		{
			/* from v. 0.98.7, for the GUI notifier: if a packet is accepted
			* or dropped (it matches a rule), the user may desire to be 
			* notified.
			*/
			packet->notify = rule->notify;
			/* v. 0.98.5: packet_id reminds the position of the rule */
			packet->packet_id = rule->position;
#ifdef ENABLE_RULENAME
			fill_packet_with_name(packet, rule);
#endif
			/* Unlock RCU before returning  */
			rcu_read_unlock();
			/* Each rule has a unique "position": return it so that it is 
			* easier to recognize which rule affected the decision
			*/
			return -rule->position;
		}

next_drop_rule:
		i++;
	}
	i = 0;
	/* now check if the packet is explicitly allowed */
	pass = 0;
	list_for_each_entry_rcu(rule, &allowed->list, list)
	{
		/* get the address of the rule */
		/* direction match */
		if ((res = direction_filter(packet, rule)) < 0)
			goto next_pass_rule;
		else if (res > 0)
			pass = 1;
		/* device */
		if ((res = device_filter(packet, rule)) < 0)
			goto next_pass_rule;
		else if (res > 0)
			pass = 1;
		/* check ip layer fields */
		if ((res = ip_layer_filter(packet, rule)) < 0)
			goto next_pass_rule;
		else if (res > 0)
			pass = 1;
		/* divide computation by protocol type */
		if (packet->protocol == IPPROTO_TCP)
		{
			if ((res = ipfi_tcp_filter(packet, rule)) < 0)
				goto next_pass_rule;
			else if (res > 0)
				pass = 1;
		} 
		else if (packet->protocol == IPPROTO_UDP)
		{
			if ((res = udp_filter(packet, rule)) < 0)
				goto next_pass_rule;
			else if (res > 0)
				pass = 1;
		} 
		else if (packet->protocol == IPPROTO_ICMP)
		{
			if ((res = icmp_filter(packet, rule)) < 0)
				goto next_pass_rule;
			else if (res > 0)
				pass = 1;
		}
		else if (packet->protocol == IPPROTO_IGMP)
		{
			/* no checks are done for IGMP specific protocol */
		}
		if(pass > 0)
		{
			/* from v. 0.98.7, for the GUI notifier: if a packet is accepted
			* or dropped (it matches a rule), the user may desire to be 
			* notified.
			*/
			packet->notify = rule->notify;
			packet->packet_id = rule->position;
#ifdef ENABLE_RULENAME
			fill_packet_with_name(packet, rule);
#endif
		}	  
		/* to add to connection table, stateful must be enabled in rule 
		* AND in global options.
		* Moreover, packet must have been accepted by engine.
		* Flag all_stateful enables stateful tracking also for rules
		* which do not have flag state specified.
		*/
		if ((pass > 0) && ((rule->state) || (ipfi_opts->all_stateful)) && (ipfi_opts->state))
		{
			if ((packet->direction == IPFI_INPUT) || (packet->direction == IPFI_OUTPUT)
					|| (packet->direction == IPFI_FWD))
			{
				/* keep_state() returns not NULL if an entry is to be added.
				* keep_state() will call lookup_existing..() which holds
				* rcu_read_lock for state tables, but the rcu locks can be nested
				* (see keep_state() comments ). */
				newtable = keep_state(packet, rule);
			}
		}
		if (pass > 0)
		{
			/* Unlock before adding the entry and returning */
			rcu_read_unlock();
			if(newtable != NULL)
			{
				found_in_state_table = 1;
				/* Add the table to the list, without any lock hold */
				add_state_table_to_list(newtable);
			}
			/* maybe we want to manipulate the packet in this place. Up to now, MSS mangle is 
			 * supported. mangle_skb() returns < 0 in case of error, 0 if mangle not needed
			 * (or not suitable - for instance changing mss is suitable only for tcp syn packets -)
			 * > 0 if mangle is applied. rule is a pointer taken from the list of rules (global).
			 */
			if(mangle_skb(&rule->pkmangle, skb, packet) < 0)
			{
			  packet->manipinfo.pmanip.mss.error = 1;
			  IPFI_PRINTK("IPFIRE: mangle_skb() failed for rule \"%s\"\n", rule->rulename);
			}
			/* see the  comment in the 'drop' case above */
			return rule->position;
		}
next_pass_rule:
		i++;
	}
	/* Unlock rcu read lock */
	rcu_read_unlock();
	/* no explicit rules have been found: return 0 */
	return 0;
}

int device_filter(const ipfire_info_t * packet, const ipfire_rule * r)
{
	/* don't bother if user fills in output rule within input context
	* or viceversa */
	if (r->nflags.indev)
	{
		if (strcmp(packet->devpar.in_devname,
					r->devpar.in_devname) == 0)
			return 1;
		else
			return -1;
	}

	if (r->nflags.outdev)
	{
		if (strcmp(packet->devpar.out_devname,
					r->devpar.out_devname) == 0)
			return 1;
		else
			return -1;
	}
	return 0;
}

int address_match(const ipfire_info_t * packet, const ipfire_rule * r)
{
	int match = 0;
	int i, addr_in_list;
	__u32 source_address, p_source_address;
	__u32 dest_address, p_dest_address;

	/* source address */
	/* Set correct source and destination address: the one corresponding
	* to the interface in packet if MYADDR was specified, the dotted
	* decimal one if ADDR is specified in flags */
	if (r->nflags.src_addr == MYADDR)
	{
		if (get_ifaddr_by_info(packet, &p_source_address) < 0)
		{
		    return -1;
		}
		source_address = p_source_address;
	} 
	else
		source_address = r->ip.ipsrc[0];

	/* initialize addr_in list */
	addr_in_list = 0;
	/* a single ip is given: it must match exactly */
	if ((r->nflags.src_addr) && (r->parmean.samean == SINGLE))
	{
		if (source_address != packet->iphead.saddr)
			return -1;
		else
			match = 1;
	}
	/* an interval is given: src address in packet must be contained in it.
	* Addresses cannot be mine */
	else if ((r->nflags.src_addr == ONEADDR) && (r->parmean.samean == INTERVAL))
	{
		if ((ntohl(r->ip.ipsrc[0]) <= ntohl(packet->iphead.saddr)) && (ntohl(r->ip.ipsrc[1]) >=
			ntohl(packet->iphead.saddr)))
		{
			match = 1;
		} 
		else
			return -1;
	}
	/* address in packet must be different from address in rule */
	else if ((r->nflags.src_addr)
			&& (r->parmean.samean == DIFFERENT_FROM))
	{
		if (source_address != packet->iphead.saddr)
			match = 1;
		else
			return -1;
	}
	/* finally: src address in packet must be not included in rule source ip interval */
	else if ((r->nflags.src_addr == ONEADDR) && (r->parmean.samean == INTERVAL_DIFFERENT_FROM))
	{
		if ((ntohl(r->ip.ipsrc[0]) <= ntohl(packet->iphead.saddr)) && (ntohl(r->ip.ipsrc[1]) >=
				ntohl(packet->iphead.saddr)))
			return -1;
		else		/* saddr of iphead not contained: ok */
			match = 1;
	}
	else if ((r->nflags.src_addr == ONEADDR) && (r->parmean.samean == MULTI))
	{
	  for(i = 0; i < MAXMULTILEN && r->ip.ipsrc[i] != 0; i++)
	  {
	    if(r->ip.ipsrc[i] == packet->iphead.saddr)
	    {
	      addr_in_list = 1;
	      break; /* no need to go further on */
	    }
	  }
	  if(addr_in_list == 1)
	    match = 1;
	  else
	    return -1;
	}
	else if ((r->nflags.src_addr == ONEADDR) && (r->parmean.samean == MULTI_DIFFERENT))
	{
	  match = 1; /* suppose packet->iphead.saddr is different from any element of the list */
	  for(i = 0; i < MAXMULTILEN && r->ip.ipsrc[i] != 0; i++)
	  {
	    if(r->ip.ipsrc[i] == packet->iphead.saddr) /* one element of the list matches */
	      return -1; /* then if one element matches source address, we must leave */
	  }
	}
	/* destination address */
	if (r->nflags.dst_addr == MYADDR)
	{
		if (get_ifaddr_by_info(packet, &p_dest_address) < 0)
		{
		  return -1;
		}
		dest_address = p_dest_address;
	} 
	else
		dest_address = r->ip.ipdst[0];

	if ((r->nflags.dst_addr > 0) && (r->parmean.damean == SINGLE))
	{
		if (dest_address != packet->iphead.daddr)
			return -1;
		else
			match = 1;
	} 
	else if ((r->nflags.dst_addr == ONEADDR) && (r->parmean.damean == INTERVAL))
	{
		if ((ntohl(r->ip.ipdst[0]) <= ntohl(packet->iphead.daddr)) && (ntohl(r->ip.ipdst[1]) >=
			ntohl(packet->iphead.daddr)))
			match = 1;
		else
			return -1;

	} 
	else if ((r->nflags.dst_addr > 0) && (r->parmean.damean == DIFFERENT_FROM))
	{
		if (dest_address != packet->iphead.daddr)
			match = 1;
		else
			return -1;
	}
	else if ((r->nflags.dst_addr == ONEADDR) && (r->parmean.damean == INTERVAL_DIFFERENT_FROM))
	{
		if ((ntohl(r->ip.ipdst[0]) <= ntohl(packet->iphead.daddr)) && (ntohl(r->ip.ipdst[1]) >=
			ntohl(packet->iphead.daddr)))
			return -1;
		else
			match = 1;
	}
	/* list of IP addresses */
	else if ((r->nflags.dst_addr == ONEADDR) && (r->parmean.damean == MULTI))
	{
	  /* re initialize addr_in list before parsing destination address */
	  addr_in_list = 0;
	  for(i = 0; i < MAXMULTILEN && r->ip.ipdst[i] != 0; i++)
	  {
	    if(r->ip.ipdst[i] == packet->iphead.daddr)
	    {
	      addr_in_list = 1;
	      break; /* no need to go further on */
	    }
	  }
	  if(addr_in_list == 1)
	    match = 1;
	  else
	    return -1;
	}
	else if ((r->nflags.dst_addr == ONEADDR) && (r->parmean.damean == MULTI_DIFFERENT))
	{
	  match = 1; /* suppose packet->iphead.daddr is different from any element of the list */
	  for(i = 0; i < MAXMULTILEN && r->ip.ipdst[i] != 0; i++)
	  {
	    if(r->ip.ipdst[i] == packet->iphead.daddr) /* one element of the list matches */
	      return -1; /* then if one element matches destination address, we must leave with -1 */
	  }
	}
	return match;
}

int port_match(const ipfire_info_t * packet, const ipfire_rule * r,
		short protocol)
{
	int match = 0, sport_found = 0, dport_found = 0;
	int i;
	u16 sport;
	u16 dport;
	switch (protocol)
	{
		case IPPROTO_TCP:
			sport = packet->transport_header.tcphead.source;
			dport = packet->transport_header.tcphead.dest;
			break;
		case IPPROTO_UDP:
			sport = packet->transport_header.udphead.source;
			dport = packet->transport_header.udphead.dest;
			break;
		default:
			IPFI_PRINTK("IPFIRE: port_match(): invalid protocol %d!\n",
					protocol);
			return -1;
			break;
	}
	/* source port */
	/* a single port is given: it must match exactly */
	if ((r->nflags.src_port) && (r->parmean.spmean == SINGLE))
	{
		if (r->tp.sport[0] != sport)
			return -1;
		else
			match = 1;
	}
	/* an interval is given: src port in packet must be contained in it */
	else if ((r->nflags.src_port) && (r->parmean.spmean == INTERVAL))
	{
		if ((ntohs(r->tp.sport[0]) <= ntohs(sport)) &&
				(ntohs(r->tp.sport[1]) >= ntohs(sport)))
			match = 1;
		else
			return -1;
	}
	/* port in packet must be different from port in rule */
	else if ((r->nflags.src_port) && (r->parmean.spmean == DIFFERENT_FROM))
	{
		if (r->tp.sport[0] != sport)
			match = 1;
		else
			return -1;
	}
	/* port must not be inside rule interval */
	else if ((r->nflags.src_port) && (r->parmean.spmean == INTERVAL_DIFFERENT_FROM))
	{
		if ((ntohs(r->tp.sport[0]) <= ntohs(sport))
				&& (ntohs(r->tp.sport[1]) >= ntohs(sport)))
			return -1;
		else
			match = 1;
	}
	/* a list of ports to check */
	else if ((r->nflags.src_port) && (r->parmean.spmean == MULTI))
	{
	  for(i = 0; i < MAXMULTILEN; i++)
	  {
	    /* if one element is zero, leave */
	    if(r->tp.sport[i] == 0)
	      break;
	    if(ntohs(r->tp.sport[i]) == ntohs(sport)) /* one element matches */
	    {
	      sport_found = 1;
	      break;
	    }
	  }
	  if(sport_found == 1) /* found a matching port */
	    match = 1;
	  else
	    return -1;
	}
	else if ((r->nflags.src_port) && (r->parmean.spmean == MULTI_DIFFERENT))
	{
	  for(i = 0; i < MAXMULTILEN; i++)
	  {
	    /* if one element is zero, leave */
	    if(r->tp.sport[i] == 0)
	      break;
	    if(ntohs(r->tp.sport[i]) == ntohs(sport)) /* one element matches, the check fails */
	      return -1;
	  }
	  /* We have left the cycle without returning, so the match is positive */
	  match = 1;
	}
	/* destination port */
	if ((r->nflags.dst_port) && (r->parmean.dpmean == SINGLE))
	{
		if (r->tp.dport[0] != dport)
			return -1;
		else
			match = 1;
	} 
	else if ((r->nflags.dst_port) && (r->parmean.dpmean == INTERVAL))
	{
		if ((ntohs(r->tp.dport[0]) <= ntohs(dport)) &&
				(ntohs(r->tp.dport[1]) >= ntohs(dport)))
			match = 1;
		else
			return -1;
	} 
	else if ((r->nflags.dst_port) && (r->parmean.dpmean == DIFFERENT_FROM))
	{
		if (r->tp.dport[0] != dport)
			match = 1;
		else
			return -1;
	} 
	else if ((r->nflags.dst_port) && (r->parmean.dpmean == INTERVAL_DIFFERENT_FROM))
	{
		if ((ntohs(r->tp.dport[0]) <= ntohs(dport))
				&& (ntohs(r->tp.dport[1]) >= ntohs(dport)))
			return -1;
		else
			match = 1;
	}
	/* a list of (destination) ports to check */
	else if ((r->nflags.dst_port) && (r->parmean.dpmean == MULTI))
	{
	  for(i = 0; i < MAXMULTILEN; i++)
	  {
	    /* if one element is zero, leave */
	    if(r->tp.dport[i] == 0)
	      break;
	    if(ntohs(r->tp.dport[i]) == ntohs(dport)) /* one element matches */
	    {
	      dport_found = 1;
	      break;
	    }
	  }
	  if(dport_found == 1) /* found a matching port */
	    match = 1;
	  else
	    return -1;
	}
	else if ((r->nflags.dst_port) && (r->parmean.dpmean == MULTI_DIFFERENT))
	{
	  for(i = 0; i < MAXMULTILEN; i++)
	  {
	    /* if one element is zero, leave */
	    if(r->tp.dport[i] == 0)
	      break;
	    if(ntohs(r->tp.dport[i]) == ntohs(dport)) /* one element matches, the check fails */
	      return -1;
	  }
	  /* We have left the cycle without returning, so the match is positive */
	  match = 1;
	}
	
	return match;
}


int ip_layer_filter(const ipfire_info_t * packet, const ipfire_rule * r)
{
	int match = 0;

	if ((match = address_match(packet, r)) < 0)
	{
		return -1;
	}

	if (r->nflags.proto)
	{
		if (r->ip.protocol != packet->iphead.protocol)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.tot_len)
	{
		if (r->ip.total_length != packet->iphead.tot_len)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.tos)
	{
		if (r->ip.tos != packet->iphead.tos)
			return -1;
		else
			match = 1;
	}
	return match;
}

int ipfi_tcp_filter(const ipfire_info_t * tcp_pack, const ipfire_rule * r)
{
	int match = 0;
	/* check tcp specific fields */
	if ((match = port_match(tcp_pack, r, IPPROTO_TCP)) < 0)
	{
		//              IPFI_PRINTK("FAILED PORT MATCH!\n");
		return -1;
	}
	//      IPFI_PRINTK("AFTER PORT: match = %d\n", match);
	if (r->nflags.fin)
	{
		if (r->tp.fin != tcp_pack->transport_header.tcphead.fin)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.syn)
	{
		if (r->tp.syn != tcp_pack->transport_header.tcphead.syn)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.rst)
	{
		if (r->tp.rst != tcp_pack->transport_header.tcphead.rst)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.psh)
	{
		if (r->tp.psh != tcp_pack->transport_header.tcphead.psh)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.ack)
	{
		if (r->tp.ack != tcp_pack->transport_header.tcphead.ack)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.urg)
	{
		if (r->tp.urg != tcp_pack->transport_header.tcphead.urg)
			return -1;
		else
			match = 1;
	}
	return match;
}

int udp_filter(const ipfire_info_t * udp_pack, const ipfire_rule * r)
{
	int match = 0;
	/* check tcp specific fields */
	if ((match = port_match(udp_pack, r, IPPROTO_UDP)) < 0)
		return -1;
	return match;
}

int icmp_filter(const ipfire_info_t * icmp_pack, const ipfire_rule * r)
{
	int match = 0;
	/* icmp specific fields */
	if (r->nflags.icmp_type)
	{
		if (r->icmp_p.type !=
				icmp_pack->transport_header.icmphead.type)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.icmp_code)
	{
		if (r->icmp_p.code !=
				icmp_pack->transport_header.icmphead.code)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.icmp_echo_id)
	{
		if (r->icmp_p.echo_id !=
				icmp_pack->transport_header.icmphead.un.echo.id)
			return -1;
		else
			match = 1;
	}
	if (r->nflags.icmp_echo_seq)
	{
		if (r->icmp_p.echo_seq !=
				icmp_pack->transport_header.icmphead.un.echo.
				sequence)
			return -1;
		else
			match = 1;
	}
	/* disabled icmp_frag_mtu. */
	return match;
}

/* fills in state table with network informations */
int fill_net_table_fields(struct state_table *state_t,
		const ipfire_info_t * packet)
{
	state_t->protocol = packet->iphead.protocol;
	state_t->saddr = packet->iphead.saddr;
	state_t->daddr = packet->iphead.daddr;
	/* take the correct values by protocol */
	switch (packet->iphead.protocol)
	{
		case IPPROTO_TCP:
			state_t->sport = packet->transport_header.tcphead.source;
			state_t->dport = packet->transport_header.tcphead.dest;
			break;
		case IPPROTO_UDP:
			state_t->sport = packet->transport_header.udphead.source;
			state_t->dport = packet->transport_header.udphead.dest;
			break;
		case IPPROTO_ICMP:
		case IPPROTO_IGMP: /* treated as ICMP */
		case IPPROTO_GRE:
		case IPPROTO_PIM:
			state_t->sport = 0;
			state_t->dport = 0;
			break;
		default:
			printk
				("IPFIRE: fill_net_table_fields (stateful connection): invalid protocol %d!\n",
				packet->iphead.protocol);
			return -1;
			break;
	}
	state_t->direction = packet->direction;
	state_t->protocol = packet->iphead.protocol;
	strncpy(state_t->in_devname, packet->devpar.in_devname, IFNAMSIZ);
	strncpy(state_t->out_devname, packet->devpar.out_devname,
			IFNAMSIZ);
	return 0;
}

void fill_timer_table_fields(struct state_table *state_t)
{
	long int expi;
	expi = get_timeout_by_state(state_t->protocol, state_t->state.state);

	timer_setup(&state_t->timer_statelist, handle_keep_state_timeout, 0);
	state_t->timer_statelist.expires = jiffies + expi * HZ;
}

#ifdef ENABLE_RULENAME
/* copies rulename from packet to state table */
inline void fill_table_with_name(struct state_table *state_t,
		const ipfire_info_t * packet)
{
	if (packet->rulename[0] != '\0')
	{
		strncpy(state_t->rulename, packet->rulename,
				RULENAMELEN);
	}
}
#endif

/* compares two state table entries */
int compare_state_entries(const struct state_table *s1,
		const struct state_table *s2)
{
	return (s1->saddr == s2->saddr) &&
		(s1->daddr == s2->daddr) &&
		(s1->sport == s2->sport) &&
		(s1->dport == s2->dport) &&
		(s1->direction == s2->direction) &&
		(s1->protocol == s2->protocol) &&
		(!strcmp(s1->in_devname, s2->in_devname)) &&
		(!strcmp(s1->out_devname, s2->out_devname));
}

/* scans root list looking for already present entries. 
* Returns NULL if none is found, the pointer to the entry
* if a match is found. If a match is found, befre returning,
* the matching table will have its timer updated. The choice
* to update timers here avoids putting another lock when
* calling timer updating routine elsewhere. 
*/
struct state_table *lookup_state_table_n_update_timer(
		const struct state_table *stt, int lock)
{
	int counter = 0;
	struct state_table *statet;
	if(lock == ACQUIRE_LOCK)
		rcu_read_lock_bh();
	list_for_each_entry_rcu(statet, &root_state_table.list, list)
	{
		counter++;
		if (compare_state_entries(statet, stt) == 1)
		{
			/* call update_timer with read lock held.
			* Eventual concurrent update_timer on the
			* same structure should not be a problem.
			* The care taken concerns avoiding item 
			* deletion on timeout, with this lock.
			*/
			update_timer_of_state_entry(statet);
			if(lock == ACQUIRE_LOCK)
				rcu_read_unlock_bh();
			return statet;
		}
	}
	if(lock == ACQUIRE_LOCK)
		rcu_read_unlock_bh();
	return NULL;
}

/* If a packet carries fields pertaining to a table already present
* in the state table list, then NULL is returned, to indicate to the
* caller that the entry derived from `packet' does not have to be
* added. If `packet' is a packet not seen, a new entry of the 
* "state_table" kind is returned. nflags is used
* just for passive ftp support for now. 
* keep_state is called by ipfire_filter with the rcu_read_lock
* hold for static rules.
* - include/linux/rcupdate.h says:
* `RCU read-side critical sections may be nested.  Any deferred actions
*   will be deferred until the outermost RCU read-side critical section
*   completes.'
*/
struct state_table* keep_state(ipfire_info_t * packet, const ipfire_rule* p_rule)
{
	struct state_table *state_t;
	struct state_table *existing_stentry;
	struct sk_buff *skb;
	ipfire_info_t *ipfi_info_warn;
	
	if(p_rule == NULL || packet == NULL)
	  return NULL;
	  
	state_t = (struct state_table *) kmalloc(sizeof(struct state_table), GFP_ATOMIC);
	/* initialize state table with zeros */
	memset(state_t, 0, sizeof(struct state_table));
	/* Begin to prepare the new entry: network fields */
	if (fill_net_table_fields(state_t, packet) < 0)
	{
		kfree(state_t);
		IPFI_PRINTK("IPFIRE: error filling net table fields!\n");
		return NULL;
	}
	if ((existing_stentry = lookup_state_table_n_update_timer(state_t, ACQUIRE_LOCK))
			!= NULL)
	{
		/* Entry already exists: we can delete our 
		* local one, while entry timer in list has
		* been updated. Return NULL.
		*/
		kfree(state_t);
		return NULL;
	}
	/* Check if list is full */
	if (state_tables_counter == max_state_entries)
	{
		/* Allocate here ipfi_info_warn, if needed */
		ipfi_info_warn = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_ATOMIC);
		if(ipfi_info_warn != NULL) /* good */
		{
		  memset(ipfi_info_warn, 0, sizeof(ipfire_info_t));
		  ipfi_info_warn->state_max_entries = 1;
		  ipfi_info_warn->packet_id = state_tables_counter;
		  skb = build_info_t_packet(ipfi_info_warn);
		  if(skb != NULL && skb_send_to_user(skb, LISTENER_DATA) < 0)
		    IPFI_PRINTK("IPFIRE: error notifying maximum number of state entries to user\n");
		  else if(skb == NULL)
		    IPFI_PRINTK("IPFIRE: failed to allocate socket buffer space in keep_state()\n");
		  /* FREE */
		  kfree(ipfi_info_warn); /* no more needed */
		}
		else /* ipfire_info_t allocation failed */
		  IPFI_PRINTK("IPFIRE: memory allocation error in keep_state, ipfi_machine.c\n");
		  
		IPFI_PRINTK("IPFIRE: reached maximum count for STATE entries: %u\n",state_tables_counter);
		kfree(state_t);  	/* list full */
		return NULL;
	}
	/* Continue to prepare the new entry: set the correct state. */
	if (set_state(packet, state_t, 0) < 0)
	{
		IPFI_PRINTK("IPFIRE: invalid state when adding new state entry!\n");
		kfree(state_t);
		return NULL;
	}
	/* ftp? */
	if(p_rule->nflags.ftp)
		/* state table is marked as needing ftp support. From now on,
		* next packets will match that state table. */
		state_t->ftp = FTP_LOOK_FOR;	  

	/*
	* Since version 0.98.5 we store the information of the originating rule
	* for each new state table. So it will be easy to look for the rule that
	* the state entry was taken from.
	*/
	state_t->originating_rule = packet->packet_id;
	/* notify to userspace? */ 
	state_t->notify = packet->notify;
	/* does the originating rule belong to root or not? */
	state_t->admin = !p_rule->owner;
	
#ifdef ENABLE_RULENAME
	fill_table_with_name(state_t, packet);
#endif

	/* the rule might contain mangle directives which might affect stateful 
	 * connections. For instance, mtu manipulation needs to be done in SYN
	 * packets but also in SYN/ACK ones. For the second case, we need to store
	 * mangle information in state tables. some_manip_table() in ipfi_mangle.h/c
	 */
	if(some_manip_enabled(&p_rule->pkmangle) && state_t->state.state == SYN_SENT)
	{
//	  IPFI_PRINTK("----> some_manip_enabled! alloco struttura per state table\n");
	  state_t->pkmanip = (struct packet_manip*) kmalloc(sizeof(struct packet_manip), GFP_ATOMIC);
	  if(state_t->pkmanip != NULL) /* copy packet manipulation data from the rule */
	    memcpy(state_t->pkmanip, &p_rule->pkmangle, sizeof(struct packet_manip));
	}
	/* Return the new table with all fields filled. It is ready
	* to be added to the list by calling add_state_table_to_list().
	*/
	return state_t;
}

/* Adds the new state table to the list. Takes a pointer to a memory allocated
* structure. This is called when rcu read locks have been released.
*/
int add_state_table_to_list(struct state_table* newtable)
{
	/* acquire lock */
	spin_lock_bh(&state_list_lock);

	fill_timer_table_fields(newtable);
	/* add timer */
	add_timer(&newtable->timer_statelist);
	/* add table to list */
	INIT_LIST_HEAD(&newtable->list);
	/* Add element */
	list_add_rcu(&newtable->list, &root_state_table.list);
	/* Update table counter */
	state_tables_counter++;
	table_id++;
	/* release lock */
	spin_unlock_bh(&state_list_lock);
	return 0;
}

/* This routine acquires the write lock before deleting an item
* on the list of the state connections.
*/
void handle_keep_state_timeout(struct timer_list *t)
{
	struct state_table *st_to_free = timer_container_of(st_to_free, t, timer_statelist);

	spin_lock_bh(&state_list_lock);

	if(we_are_exiting != 0)
	{
		IPFI_PRINTK("data in handle_keep_state_timeout() we are exiting!\n");
		spin_unlock_bh(&state_list_lock);
		return;
	}

	if(st_to_free == NULL)
	{
		IPFI_PRINTK("handle_timeout: null data\n");
		spin_unlock_bh(&state_list_lock);
		return;
	}
	/* Once the timer has decayed, the kernel automatically removes the
	* element from the list. Anyway, removing the timer within the timer
	* function is considered a good practise. First acquire lock.
	*/


	timer_delete(&st_to_free->timer_statelist);
	list_del_rcu(&st_to_free->list);
	/* do not decrease table_id, but decrement state_tables_counter. */
	state_tables_counter--;
	/* call_rcu will free memory */
	call_rcu(&st_to_free->state_rcuh, free_state_entry_rcu_call);
	spin_unlock_bh(&state_list_lock);
}

/* returns in *addr the internet address corresponding to 
* ouput or input interface, depending on field "direction" of info 
* info packet. This is good for in and out directions, where 
* the context is clear when one says "my address". 
*/
int get_ifaddr_by_info(const ipfire_info_t * pack, __u32 * addr)
{
	switch (pack->direction)
	{
		case IPFI_INPUT:
			/* if packet enters, look for input interface as our interface */
			if (get_ifaddr_by_name(pack->devpar.in_devname, addr) <
					0)
			{
				IPFI_PRINTK("IPFIRE: direction: input no interface matching name %s!\n",
					pack->devpar.in_devname);
				return -1;
			}
			break;
		case IPFI_OUTPUT:
			/* if packet goes out, look for out interface as our interface */
			if (get_ifaddr_by_name(pack->devpar.out_devname, addr) <
					0)
			{
				printk ("IPFIRE: direction: output: no interface matching name %s!\n",
					pack->devpar.out_devname);
				return -1;
			}
			break;
		default:
			printk
				("IPFIRE: cannot get my address for direction %d!\n",
				pack->direction);
			return -1;
	}
	return 0;
}

/* returns in *addr the internet address having the name ifname */
int get_ifaddr_by_name(const char *ifname, __u32 * addr)
{
	struct net_device *pnet_device;
	struct in_device *pin_device;
	struct in_ifaddr* inet_ifaddr;

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, pnet_device)
	{
		if ((netif_running(pnet_device))
				&& (pnet_device->ip_ptr != NULL)
				&& (strcmp(pnet_device->name, ifname) == 0))
		{
			pin_device =
				(struct in_device *) pnet_device->ip_ptr;
			inet_ifaddr = pin_device->ifa_list;
			if(inet_ifaddr == NULL)
			{
				IPFI_PRINTK("ifa_list is null!\n");
				break;
			}
			/* ifa_local: ifa_address is the remote point in ppp */
			*addr = (inet_ifaddr->ifa_local);
			rcu_read_unlock();
			return 1;
		}

	}

	rcu_read_unlock();
	return -1;		/* address not found! */
}

int free_state_tables(void)
{
	struct state_table *tl;
	int counter = 0, i = 0;
	/* free all entries in tables */
	spin_lock_bh(&state_list_lock);
	list_for_each_entry(tl, &root_state_table.list, list)
	{
		i++;
		if(timer_delete(&tl->timer_statelist) > 0 )
		{
			list_del_rcu(&tl->list);
			call_rcu(&tl->state_rcuh, free_state_entry_rcu_call);
			counter++;
			state_tables_counter--;
		}
		else
			IPFI_PRINTK("IPFIRE: free_state_tables(): timer already expired for the entry %d.\n", i);
	}
	spin_unlock_bh(&state_list_lock);
	return counter;
}

/*  1. set the correct state of the new entry (IPFI_NEW, packet not already seen,
    just the rule is ready for future connection);
    2. initialize timers;
    3. add the rule to the tail of the list just as any other rule
    4. :)
    */
int add_ftp_dynamic_rule(struct state_table* ftpt)
{
	if (state_tables_counter == max_state_entries)
	{
		IPFI_PRINTK("IPFIRE: reached maximum count for STATE entries "
				"(adding FTP rule): %u\n", state_tables_counter);
		kfree(ftpt);
		return -1;
	}
	/* set the correct state. We haven't already seen any ftp data packet for now */
	ftpt->state.state = FTP_NEW;

	if(ftpt->ftp != FTP_DEFINED)
	{
		IPFI_PRINTK("IPFIRE: ftp support: you shouldn't be here without FTP_DEFINED set!\n");
		return -1;
	}	  	  
	/* Since version 0.98.5, the ftp table id is the same of the state table 
	* that generated it. So, we do not set the ftp table id here, but
	* inside get_params_and_alloc_newentry() in ipfi_ftp.c
	*/
	/* ftpt->id = table_id + 1; */

	add_state_table_to_list(ftpt);
	return 0;
}



//static int  init(void)
int init_machine(void)
{
	INIT_LIST_HEAD(&root_state_table.list);
	return 0;
}

//static void __exit fini(void)
void fini_machine(void)
{
	int ret;
	ret = free_state_tables();
	IPFI_PRINTK("IPFIRE: state tables freed: %d.\n", ret);
	/* might_sleep(): see linux kernel sources/include/linux.h:
	* this is a macro which will print a stack trace if it is executed in an atomic
	* context (spinlock, irq-handler, ...).
	*
	* This is a useful debugging help to be able to catch problems early and not
	* be biten later when the calling function happens to sleep when it is not
	* supposed to.
	*/
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
	/**
	* See also kernel sources/kernel/rcupdate.c:
	* synchronize_rcu - wait until a grace period has elapsed.
	*
	* Control will return to the caller some time after a full grace
	* period has elapsed, in other words -> after all currently executing RCU
	* read-side critical sections have completed <-.  RCU read-side critical
	* sections are delimited by rcu_read_lock() and rcu_read_unlock(),
	* and may be nested.
	*
	* If your read-side code is not protected by rcu_read_lock(), do -not-
	* use synchronize_rcu().
	*/
	/* rcu_barrier(), differently from synchroinze_rcu(), waits the completion
	* of the rcu callbacks, while the second waits just a grace time.
	* So I use rcu_barrier() instead.
	*/
}

MODULE_DESCRIPTION("IPFIREwall filtering functions and state machine.");
MODULE_AUTHOR("Giacomo S. <delleceste@gmail.com>");
MODULE_LICENSE("GPL");



