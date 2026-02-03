/* ipfi_translation.c manages Network Address Translation and
 * getsockopt() interface. */

/***************************************************************************
 *  Copyright  2005  Giacomo S.
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

#include "includes/ipfi.h"
#include "includes/ipfi_netl.h"
#include "includes/ipfi_translation.h"
#include "includes/ipfi_machine.h"
#include "includes/ipfi_netl_packet_builder.h"
#include "includes/globals.h"


#define NOCHECK_CSUM 0

#define CHECK_CSUM 1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
/* Incoming packets: CHECKSUM_HW has been replaced by CHECKSUM_COMPLETE.
 * see kernel sources/include/linux/skbuff.h
 */
#define CHECKSUM_HW CHECKSUM_COMPLETE
#endif

#define SO_IPFI_GETORIG_DST    	200	/* a number */
static struct nf_sockopt_ops so_getoriginal_dst = {
    .pf = PF_INET,
    .get_optmin = SO_IPFI_GETORIG_DST,
    .get_optmax = SO_IPFI_GETORIG_DST + 1,
    .get = &get_original_dest,
};

int get_orig_from_dnat_entry(const struct dnatted_table *dnt,
                             const net_quadruplet * n4,
                             struct sockaddr_in *sin)
{
    if (dnt->protocol != IPPROTO_TCP)
        return -1;
    /* valid only for TCP, so: */
    if ((dnt->old_saddr == n4->daddr) &&
            (dnt->new_daddr == n4->saddr) &&
            (dnt->old_sport == n4->dport) &&
            (dnt->new_dport == n4->sport))
    {
        sin->sin_addr.s_addr = dnt->old_daddr;
        sin->sin_port = dnt->old_dport;
        return 1;
    }
    return -1;
}

int lookup_dnat_table_and_getorigdst(const net_quadruplet *n4, struct sockaddr_in *sin) {
    int counter = 0;
    struct dnatted_table *dntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(dntmp, &root_dnatted_table.list, list)
    {
        counter++;
        if (get_orig_from_dnat_entry(dntmp, n4, sin) == 1) {
            rcu_read_unlock_bh();
            return 0;
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

/* getsockopt related function: finds original destination address and port
 * in a destination natted connection */
int get_original_dest(struct sock *sk, int optval, void __user * user, int *len)
{
    int status;
    struct inet_sock *inet;
    struct sockaddr_in *sin;

    /* a. Preliminary checks before allocating memory and getting data
    */
    /* We only do TCP at the moment: is there a better way? */
    if (strcmp(sk->sk_prot->name, "TCP")) {
        IPFI_PRINTK("SO_ORIGINAL_DST: Not a TCP socket\n");
        return -ENOPROTOOPT;
    }
    if ((unsigned int) *len < sizeof(struct sockaddr_in)) {
        IPFI_PRINTK("SO_ORIGINAL_DST: len %u not %lu\n", *len, sizeof(struct sockaddr_in));
        return -EINVAL;
    }

    /* b. allocate necessary data structures */
    sin = (struct sockaddr_in *) kmalloc(sizeof(struct sockaddr_in), GFP_ATOMIC);
    if (!sin)
        return -ENOMEM;

    /* c. process data */
    inet = (struct inet_sock *) sk;

    net_quadruplet n4 = { inet->inet_rcv_saddr, inet->inet_daddr, inet->inet_sport, inet->inet_dport, 1};

    // tmp_iit->iphead.saddr = inet->inet_rcv_saddr;	/* bound local ipv4 addr */
    // tmp_iit->iphead.daddr = inet->inet_daddr;	/* foreign ipv4 addr */
    // tmp_iit->transport_header.tcphead.source = inet->inet_sport;
    // tmp_iit->transport_header.tcphead.dest = inet->inet_dport;
    // tmp_iit->protocol = IPPROTO_TCP;

    //	IPFI_PRINTK("IPFIRE GETORIG COUPLE: %u.%u.%u.%u:%u-%u.%u.%u.%u:%u.\n", NIPQUAD(tmp_iit->iphead.saddr),
    //			ntohs(tmp_iit->transport_header.tcphead.source), NIPQUAD(tmp_iit->iphead.daddr),
    //			ntohs(tmp_iit->transport_header.tcphead.dest));

    if (lookup_dnat_table_and_getorigdst(&n4, sin) < 0)
    {
        //		IPFI_PRINTK("IPFIRE: get_original_dest(): GETORIG COUPLE FAILED: %u.%u.%u.%u:%u-%u.%u.%u.%u:%u.\n",
        //				NIPQUAD(tmp_iit->iphead.saddr), ntohs(tmp_iit->transport_header.tcphead.source),
        //				NIPQUAD(tmp_iit->iphead.daddr), ntohs(tmp_iit->transport_header.tcphead.dest));
        /* free memory before returning */
        kfree(sin);
        return -ENOENT;
    }
    /* we have old destination address and port, we have to set family */
    sin->sin_family = AF_INET;
    if (copy_to_user(user, sin, sizeof(struct sockaddr_in)) != 0)
        status = -EFAULT;
    else
        status = 0;
    /* free memory before leaving */
    kfree(sin);
    return status;
}

/* given a socket buffer skb, returns source and destination addresses and ports 
 * at the addresses of parameters passed as arguments, 1 in case of TCP and UDP
 * 0 in case of ICMP, -1 in case of invalid protocol.
 */
net_quadruplet get_quad_from_skb(const struct sk_buff* skb)
{
    struct iphdr *iphdr;
    struct tcphdr *ptcphead;
    struct udphdr *pudphead;
    net_quadruplet netquad;
    net_quadruplet nq_invalid;
    memset(&netquad, 0, sizeof(net_quadruplet));
    memset(&nq_invalid, 0, sizeof(net_quadruplet));
    /* valid netquad to compile and return in case of success */
    netquad.valid = 1;

    if (skb == NULL)
    {
        IPFI_PRINTK("IPFIRE: get_quad_from_skb(): passed socket buffer NULL\n");
        return nq_invalid;
    }

    iphdr = ip_hdr(skb);
    if(iphdr == NULL)
    {
        IPFI_PRINTK("IPFIRE: get_quad_from_skb(): could not extract IP header\n");
        return nq_invalid;
    }
    netquad.saddr = iphdr->saddr;
    netquad.daddr = iphdr->daddr;

    switch (iphdr->protocol)
    {
    case IPPROTO_TCP: {
        struct tcphdr *th = (struct tcphdr *)((void *)iphdr + iphdr->ihl * 4);
        netquad.sport = th->source;
        netquad.dport = th->dest;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = (struct udphdr *)((void *)iphdr + iphdr->ihl * 4);
        netquad.sport = uh->source;
        netquad.dport = uh->dest;
        break;
    }
    case IPPROTO_ICMP:
    case IPPROTO_IGMP:
    case IPPROTO_GRE:
    case IPPROTO_PIM:
        return netquad;
        break;
    default:
        IPFI_MODERATE_PRINTK(PRINT_PROTO_UNSUPPORTED,
                             "IPFIRE: get_quad_from_skb(): unsupported protocol %d\n", iphdr->protocol);
        return nq_invalid;
    }
    return netquad;
}

/* PACKET MANIPULATION function.
 *
 * given source and destination addresses and ports, this function sets them
 * in socket buffer passed as parameter. In case of TCP or UDP protocols,
 * returns 1, 0 for ICMP, -1 in case of errors. Only fields specified in pkt_manip_info
 * are set.
 * Finally, it replaces checksums.
 */
int manip_skb(struct sk_buff *skb, __u32 saddr, __u16 sport,
              __u32 daddr, __u16 dport, struct pkt_manip_info mi)
{
    struct iphdr *ipheader;
    int csum_check;
    unsigned int l4hdroff;
    struct tcphdr *ptcphead = NULL;
    struct udphdr *pudphead = NULL;
    unsigned int  iphdroff = 0;
    unsigned int writable_len = 0;
    __u32 oldaddr = 0, newaddr = 0;
    __u16 oldport = 0, newport = 0;
    bool check_csum = mi.direction < IPFI_OUTPUT ? true : false;
    ipheader = ip_hdr(skb);
    if (ipheader == NULL)
        return network_header_null("manip_skb()", "IP header NULL!");

    l4hdroff = ipheader->ihl * 4;

    if (skb == NULL)
        return network_header_null("manip_skb()", "socket buffer NULL!");

    /* before making any change to skb, make sure
     * checksums of original packet are correct.
     * Check the checksum only of input packets, not
     * of outgoing ones (see net/ipv4/netfilter/ip_conntrack_proto_tcp.c) */
    if (check_csum)
    {
        if ((csum_check = check_checksums(skb)) < 0)
            return csum_error_message("manip_skb()", csum_check);
    }

    /* net/netfilter/core.c:
     * tests if the skb is an exclusive copy or if it is a writable clone.
     * If not, it may call __pskb_pull_tail(), which advances the tail of
     * the skb header (net/core/skbuff.c): all the pointers pointing into
     * skb header may change and must be reloaded after call to this function.
     */
    if((mi.sp ^ mi.dp) && ipheader->protocol == IPPROTO_TCP)
        writable_len = l4hdroff + sizeof(struct tcphdr);
    else if((mi.sp ^ mi.dp)  && ipheader->protocol == IPPROTO_UDP)
        writable_len = l4hdroff + sizeof(struct udphdr);
    else if(mi.sp | mi.dp)
        return -1;
    else
        writable_len = l4hdroff;

    if(skb_ensure_writable(skb, writable_len))
        return -1;
    /* reload the pointer to ip header */
    ipheader = (void *)skb->data + iphdroff;

    /* pointers to tcp and udp headers */
    if(ipheader->protocol == IPPROTO_TCP) /* if one is set, then need to recalculate l4 checksum */
        ptcphead = (struct tcphdr *)(skb->data + l4hdroff);
    else if(ipheader->protocol == IPPROTO_UDP)
        pudphead =  (struct udphdr *)(skb->data + l4hdroff);

    /* manipulate packet and update ip checksum */
    if(mi.sa)
    {
        oldaddr = ipheader->saddr;
        newaddr = saddr;
        ipheader->saddr = saddr;
    }
    else if (mi.da)
    {
        oldaddr = ipheader->daddr;
        newaddr = daddr;
        ipheader->daddr = daddr;
    }
    /* manipulate the packet, according to the protocol */
    if(mi.sp ^ mi.dp)
    {
        switch (ipheader->protocol)
        {
        case IPPROTO_TCP:
            if (mi.sp) {
                oldport = ptcphead->source;
                newport = sport;
                ptcphead->source = newport;
            }
            else if (mi.dp) {
                oldport = ptcphead->dest;
                newport = dport;
                ptcphead->dest = newport;
            }
            break;

        case IPPROTO_UDP:
            if (mi.sp)  {
                oldport = pudphead->source;
                newport = sport;
                pudphead->source = newport;
            }
            else if (mi.dp) {
                oldport = pudphead->dest;
                newport = dport;
                pudphead->dest = newport;
            }
            break;
        case IPPROTO_ICMP:
        case IPPROTO_IGMP:
        case IPPROTO_GRE:
        case IPPROTO_PIM:
            break;
        default:
            IPFI_PRINTK ("IPFIRE: manip_skb(): invalid protocol %d.\n", ipheader->protocol);
            return -1;
            break;
        }
    }

    if(mi.sa ^ mi.da) {
        /* recalculate IP header checksum */
        csum_replace4(&ipheader->check, oldaddr, newaddr);
        switch(ipheader->protocol) {
        case IPPROTO_TCP:  /* adjust tcp checksum according to the ip address change */
            inet_proto_csum_replace4(&ptcphead->check, skb, oldaddr, newaddr, 1);
            break;
        case IPPROTO_UDP:  /* adjust udp checksum according to the ip address change */
            if (pudphead->check || skb->ip_summed == CHECKSUM_PARTIAL) {
                inet_proto_csum_replace4(&pudphead->check, skb, oldaddr, newaddr, 1);
                if (!pudphead->check)
                    pudphead->check = CSUM_MANGLED_0; /* include/net/checksum.h:#define CSUM_MANGLED_0 ((__force __sum16)0xffff) */
            }
            break;
        }
    }
    /* replace checksum for tcp/udp port changes, if either mi.sp or mi.dp is set */
    if(mi.sp ^ mi.dp) {
        switch(ipheader->protocol)  {
        /* IPPROTO_TCP and IPPROTO_UDP cases only */
        case IPPROTO_UDP:
            if (pudphead->check || skb->ip_summed == CHECKSUM_PARTIAL)   {
                inet_proto_csum_replace2(&pudphead->check, skb, oldport, newport, 0);
                if (!pudphead->check)
                    pudphead->check = CSUM_MANGLED_0; /* include/net/checksum.h:#define CSUM_MANGLED_0 ((__force __sum16)0xffff) */
            }
            break;
        case IPPROTO_TCP:
            inet_proto_csum_replace2(&ptcphead->check, skb, oldport, newport, 0);
            break;
        }
    }
    // 	if(mi.direction > IPFI_INPUT_PRE) /* we were called from OUTPUT or post routing */
    // 	  skb->ip_summed = CHECKSUM_NONE;
    return 1;
}

int fill_entry_net_fields(struct dnatted_table *dnentry,
                          const ipfire_info_t * original_pack,
                          const ipfire_rule * dnat_rule)
{
    memset(dnentry, 0, sizeof(struct dnatted_table));
    /* Has packet arrived from external interface? */
    dnentry->external = original_pack->flags.external;
    dnentry->protocol = original_pack->packet.iphead.protocol;
    dnentry->old_saddr = original_pack->packet.iphead.saddr;
    dnentry->old_daddr = original_pack->packet.iphead.daddr;

    /* initialize new address to the value in original packet */
    dnentry->new_daddr = original_pack->packet.iphead.daddr;
    /* copy interfaces names */
    dnentry->in_ifindex = original_pack->netdevs.in_idx;
    dnentry->out_ifindex = original_pack->netdevs.out_idx;
    switch (original_pack->packet.iphead.protocol)
    {
    case IPPROTO_TCP:
        dnentry->old_sport =
                original_pack->packet.transport_header.tcphead.source;
        dnentry->old_dport =
                original_pack->packet.transport_header.tcphead.dest;
        dnentry->new_dport = dnentry->old_dport;
        break;
    case IPPROTO_UDP:
        dnentry->old_sport =
                original_pack->packet.transport_header.udphead.source;
        dnentry->old_dport =
                original_pack->packet.transport_header.udphead.dest;
        dnentry->new_dport = dnentry->old_dport;
        break;
    case IPPROTO_ICMP:
    case IPPROTO_IGMP:
    case IPPROTO_GRE:
    case IPPROTO_PIM:
        break;
    default:
        IPFI_PRINTK("IPFIRE: fill_entry_net_fields() (adding dnat entry): invalid protocol: %d.\n",
                    original_pack->packet.iphead.protocol);
        return -1;
        break;
    }
    dnentry->direction = original_pack->flags.direction;
    // *CHECK *
    dnentry->id = original_pack->response.rulepos;
    //      //
    dnentry->position = dnatted_entry_counter;
    /* new values */
    if (dnat_rule->nflags.newaddr)
        dnentry->new_daddr = dnat_rule->newaddr;

    if (dnat_rule->nflags.newport)
        dnentry->new_dport = dnat_rule->newport;
    return 0;
}

/* Callback function for freeing a DNAT entry */
void free_dnat_entry_rcu_call(struct rcu_head *head)
{
    struct dnatted_table *dnatt=
            container_of(head, struct dnatted_table, dnat_rcuh);
    kfree(dnatt);
}

/* Must be called with the lock */
inline void update_dnat_timer(struct dnatted_table *dnt)
{
    unsigned int timeout = get_timeout_by_state(dnt->protocol, dnt->state);
    mod_timer(&dnt->timer_dnattedlist,
              jiffies + HZ * timeout);
}

/* Must be called with the lock */
inline void update_snat_timer(struct snatted_table *snt)
{
    unsigned int timeout = get_timeout_by_state(snt->protocol, snt->state);
    mod_timer(&snt->timer_snattedlist,
              jiffies + HZ * timeout);
}

/* Timeout handler for dnat entries. */
void handle_dnatted_entry_timeout(struct timer_list *t)
{
    struct dnatted_table *dnt_to_free = timer_container_of(dnt_to_free, t, timer_dnattedlist);
    /* acquire lock before freeing rule (dnat table lock) */
    spin_lock(&dnat_list_lock);
    timer_delete_sync(&dnt_to_free->timer_dnattedlist);
    list_del_rcu(&dnt_to_free->list);
    // 	kfree(dnt_to_free);
    call_rcu(&dnt_to_free->dnat_rcuh, free_dnat_entry_rcu_call);
    dnatted_entry_counter--;
    /* release lock */
    spin_unlock(&dnat_list_lock);
}

/* Called when adding a new entry, the network part and the state 
 * must already be initialized.
 */
void fill_timer_dnat_entry(struct dnatted_table *dnt)
{
    unsigned timeo;
    timeo = get_timeout_by_state(dnt->protocol, dnt->state);
    timer_setup(&dnt->timer_dnattedlist, handle_dnatted_entry_timeout, 0);

    dnt->timer_dnattedlist.expires= jiffies + HZ * timeo;
}

int de_dnat(struct sk_buff *skb, const struct dnatted_table *dnatt)
{
    /* set source address of outgoing packet equal to the original
     * destination address which was translated while incoming
     */
    struct pkt_manip_info mi;
    mi.sa = 1, mi.sp = 1, mi.da = 0, mi.dp = 0;
    mi.direction = IPFI_OUTPUT_POST;
    return
            manip_skb(skb, dnatt->old_daddr, dnatt->old_dport,
                      dnatt->old_saddr, dnatt->old_sport, mi);
}

int de_dnat_table_match(const struct dnatted_table *dnt,
                        const struct sk_buff *skb, ipfire_info_t * packet)
{
    net_quadruplet nquad;
    struct iphdr *iphead;
    iphead = ip_hdr(skb);
    if(iphead == NULL)
    {
        IPFI_PRINTK("IPFIRE: de_dnat_table_match(): ip header NULL!\n");
        return -1;
    }

    /* if dnat entry has external flag set, de_dnat is needed
     * anyway because of port translation. IP instead should be
     * masqueraded or source natted in postrouting. */

    /* packets DNATted in output hook must preserve their source address */
    if (dnt->direction == IPFI_OUTPUT)
        return -1;
    /* obtain network quadruplet with source and dest ips and ports */
    nquad = get_quad_from_skb(skb);
    if(!nquad.valid)
    {
        return -1;
    }
    /* we don't look for device match here */
    /* Destination address of coming back packet must be
     * equal to old destination address (our one). Source
     * address must be the one we destination-natted.
     */
    if (iphead->protocol != dnt->protocol)
        return -1;

    if (dnt->protocol == IPPROTO_ICMP || dnt->protocol == IPPROTO_IGMP
            || dnt->protocol == IPPROTO_GRE || dnt->protocol == IPPROTO_PIM)
    {
        if ((nquad.saddr == dnt->new_daddr)
                && (nquad.daddr == dnt->old_saddr))
            goto success;
    }
    else if ((dnt->protocol == IPPROTO_TCP) ||
             (dnt->protocol == IPPROTO_UDP))
    {
        if ((nquad.saddr == dnt->new_daddr)
                && (nquad.sport == dnt->new_dport)
                && (nquad.daddr == dnt->old_saddr)
                && (nquad.dport == dnt->old_sport))
            goto success;
    }
    return -1;
success:
    return 1;
}

/* This one is called in post routing */
int de_dnat_translation(struct sk_buff *skb, ipfire_info_t * pack)
{
    int counter = 0;
    int ret;
    struct dnatted_table *dntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(dntmp, &root_dnatted_table.list, list)
    {
        counter++;
        /* de_dnat_table_match() copies into pack rule
         * name if a match is found */
        if (de_dnat_table_match(dntmp, skb, pack) > 0)
        {
            /* Update the state of the destination nat entry */
            dntmp->state = state_machine(pack, dntmp->state, 1);
            /* Now update the timer of the entry */
            update_dnat_timer(dntmp);
            ret = de_dnat(skb, dntmp);
            rcu_read_unlock_bh();
            return ret;
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

int compare_entries(const struct dnatted_table *dne1,
                    const struct dnatted_table *dne2) {
    return ((dne1->protocol == dne2->protocol) &&
            (dne1->old_saddr == dne2->old_saddr) &&
            (dne1->old_daddr == dne2->old_daddr) &&
            (dne1->old_dport == dne2->old_dport) &&
            (dne1->old_sport == dne2->old_sport) &&
            (dne1->new_daddr == dne2->new_daddr) &&
            (dne1->new_dport == dne2->new_dport) &&
            (dne1->direction == dne2->direction) &&
            (dne1->in_ifindex == dne2->in_ifindex) &&
            (dne1->out_ifindex == dne2->out_ifindex));
}

/* Looks up dnatted table, comparing each entry with the entry 
 * passed as argument. This happens while holding a read lock
 * which also disables sw interrupts. We take advantage of such
 * lock to update here entry timer, instead of acquiring another
 * lock later elsewhere to update the timer.
 * The timer is updated depending on the state of the entry,
 * which is refreshed first of all when an entry is found in the
 * list.
 */
struct dnatted_table *
        lookup_dnatted_table_n_update_timer(const struct dnatted_table *dne, ipfire_info_t* info)
{
    int counter = 0;
    struct dnatted_table *dntmp;
    /* acquire read lock for dnat table */
    rcu_read_lock_bh();
    list_for_each_entry_rcu(dntmp, &root_dnatted_table.list, list)
    {
        counter++;
        if (compare_entries(dntmp, dne) == 1)
        {
            /* Update the state of the existing entry in the kernel tables */
            /* 0 means 'reverse = 0'. Here we are in the original direction */
            dntmp->state = state_machine(info,  dntmp->state, 0);
            update_dnat_timer(dntmp);
            rcu_read_unlock_bh();
            return dntmp;
        }
    }
    rcu_read_unlock_bh();
    return NULL;
}

int add_dnatted_entry(const struct sk_buff *skb,
                      ipfire_info_t * original_pack,
                      const ipfire_rule * dnat_rule)
{
    struct dnatted_table *dnatted_entry;
    struct dnatted_table *existing_entry;
    struct sk_buff *skb_to_user;
    ipfire_info_t *ipfi_info_warn;
    dnatted_entry = (struct dnatted_table *)
            kmalloc(sizeof(struct dnatted_table), GFP_ATOMIC);
    if (fill_entry_net_fields(dnatted_entry, original_pack, dnat_rule)
            < 0)
    {
        kfree(dnatted_entry);
        return -1;
    }
    /* lookup_dnatted_table_n_update_timer() updates first the state.
     * Then it updates the timer.
     */
    if ((existing_entry = lookup_dnatted_table_n_update_timer(dnatted_entry, original_pack)) != NULL)
    {
        kfree(dnatted_entry);	/* free just mallocated memory */
        return 1;	/* entry already existing */
    }
    if (dnatted_entry_counter == fwopts.max_nat_entries)
    {
        /* allocate ipfi_info_warn: it is created and lives only inside this if branch */
        ipfi_info_warn = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_ATOMIC);
        if(ipfi_info_warn != NULL)
        {
            memset(ipfi_info_warn, 0, sizeof(ipfire_info_t));
            // *CHECK *
            ipfi_info_warn->flags.nat_max_entries = 1;
            ipfi_info_warn->response.rulepos = fwopts.max_nat_entries;
            //         //
            skb_to_user = build_info_t_packet(ipfi_info_warn);

            if (skb_to_user != NULL && skb_send_to_user(skb_to_user, LISTENER_DATA) < 0)
                IPFI_PRINTK("IPFIRE: error notifying maximum number of nat entries to user\n");
            else if(!skb_to_user)
                IPFI_PRINTK("IPFIRE: failed to allocate memory for socket buffer in add_dnatted_entry()\n");
            /* FREE ipfi_info_warn */
            kfree(ipfi_info_warn);
        }
        IPFI_PRINTK("IPFIRE: reached maximum count for DNATTED entries: %lu.\n", fwopts.max_nat_entries);
        kfree(dnatted_entry);	/* free just mallocated memory */
        return -1;
    }

    /* A new dnat table will be added */
    /* Set the state of the new dnat table */
    dnatted_entry->state = state_machine(original_pack,  dnatted_entry->state, 0);

    /* put the lock on dnat table */
    spin_lock_bh(&dnat_list_lock);
    /* fill in timer fields */
    fill_timer_dnat_entry(dnatted_entry);
    /* add timer */
    add_timer(&dnatted_entry->timer_dnattedlist);
    /* add entry to root table */
    INIT_LIST_HEAD(&dnatted_entry->list);
    list_add_rcu(&dnatted_entry->list, &root_dnatted_table.list);
    spin_unlock_bh(&dnat_list_lock);
    return 0;
}

/* packet contains the fields taken from sk_buff, r is the translation rule.
 * In this function, the packet must match the rule provided by user for
 * DNAT or SNAT (or MASQUERADE). 1 is returned on success, i.e. if the
 * rule matches ip packet. Rule name is filled in in packet if a matcu
 * is found with a rule. */
int translation_rule_match(const ipfire_info_t * packet, const ipfire_rule * r)
{
    /* rule direction must be the same of packet direction */
    if (r->direction != packet->flags.direction)
        return -1;

    if (r->ip.protocol != packet->packet.iphead.protocol)
        return -1;

    /* then _all_ fields must match */
    /* device names */
    if (r->nflags.indev && r->devpar.in_ifindex != packet->netdevs.in_idx)
        return -1;
    if (r->nflags.outdev && r->devpar.out_ifindex != packet->netdevs.out_idx)
        return -1;
    /* ip */
    if (address_match(&packet->packet.iphead, r, packet->flags.direction, NULL, NULL) < 0)
        return -1;
    /* transport */
    switch (packet->packet.iphead.protocol)
    {
    case IPPROTO_TCP:
        if (port_match(&packet->packet.transport_header.tcphead, NULL, r, IPPROTO_TCP) < 0)
            return -1;
        break;
    case IPPROTO_UDP:
        if (port_match(NULL, &packet->packet.transport_header.udphead, r, IPPROTO_UDP) < 0)
            return -1;
        break;
    case IPPROTO_ICMP:
    case IPPROTO_IGMP:
    case IPPROTO_GRE:
    case IPPROTO_PIM:
        break;
    }
    return 1;
}

/* returns 1 if network address is a private one conforming
 * to rfc 1918, 0 otherwise */
inline int private_address(__u32 addr)
{
    __u32 haddr = ntohl(addr);
    /* See RFC 1918: "Address allocation for Private Internets" */
    /* Class A private network: 10.0.0.0 - 10.255.255.255 */
    if ((haddr >= 0xa00000) && (haddr <= 0xaffffff))
        return 1;
    /* Class B private network: 172.16.0.0 - 172.31.255.255 */
    if ((haddr >= 0xac100000) && (haddr <= 0xac1fffff))
        return 1;
    /* Class C private network: 192.168.0.0 - 192.168.255.255 */
    if ((haddr >= 0xc0a80000) && (haddr <= 0xc0a8ffff))
        return 1;
    return 0;
}

/* returns 1 if packet comes from a public host and 
 * gets redirected to an internal host. In this case,
 * the address of the remote host, shall not be substituted
 * with our address: receiving machine has the right to see
 * the real identity of the sender. */
inline int public_to_private_address(const struct sk_buff *skb,
                                     const ipfire_rule * ipfr) {
    struct iphdr* iphead;
    iphead = ip_hdr(skb);
    if(iphead == NULL) {
        IPFI_PRINTK("IPFIRE: public_to_private_address(): ip header NULL!\n");
        return -1;
    }
    /* if source address of skb is private, return 0. */
    if (private_address(iphead->saddr))
        return 0;
    /* source address of host is public, see if packet is
     * destination natted towards internal network: */
    if (private_address(ipfr->newaddr))
        return 1;
    /* private -> private or public->public or private->public */
    return 0;
}

/* prints the checksum error message according to the checksum_errore enum
 * defined in ipfi.h and returns -1. Introducted in 0.99.2
 */
int csum_error_message(const char *origin, int enum_code)
{
    if(origin == NULL)
    {
        IPFI_PRINTK("int csum_error_message(const char *origin, int enum_code): origin must be a non null char pointer!\n");
        return -1;
    }
    IPFI_PRINTK("IPFIRE: %s: checksum error: ", origin);
    switch(-enum_code)
    {
    /*  BAD_IP_CSUM = 1, BAD_TCPHEAD_CSUM,  BAD_TCPHEAD_CHECK,
            BAD_UDPHEAD_CHECK, BAD_UDPHEAD_CSUM */
    case BAD_IP_CSUM:
        IPFI_PRINTK("bad IP checksum.\n");
        break;
    case BAD_TCPHEAD_CSUM:
        IPFI_PRINTK("bad TCP header checksum.\n");
        break;
    case BAD_TCPHEAD_CHECK:
        IPFI_PRINTK("TCP header check failed.\n");
        break;
    case BAD_UDPHEAD_CSUM:
        IPFI_PRINTK("bad UDP header checksum.\n");
        break;
    case BAD_UDPHEAD_CHECK:
        IPFI_PRINTK("UDP header check failed.\n");
        break;
    default:
        IPFI_PRINTK("Unrecognized value %d for checksum error!\n", enum_code);
        break;
    }
    return -1;
}

/* translate destination address or destination port
 * Used in prerouting or output directions.
 * This is called from ipfi_response() and ipfi_pre_process(),
 * where skb != NULL must have already been checked.
 */
int dnat_translation(struct sk_buff *skb,
                     ipfire_info_t * packet,
                     const ipfi_flow *flow,
                     const struct info_flags *flags)
{
    ipfire_rule *transrule;
    ipfire_rule *dnat_rules = NULL;
    int counter = 0, csum_check;

    if (flow->direction == IPFI_INPUT_PRE)
        dnat_rules = &translation_pre;
    else if (flow->direction == IPFI_OUTPUT)
        dnat_rules = &translation_out;
    if (dnat_rules == NULL)
        return -1;

    /* read lock: it might be possible that rule list is modified during read in non atomic context (output maybe)
    */
    rcu_read_lock_bh();
    list_for_each_entry_rcu(transrule, &dnat_rules->list, list)
    {
        counter++;
        if (translation_rule_match(packet, transrule) > 0)
        {
            if( (flow->direction == IPFI_INPUT_PRE) && ((csum_check = check_checksums(skb)) < 0) )
            {
                rcu_read_unlock_bh(); /* unlock before returning */
                return csum_error_message("dnat_translation()", csum_check);
            }

            if(public_to_private_address(skb, transrule))
                packet->flags.external = 1;
            /* there is a rule for our packet to be translated */
            /* add_dnatted_entry() adds a new table if not already present,
             * and if it is present, its timeout gets updated.
             */
            if(add_dnatted_entry(skb, packet, transrule) == 0)
                dnatted_entry_counter++;
            dest_translate(skb, transrule);
            rcu_read_unlock_bh();
            return 0; /* unlock before returning */
        }
    }
    rcu_read_unlock_bh(); /* unlock before returning */
    return -1;
}

/* changes destination address and or port. Called by int dnat_translation() while rcu_read_lock_bh is held */
int dest_translate(struct sk_buff *skb, const ipfire_rule * transrule)
{
    struct tcphdr *p_tcphead;
    struct udphdr *p_udphead;
    struct iphdr* iphead;
    struct udphdr udphead;
    struct tcphdr tcphead;

    struct pkt_manip_info mi;
    memset(&mi, 0, sizeof(mi));

    if (transrule->nflags.newaddr)
        mi.da = 1;
    if(transrule->nflags.newport)
        mi.dp = 1;
    mi.direction = transrule->direction; /* can be output or pre routing */
    return manip_skb(skb, 0, 0, transrule->newaddr, transrule->newport, mi);
    iphead = ip_hdr(skb);
    if(iphead == NULL)
        return network_header_null("dest_translate()", "IP HEADER NULL!");

    if (transrule->nflags.newaddr) {			/* change ip destination address */
        iphead->daddr = transrule->newaddr;
    }
    if (transrule->nflags.newport) {
        switch (transrule->ip.protocol) {
        case IPPROTO_TCP:
            p_tcphead = (struct tcphdr *)((void *)iphead + iphead->ihl * 4);
            p_tcphead->dest = transrule->newport;
            break;
        case IPPROTO_UDP:
            p_udphead = (struct udphdr *)((void *)iphead + iphead->ihl * 4);
            p_udphead->dest = transrule->newport;
            break;

        case IPPROTO_ICMP:
        case IPPROTO_IGMP:
        case IPPROTO_GRE:
        case IPPROTO_PIM:
            break;
        default:
            IPFI_PRINTK("IPFIRE: dest_translate: unsupported protocol: %d\n", transrule->ip.protocol);
            break;
        }
    }
    return 1;
}

int free_dnatted_table(void)
{
    struct list_head *pos;
    struct list_head *q;
    struct dnatted_table *dtl;
    int counter = 0;
    spin_lock_bh(&dnat_list_lock);
    list_for_each_safe(pos, q, &root_dnatted_table.list)
    {
        dtl = list_entry(pos, struct dnatted_table, list);
        if(timer_delete_sync(&dtl->timer_dnattedlist) )
        {
            list_del_rcu(&dtl->list);
            call_rcu(&dtl->dnat_rcuh, free_dnat_entry_rcu_call);
            counter++;
            dnatted_entry_counter--;
        }
    }
    spin_unlock_bh(&dnat_list_lock);
    return counter;
}

/* looks for matches in dynamic denatted tables. If a match is found,
 * rule name is copied to packet */
int pre_denat_table_match(const struct dnatted_table *dnt,
                          const struct sk_buff *skb,
                          ipfire_info_t * packet)
{
    net_quadruplet netquad;
    struct iphdr* iphead;

    if ((skb == NULL) || (dnt == NULL))
        return network_header_null("pre_denat_table_match()", "skb or dnatted_table NULL!");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    iphead = skb->nh.iph;
#else
    iphead = ip_hdr(skb);
#endif
    if(iphead == NULL)
        return network_header_null("pre_denat_table_match()", "IP header NULL!");

    /* if a connection was originated by a remote external node, remote
     * source address had not been changed and so internal host (to
     * which flow had been redirected) already sent response to the
     * right address */
    if (dnt->external)
        return -1;
    netquad = get_quad_from_skb(skb);

    if (!netquad.valid)
    {
        IPFI_PRINTK("IPFIRE: failed to get_quad_from_skb() in pre_denat_table_match()\n");
        return -1;
    }

    if (iphead->protocol != dnt->protocol)
        return -1;
    if (dnt->direction == IPFI_OUTPUT)
    {
        if (dnt->protocol == IPPROTO_ICMP || dnt->protocol == IPPROTO_IGMP ||
                dnt->protocol == IPPROTO_GRE  || dnt->protocol == IPPROTO_PIM)
        {
            if ((netquad.saddr == dnt->new_daddr) && (netquad.daddr == dnt->old_saddr))
                goto success;
        }
        else if ((dnt->protocol == IPPROTO_TCP) || (dnt->protocol == IPPROTO_UDP))
        {
            if ((netquad.saddr == dnt->new_daddr) && (netquad.sport == dnt->new_dport)
                    && (netquad.daddr == dnt->old_saddr) && (netquad.dport == dnt->old_sport))
                goto success;
        }
    }
    else
    {
        if (dnt->protocol == IPPROTO_ICMP || dnt->protocol == IPPROTO_IGMP
                || dnt->protocol == IPPROTO_GRE  || dnt->protocol == IPPROTO_PIM)
        {
            if ((netquad.saddr == dnt->new_daddr) && (netquad.daddr == dnt->old_daddr))
                goto success;
        }
        else if ((dnt->protocol == IPPROTO_TCP) || (dnt->protocol == IPPROTO_UDP))
        {
            if ((netquad.saddr == dnt->new_daddr) && (netquad.sport == dnt->new_dport)
                    && ((netquad.daddr == dnt->old_daddr) || (netquad.daddr == dnt->our_ifaddr))
                    && (netquad.dport == dnt->old_sport))
                goto success;
        }
    }
    return -1;
success:
    return 1;
}

int pre_de_dnat_translate(struct sk_buff *skb,
                          const struct dnatted_table *dnt)
{
    struct pkt_manip_info mi;
    memset(&mi, 0, sizeof(mi));
    /* pre routing hook */
    mi.direction = IPFI_INPUT_PRE;
    if (dnt->direction == IPFI_OUTPUT)
    {
        mi.sa = 1, mi.sp = 1;
        return manip_skb(skb, dnt->old_daddr, dnt->old_dport, 0, 0, mi);
    }
    else
    {
        /* we are interested in changing destination fields */
        mi.da = 1, mi.dp = 1;
        return manip_skb(skb, 0, 0, dnt->old_saddr, dnt->old_sport, mi);
    }
}

/* if a packet hits prerouting hook and comes back from a previously
 * dnatted connection, with ip address translation (i.e. has been forwarded),
 * it must be de-dnatted.
 * This function calls state_machine() to keep the state of the packet
 * and then updates the timer of the entry itself.
 */

int pre_de_dnat(struct sk_buff *skb, ipfire_info_t * packet)
{
    int counter = 0, ret;
    struct dnatted_table *dntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(dntmp, &root_dnatted_table.list, list)
    {
        counter++;
        // *CHECK* no more rulename
        /* pre_denat_table_match() copies rulename from entry
         *
         * to packet if a match is found. For this packet is passed.
         */
        //                //
        if (pre_denat_table_match(dntmp, skb, packet) > 0)
        {
            /* Update the state of the destination nat entry */
            dntmp->state = state_machine(packet, dntmp->state, 1);
            /* Now update the timer of the entry */
            update_dnat_timer(dntmp);
            ret = pre_de_dnat_translate(skb, dntmp);
            rcu_read_unlock_bh();
            return ret;
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

/* set source address of outgoing packet equal to our source address */
int snat_dynamic_translate(struct sk_buff *skb, struct dnatted_table *dnt)
{
    struct pkt_manip_info mi;
    memset(&mi, 0, sizeof(mi));
    mi.sa = 1;
    mi.direction = IPFI_OUTPUT_POST;
    dnt->our_ifaddr = get_ifaddr(skb);
    /* old_daddr was the one pointing to us, NOCHECK because outgoing */
    return manip_skb(skb, dnt->our_ifaddr, 0, 0, 0, mi);
}

int snat_dynamic_table_match(const struct dnatted_table *dnt,
                             const struct sk_buff *skb,
                             ipfire_info_t * packet)
{
    net_quadruplet netq;

    /* if the connection originated from external network, the packet
     * must be forwarded to the internal destination without having its
     * source address changed. If 60.123.11.32 sent to our external interface
     * and we dnatted it to 192.168.1.10, the last wants to see packet
     * arrive from 60.123.11.32, not by us. */
    if (dnt->external)
        return -1;

    /* DNATted packets in OUTPUT direction must not be source address
     * translated */
    if (dnt->direction == IPFI_OUTPUT)
        return -1;

    netq = get_quad_from_skb(skb);
    if (!netq.valid)
    {
        IPFI_PRINTK("IPFIRE: could not correctly get_quad_from_skb() in snat_dynamic_table_match()\n");
        return -1;
    }
    if (dnt->protocol == IPPROTO_ICMP || dnt->protocol == IPPROTO_IGMP
            || dnt->protocol == IPPROTO_GRE  || dnt->protocol == IPPROTO_PIM)
    {
        if ((netq.saddr == dnt->old_saddr) && (netq.daddr == dnt->new_daddr))
            goto success;
    }
    else if ((dnt->protocol == IPPROTO_TCP) || (dnt->protocol == IPPROTO_UDP))
    {
        if ((netq.saddr == dnt->old_saddr) && (netq.sport == dnt->old_sport)
                && (netq.daddr == dnt->new_daddr) && (netq.dport == dnt->new_dport))
            goto success;
    }
    return -1;
success:
    return 1;
}

/* checks in dynamic entries in root nat table looking for a rule matching 
 * the packet in skb to source address-translate in postrouting hook, after
 * a packet has gone in forward hook. Only packets forwarded to another
 * machine should match in snat_dynamic_table_match() (see before).
 * In that case, source address of outgoing forwarded packet must be
 * our address, which we can find in entry->old_daddr (see snat_dynamic
 * _translate() ).
 */
/* Another comment in .h file looks like the following:
 * if NAT is enabled, there might be packets forwarded to another machine.
 * In that case, before leaving local node, source address of leaving packet,
 * which is old address of sending node, must be set to our address, so
 * that destination machine responds to us, unless first packet arrived
 * from external network. This happens in the same flow of originating
 * connection.
 */

int post_snat_dynamic(struct sk_buff *skb, ipfire_info_t * packet)
{
    int counter = 0, ret;
    struct dnatted_table *dntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(dntmp, &root_dnatted_table.list, list)
    {
        counter++;
        /* snat_dynamic_table_match() copies rulename from dynamic
         * entry to packet if a match is found */
        if (snat_dynamic_table_match(dntmp, skb, packet) > 0)
        {
            /* Update the state
             * ! CHECK THE reverse: ok, the same direction of
             * the originating connection
             */
            dntmp->state = state_machine(packet, dntmp->state, 0);
            /* Update the timer */
            update_dnat_timer(dntmp);
            ret = snat_dynamic_translate(skb, dntmp);
            rcu_read_unlock_bh();
            return ret;
        }
    }
    rcu_read_unlock_bh();
    return -1;
}


/* SOURCE NAT OR MASQUERADING SECTION */

int compare_snat_entries(const struct snatted_table *sne1,
                         const struct snatted_table *sne2)
{
    return ((sne1->protocol == sne2->protocol) &&
            (sne1->old_saddr == sne2->old_saddr) &&
            (sne1->old_daddr == sne2->old_daddr) &&
            (sne1->old_dport == sne2->old_dport) &&
            (sne1->old_sport == sne2->old_sport) &&
            (sne1->new_saddr == sne2->new_saddr) &&
            (sne1->new_sport == sne2->new_sport) &&
            (sne1->direction == sne2->direction) &&
            (sne1->in_ifindex == sne2->in_ifindex) &&
            (sne1->out_ifindex == sne2->out_ifindex));

}

/* Looks up in source address translated tables and if 
 * an entry is equal to the entry passed as parameter
 * its timer is updated and a pointer to it is returned.
 * See dnatted lookup function counterpart for further details.
 */
struct snatted_table *lookup_snatted_table_n_update_timer(const struct snatted_table *sne, ipfire_info_t* info)
{
    int counter = 0;
    struct snatted_table *sntmp;
    /* read lock on source nat tables */
    rcu_read_lock_bh();
    list_for_each_entry_rcu(sntmp, &root_snatted_table.list, list)
    {
        counter++;
        if (compare_snat_entries(sntmp, sne) == 1)
        {
            /* Update the state. reverse is 0 */
            sntmp->state = state_machine(info, sntmp->state, 0);
            /* Modify timer while in lock and without being
             * interrupted by timeouts.
             * update_snat_timer updates the timer
             * depending on the state of the connection.
             */
            update_snat_timer(sntmp);
            rcu_read_unlock_bh();
            return sntmp;
        }
    }
    rcu_read_unlock_bh();
    return NULL;
}

int fill_snat_entry_net_fields(struct snatted_table *snentry,
                               const ipfire_info_t * original_pack,
                               const ipfire_rule * snat_rule)
{
    memset(snentry, 0, sizeof(struct snatted_table));
    snentry->protocol = original_pack->packet.iphead.protocol;
    snentry->old_saddr = original_pack->packet.iphead.saddr;
    snentry->old_daddr = original_pack->packet.iphead.daddr;
    /* initialize new address to the value in original packet */
    snentry->new_saddr = original_pack->packet.iphead.daddr;
    snentry->in_ifindex = original_pack->netdevs.in_idx;
    snentry->out_ifindex = original_pack->netdevs.out_idx;
    switch (original_pack->packet.iphead.protocol)
    {
    case IPPROTO_TCP:
        snentry->old_sport =
                original_pack->packet.transport_header.tcphead.source;
        snentry->old_dport =
                original_pack->packet.transport_header.tcphead.dest;
        snentry->new_sport = snentry->old_dport;
        break;
    case IPPROTO_UDP:
        snentry->old_sport =
                original_pack->packet.transport_header.udphead.source;
        snentry->old_dport =
                original_pack->packet.transport_header.udphead.dest;
        snentry->new_sport = snentry->old_dport;
        break;
    case IPPROTO_ICMP:
    case IPPROTO_IGMP:
    case IPPROTO_GRE:
    case IPPROTO_PIM:
        break;
    default:
        printk
                ("IPFIRE: fill_entry_net_fields() (adding dnat entry): invalid protocol: %d.\n",
                 original_pack->packet.iphead.protocol);
        return -1;
        break;
    }
    snentry->direction = original_pack->flags.direction;
    snentry->position = original_pack->response.rulepos;
    /* new values */
    if (snat_rule->nflags.newaddr)
        snentry->new_saddr = snat_rule->newaddr;

    if (snat_rule->nflags.newport)
        snentry->new_sport = snat_rule->newport;

    return 0;
}

/* Callback function for freeing a SNAT entry */
void free_snat_entry_rcu_call(struct rcu_head *head)
{
    struct snatted_table *snatt=
            container_of(head, struct snatted_table, snat_rcuh);
    kfree(snatt);
}


void handle_snatted_entry_timeout(struct timer_list *t)
{
    struct snatted_table *snt_to_free = timer_container_of(snt_to_free, t, timer_snattedlist);
    //      IPFI_PRINTK("IPFIRE: timer expired for dnatted entry %d...", snt_to_free->position);
    /* Acquire lock on source nat table */
    spin_lock_bh(&snat_list_lock);
    timer_delete_sync(&snt_to_free->timer_snattedlist);
    list_del_rcu(&snt_to_free->list);
    call_rcu(&snt_to_free->snat_rcuh, free_snat_entry_rcu_call);
    snatted_entry_counter--;
    /* release lock */
    spin_unlock_bh(&snat_list_lock);
}

void fill_timer_snat_entry(struct snatted_table *snt)
{
    unsigned timeo;
    timeo = get_timeout_by_state(snt->protocol, snt->state);
    timer_setup(&snt->timer_snattedlist, handle_snatted_entry_timeout, 0);
    snt->timer_snattedlist.expires = jiffies + HZ * timeo;
}

int add_snatted_entry(ipfire_info_t * original_pack,
                      const ipfire_rule * snat_rule,
                      ipfire_info_t * packet)
{
    struct snatted_table *snatted_entry;
    struct snatted_table *existing_entry;
    struct sk_buff *skb_to_user;
    ipfire_info_t *ipfi_info_warn;
    /* memory allocation for new entry */
    snatted_entry = (struct snatted_table *) kmalloc(sizeof(struct snatted_table), GFP_ATOMIC);

    if (fill_snat_entry_net_fields (snatted_entry, original_pack, snat_rule) < 0)
    {
        kfree(snatted_entry);
        return -1;
    }
    /* The following first of all updates the state, then the timer */
    if ((existing_entry = lookup_snatted_table_n_update_timer(snatted_entry, original_pack)) != NULL)
    {
        /* An entry is already in list and its timer has
         * been updated.
         */
        kfree(snatted_entry);	/* just kmallocated entry is not of use */
        return 1;	/* entry already existing */
    }
    if (snatted_entry_counter == fwopts.max_nat_entries)
    {
        ipfi_info_warn = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_ATOMIC);
        if(ipfi_info_warn != NULL)
        {
            /* fill in ipfi_info_warn, build info_t_packet and then finally free */
            memset(ipfi_info_warn, 0, sizeof(ipfire_info_t));
            ipfi_info_warn->flags.snat_max_entries = 1;

            // *CHECK* //
            ipfi_info_warn->response.rulepos = fwopts.max_nat_entries;
            //         //
            skb_to_user = build_info_t_packet(ipfi_info_warn);

            if (skb_to_user != NULL && skb_send_to_user(skb_to_user,  LISTENER_DATA) < 0)
                IPFI_PRINTK("IPFIRE: error notifying maximum number of snat entries to user\n");
            else if(!skb_to_user)
                IPFI_PRINTK("IPFIRE: failed to allocate memory for socket buffer in add_snatted_entry()\n");
            /* information sent to userspace: can free ipfi_info_warn */
            kfree(ipfi_info_warn);
        }
        IPFI_PRINTK("IPFIRE: reached maximum count for NATTED entries: %lu.\n",
                    fwopts.max_nat_entries);
        kfree(snatted_entry);	/* just kmallocated entry is not of use */
        return -1;
    }

    /* A new dnat table will be added */
    /* Set the state of the new dnat table */
    snatted_entry->state = state_machine(original_pack,  snatted_entry->state, 0);

    spin_lock_bh(&snat_list_lock);
    fill_timer_snat_entry(snatted_entry);
    /* add timer */
    add_timer(&snatted_entry->timer_snattedlist);
    /* add entry to root table */
    INIT_LIST_HEAD(&snatted_entry->list);
    list_add_rcu(&snatted_entry->list, &root_snatted_table.list);
    spin_unlock_bh(&snat_list_lock);
    return 0;
}

__u32 get_ifaddr(const struct sk_buff * skb)
{
    __u32 newsaddr;
    __be32 dst = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
    struct rtable *rt = (struct rtable *) (skb)->dst;
#else
    struct rtable *rt = skb_rtable(skb); /* include/linux/skbuff.h since 2.6.31 */
#endif
    struct net_device *dev = skb->dev;

    if (dev == NULL) {
        IPFI_PRINTK("IPFIRE: get_ifaddr(): skb->dev is NULL!\n");
        return 0;
    }

    if (rt) {
        const struct iphdr *iph = ip_hdr(skb);
        if (iph)
            dst = iph->daddr;
    }

    newsaddr = inet_select_addr(dev, dst, RT_SCOPE_UNIVERSE);
    return newsaddr;
}

void fill_masquerade_rule_fields(ipfire_rule * ipfr, __u32 newsaddr)
{
    ipfr->nflags.newaddr = 1;
    ipfr->newaddr = newsaddr;
    ipfr->nflags.newport = 0;
    ipfr->newport = 0;
}

/* used after fill_masquerade_rule_fields and translation to clear the newaddr fields 
 * of the rule - otherwise the rule would result modified by the masquerade operation!
 */
void clear_masquerade_rule_fields(ipfire_rule *r)
{
    r->nflags.newaddr = 0;
    r->newaddr = 0;
}

int do_masquerade(struct sk_buff *skb, ipfire_rule * ipfr)
{
    struct pkt_manip_info mi;
    mi.sa = 1, mi.da = 0, mi.sp = 0, mi.dp = 0;
    mi.direction = IPFI_OUTPUT_POST;
    return manip_skb(skb, ipfr->newaddr, 0, 0, 0, mi);
}

int do_source_nat(struct sk_buff *skb, ipfire_rule * ipfr)
{
    return 0;
}

/* Scans user defined translation rules in search of a rule 
 * matching the packet received. If a match is found, a
 * dynamic source nat table is added.
 */
int masquerade_translation(struct sk_buff *skb, ipfire_info_t * packet)
{
    ipfire_rule *transrule;
    int counter = 0, status = -1;
    __u32 masq_addr;

    /* 1. masquerade */
    rcu_read_lock_bh(); /* lock while reading */
    list_for_each_entry_rcu(transrule, &masquerade_post.list, list)
    {
        counter++;
        if (translation_rule_match(packet, transrule) > 0)
        {
            /* there is a rule for our packet to be translated */
            masq_addr = get_ifaddr(skb);
            /* sets new src address on behalf of add_snatted_entry */
            fill_masquerade_rule_fields(transrule, masq_addr);
            /* add_snatted_entry copies rule name from packet to
             * dynamic snat entry */
            if (add_snatted_entry(packet, transrule, packet) == 0)
                snatted_entry_counter++;
            /* masquerade now - while still holding read lock on the list - */
            status = do_masquerade(skb, transrule);
            /* clear the modified new address fields of the rule above set */
            clear_masquerade_rule_fields(transrule);
            rcu_read_unlock_bh(); /* unlock before returning */
            return status;
        }
    }
    rcu_read_unlock_bh(); /* unlock before returning */
    return status; /* -1 as in initialization */
}

int snat_translation(struct sk_buff *skb, ipfire_info_t * packet)
{
    ipfire_rule *snatrule;
    int counter = 0;
    int status = -1;

    /* source nat translation */
    rcu_read_lock_bh(); /* lock while reading */
    list_for_each_entry_rcu(snatrule, &translation_post.list, list)
    {
        counter++;
        if (translation_rule_match(packet, snatrule) > 0)
        {
            /* there is a rule for our packet to be translated */
            /* add_snatted_entry(), if adds a rule, copies name from
             * packet to new entry */
            if (add_snatted_entry(packet, snatrule, packet) == 0)
                snatted_entry_counter++;
            /* call do_source_nat while holding the lock */
            status = do_source_nat(skb, snatrule);
            rcu_read_unlock_bh(); /* unlock before returning */
            return status;
        }
    }
    rcu_read_unlock_bh(); /* unlock before returning */
    return status; /* has still remained -1 */
}

/* restores original source address (changed by snat/masq) in
 * the destination address of coming back packet. We are in pre-
 * routing hook. */
int de_snat(struct sk_buff *skb, struct snatted_table *snt)
{
    struct pkt_manip_info mi;
    /* destination address gets changed */
    mi.sa = 0, mi.da = 1, mi.sp = 0, mi.dp = 0;
    mi.direction = IPFI_INPUT_PRE;
    return manip_skb(skb, 0, 0, snt->old_saddr, 0, mi);
}

int de_snat_table_match(struct snatted_table *snt,
                        struct sk_buff *skb, ipfire_info_t * packet)
{
    net_quadruplet nquad;
    struct iphdr *iphead;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    iphead = skb->nh.iph;
#else
    iphead = ip_hdr(skb);
#endif
    if(iphead == NULL)
        return network_header_null("de_snat_table_match()", "IP header NULL!");

    nquad = get_quad_from_skb(skb);
    if (!nquad.valid)
    {
        return -1;
    }
    /* we don't look for device match here */
    /* Destination address of coming back packet must be
     * equal to new destination address (masqueraded one). Source
     * address and port are unchanged.
     */
    if (iphead->protocol != snt->protocol)
        return -1;

    if (snt->protocol == IPPROTO_ICMP || snt->protocol == IPPROTO_IGMP
            || snt->protocol == IPPROTO_GRE || snt->protocol == IPPROTO_PIM)
    {			/* match only addresses */
        if ((nquad.saddr == snt->old_daddr) && (nquad.daddr == snt->new_saddr))
            goto success;
    }
    else if ((snt->protocol == IPPROTO_TCP) || (snt->protocol == IPPROTO_UDP))
    {
        if ((nquad.saddr == snt->old_daddr) && (nquad.sport == snt->old_dport)
                && (nquad.daddr == snt->new_saddr) && (nquad.dport == snt->old_sport))
            goto success;
    }
    return -1;
success:
    return 1;
}

int pre_de_snat(struct sk_buff *skb, ipfire_info_t * packet)
{
    int counter = 0, ret;
    struct snatted_table *sntmp;
    /* lock snat table */
    rcu_read_lock_bh();
    list_for_each_entry_rcu(sntmp, &root_snatted_table.list, list)
    {
        counter++;
        /* de_snat_table_match() copies rule name into packet if
         * a match is found. For this packet is passed */
        if (de_snat_table_match(sntmp, skb, packet) > 0)
        {
            /* Update the state of the source nat entry */
            sntmp->state = state_machine(packet, sntmp->state, 1);
            /* Then update the timer of the entry, depending on the state */
            update_snat_timer(sntmp);
            ret = de_snat(skb, sntmp);
            rcu_read_unlock_bh();
            return ret;
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

/* checks ip and transport checksums, returning 0  if correct,
 * a negative element of the enum checksum_errors defined in ipfi.h otherwise */
int check_checksums(const struct sk_buff *skb)
{
    __u16 check;
    int datalen;
    struct iphdr *iph = NULL;
    struct tcphdr *th = NULL;
    struct udphdr *uh = NULL;
    struct udphdr udphead;
    struct tcphdr tcphead;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    iph = skb->nh.iph;
#else
    iph = ip_hdr(skb);
#endif
    /* if (skb == NULL) we do not need it here because
     * we reach this point with the check already done.
     */
    if(iph == NULL)
        return network_header_null("check_checksums()",
                                   "IP header NULL");

    datalen = skb->len - iph->ihl * 4;

    check = iph->check;	/* save ip checksum */
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *) iph, iph->ihl);
    if (iph->check != check)	/* wrong checksum */
        return -BAD_IP_CSUM;
    /* tcp */
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        /* check tcp sum. We are in incoming packet context, we should never see
             * CHECKSUM_UNNECESSARY: see include/linux/skbuff.h. If UNNECESSARY
             * is set, skb->csum is undefined. */
        if (skb->ip_summed != CHECKSUM_UNNECESSARY
                && csum_tcpudp_magic(iph->saddr, iph->daddr, datalen, IPPROTO_TCP,
                                     skb->ip_summed == CHECKSUM_HW ? skb-> csum : skb_checksum(skb, iph->ihl * 4, datalen, 0)))
            return -BAD_TCPHEAD_CSUM;
        break;
    case IPPROTO_UDP:
        uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
        /* UDP checksum */
        /* if check is 0, there is no checksum */
        if (!uh->check)
            return 0;
        /* otherwise calculate it */
        if (csum_tcpudp_magic (iph->saddr, iph->daddr, datalen, IPPROTO_UDP, skb->ip_summed ==
                               CHECKSUM_HW ? skb->csum : skb_checksum(skb, iph->ihl * 4, datalen, 0)))
            return -BAD_UDPHEAD_CSUM;
    default:
        break;
    }
    return 0;
}

int free_snatted_table(void)
{
    struct list_head *pos;
    struct list_head *q;
    struct snatted_table *stl;
    int counter = 0;
    synchronize_net();
    spin_lock_bh(&snat_list_lock);
    list_for_each_safe(pos, q, &root_snatted_table.list)
    {
        stl = list_entry(pos, struct snatted_table, list);
        if(timer_delete_sync(&stl->timer_snattedlist) )
        {
            list_del_rcu(&stl->list);
            call_rcu(&stl->snat_rcuh, free_snat_entry_rcu_call);
            counter++;
            snatted_entry_counter--;
        }
    }
    spin_unlock_bh(&snat_list_lock);
    return counter;
}

MODULE_DESCRIPTION("ipfire network address translation functions");
MODULE_AUTHOR("Giacomo S. <jacum@libero.it>");
MODULE_LICENSE("GPL");

//static int __init init(void)
int init_translation(void)
{
    int ret;
    INIT_LIST_HEAD(&root_dnatted_table.list);
    INIT_LIST_HEAD(&root_snatted_table.list);
    ret = nf_register_sockopt(&so_getoriginal_dst);
    if (ret != 0)
    {
        IPFI_PRINTK(KERN_ERR
                    "IPFIRE: unable to register netfilter socket option\n");
        return ret;
    }
    return 0;
}

//static void __exit fini(void)
void fini_translation(void)
{
    int ret;
    ret = free_dnatted_table();
    // 	IPFI_PRINTK("DNAT items: %d entries freed. ", ret);
    ret = free_snatted_table();
    /* see ipfi_machine.c in this directory for the comments on
     * might_sleep() and rcu_barrier()
     */
    might_sleep();
    rcu_barrier();
    // 	IPFI_PRINTK("SNAT items: %d freed.\n", ret);
    nf_unregister_sockopt(&so_getoriginal_dst);
    //IPFI_PRINTK("IPFIRE: sockopt unregistered.\n");
}

