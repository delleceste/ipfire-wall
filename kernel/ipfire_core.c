/* ip firewall Giacomo S. */
#include <linux/module.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include "includes/ipfi.h"
#include "includes/ipfi_netl.h"
#include "includes/ipfi_translation.h"
#include "includes/ipfi_machine.h"
#include "includes/build.h"
#include "includes/ipfi_netl_packet_builder.h"
#include "includes/ipfi_proc.h"
#include "includes/ipfi_tcpmss.h"
#include "includes/ipfi_defrag.h"
#include "includes/module_init.h"

/* since kernel 2.6.25, hook names have changed from _IP_ to _INET_ */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24)

#define NF_IP_PRE_ROUTING 	NF_INET_PRE_ROUTING
#define NF_IP_POST_ROUTING 	NF_INET_POST_ROUTING
#define NF_IP_LOCAL_IN 	NF_INET_LOCAL_IN
#define NF_IP_LOCAL_OUT 	NF_INET_LOCAL_OUT
#define NF_IP_FORWARD		NF_INET_FORWARD

#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giacomo S. <delleceste@gmail.com>");
MODULE_DESCRIPTION("IPv4 packet filter");

/* Versione di test!
 * (C) Giacomo Strangolino, 2005-2026
 * Filtro di pacchetti con funzionalita' di NAT.
 * Il software in kernel space consta di 6 moduli interdipendenti.
 * Per problemi potete scrivere a Giacomo S.
 * posta elettronica: jacum@libero.it
 * Software libero :)
 * Si legga la documentazione per l'uso e l'installazione.
 * I commenti al codice e la documentazione sono in lingua inglese
 * per facilitare la lettura del codice a chi ne avesse bisogno, dal
 * momento che io stesso sono stato aiutato nello svolgimento
 * del progetto da diverse persone sparse in tutto il mondo.
 * Grazie!
 * Giacomo.
 */

/***************************************************************************
 *  Copyright  2005-2026  Giacomo Strangolino.
 *
 *  email:
 *  delleceste@gmail.com
 *
 *  Web Site: 		www.giacomos.it
 *  IPFIRE-wall home: 	www.giacomos.it/ipfire
 *
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

/*
 * Thanks to:
 * Alessandro Rubini, Alexander Harsch, Andrea Barberio, Jozsef Kadlecsik, Diego Billi,
 * Luigi Rizzo, Paul `Rusty' Russell, Andrew Gargan, Daniele orlandi, Stephen Hemminger,
 * Kasper Dupont, Peter T. Breuer, Tauno Voipio;
 */

/* Linux kernel 2.6.9 and above were used for test, together with
 * debian GNU/Linux - www.debian.org - and
 * slackware Linux  - www.slackware.org.
 */

extern short default_policy;
char *policy = "drop";

module_param(policy, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(default_policy,
                 "\"accept\" or \"drop\" policy as default.\n");

int welcome(void);

/* packet counters */
unsigned long long int in_counter = 0;
unsigned long long int out_counter = 0;
unsigned long long int fwd_counter = 0;
unsigned long long int pre_counter = 0;
unsigned long long int post_counter = 0;

time64_t module_load_time;

/* bad checksum counter for packets received */
unsigned badcsum_cnt_rcv = 0;

/* statistics */
extern struct kernel_stats kstats;

/* is loguser enabled? */
extern short loguser_enabled;

extern struct ipfire_options fwopts;

extern struct sock *sknl_ipfi_control;

extern pid_t userspace_control_pid;	/* used for initialization  */
extern pid_t userspace_data_pid;
extern short loguser_enabled;
extern short gui_notifier_enabled;

struct nf_hook_ops nfh_pre, nfh_in, nfh_out, nfh_fwd, nfh_post, nfh_defrag_pre, nfh_defrag_out;

#define KERNEL_MODULE_VERSION "1.99.5"
#define BUILD_DATE 	_BUILD_DATE
#define BUILD_SYS 	_BUILD_SYS

int welcome(void) {
    struct timespec64 tv_load_time;
    IPFI_PRINTK("IPFIRE-wall MODULE INITIALIZED [%s] built on %s, %s\n",
                KERNEL_MODULE_VERSION, BUILD_DATE, BUILD_SYS);
    IPFI_PRINTK("Giacomo S. <delleceste@gmail.com>\n");

    /* set loading time into kernel stats struct */
    ktime_get_real_ts64(&tv_load_time);
    module_load_time = tv_load_time.tv_sec;
    /* Set default policy and write it in kernel stats */
    set_policy(policy);
    init_kernel_stats(&kstats);
    kstats.policy = default_policy;
    kstats.kmod_load_time = module_load_time;
    if (init_procentry(PROCENT, policy) < 0)
        return -1;
    set_procentry_values();
    userspace_control_pid = 0;
    userspace_data_pid = 0;
    init_machine(); /* just calls INIT_LIST_HEAD(&root_state_table.list); */
    init_translation();
    init_log();
    if(init_netl() == 0) {
        register_hooks();
    }
    return 0;
}

static int __init ini(void) {
    return welcome();
}

static void __exit fini(void) {
    IPFI_PRINTK("IPFIRE-wall unloading:  \n");

    /* net/core/dev.c : synchronizes with packet receive processing.
         * calls might_sleep() and
         * synchronize_rcu()
         */
    synchronize_net();

    /* Stop receiving anything from the network */
    /* Stop receiving anything from the network */
    nf_unregister_net_hook(&init_net, &nfh_pre);
    nf_unregister_net_hook(&init_net, &nfh_in);
    nf_unregister_net_hook(&init_net, &nfh_out);
    nf_unregister_net_hook(&init_net, &nfh_post);
    nf_unregister_net_hook(&init_net, &nfh_fwd);
    nf_unregister_net_hook(&init_net, &nfh_defrag_out);
    nf_unregister_net_hook(&init_net, &nfh_defrag_pre);

    /* will call might_sleep() and rcu_barrier() */
    fini_machine();
    /* will call might_sleep() and rcu_barrier() */
    fini_translation();
    /* will call might_sleep() and rcu_barrier() */
    fini_log();

    /* fini_netl(): just calls sock_release on the netlink socket */
    fini_netl();
    clean_proc();
}


void set_policy(const char *def_policy) {
    if (strncmp(def_policy, "accept", 6) == 0) {
        kstats.policy = default_policy = 1;
        printk("IPFIRE: default policy: ACCEPT packets which do not match any rule.\n");
    } else {
        kstats.policy = default_policy = 0;
        printk("IPFIRE: default policy: DROP packets not matching rules.\n");
    }
}

// enum nf_ip_hook_priorities {
// 	NF_IP_PRI_FIRST = INT_MIN,
// 	NF_IP_PRI_CONNTRACK_DEFRAG = -400,
// 	NF_IP_PRI_RAW = -300,
// 	NF_IP_PRI_SELINUX_FIRST = -225,
// 	NF_IP_PRI_CONNTRACK = -200,
// 	NF_IP_PRI_MANGLE = -150,
// 	NF_IP_PRI_NAT_DST = -100,
// 	NF_IP_PRI_FILTER = 0,
// 	NF_IP_PRI_SECURITY = 50,
// 	NF_IP_PRI_NAT_SRC = 100,
// 	NF_IP_PRI_SELINUX_LAST = 225,
// 	NF_IP_PRI_CONNTRACK_CONFIRM = INT_MAX,
// 	NF_IP_PRI_LAST = INT_MAX,
// };

int register_hooks(void)
{
    /* pre routing */
    /* defrag */
    nfh_defrag_pre.pf     = PF_INET;
    nfh_defrag_pre.hook       = ipfi_defrag;
    nfh_defrag_pre.hooknum    = NF_INET_PRE_ROUTING;
    nfh_defrag_pre.priority   = NF_IP_PRI_CONNTRACK_DEFRAG;
    nf_register_net_hook(&init_net, &nfh_defrag_pre);

    nfh_pre.pf = PF_INET;
    nfh_pre.hooknum = NF_IP_PRE_ROUTING;
    /* make our function last (packets will arrive defragmented..) */
    nfh_pre.priority = NF_IP_PRI_NAT_DST;
    nfh_pre.hook = deliver_process_by_direction;
    nf_register_net_hook(&init_net, &nfh_pre);

    /* input */
    nfh_in.pf = PF_INET;
    nfh_in.hooknum = NF_IP_LOCAL_IN;
    nfh_in.priority = NF_IP_PRI_FILTER;
    nfh_in.hook = deliver_process_by_direction;
    nf_register_net_hook(&init_net, &nfh_in);

    /* forward */
    nfh_fwd.pf = PF_INET;
    nfh_fwd.hooknum = NF_IP_FORWARD;
    nfh_fwd.priority = NF_IP_PRI_FILTER;	/* make our function first */
    nfh_fwd.hook = deliver_process_by_direction;
    nf_register_net_hook(&init_net, &nfh_fwd);

    /* output */
    nfh_out.pf = PF_INET;
    nfh_out.hooknum = NF_IP_LOCAL_OUT;
    nfh_out.priority = NF_IP_PRI_FILTER;	/* make our function first */
    nfh_out.hook = deliver_process_by_direction;
    nf_register_net_hook(&init_net, &nfh_out);

    /* defrag */
    nfh_defrag_out.pf     = PF_INET;
    nfh_defrag_out.hook       = ipfi_defrag;
    nfh_defrag_out.hooknum    = NF_INET_LOCAL_OUT;
    nfh_defrag_out.priority   = NF_IP_PRI_CONNTRACK_DEFRAG;
    nf_register_net_hook(&init_net, &nfh_defrag_out);

    /* post routing */
    nfh_post.pf = PF_INET;
    nfh_post.hooknum = NF_IP_POST_ROUTING;
    nfh_post.priority = NF_IP_PRI_NAT_SRC;	/* make our function first */
    nfh_post.hook = deliver_process_by_direction;
    nf_register_net_hook(&init_net, &nfh_post);

    return 0;
}

unsigned int deliver_process_by_direction(void *priv,
                                          struct sk_buff *skb,
                                          const struct nf_hook_state *state)
{
    unsigned int hooknum = state->hook;
    const struct net_device *in = state->in;
    const struct net_device *out = state->out;
    unsigned int ret;
    __be32 daddr;
    ipfi_flow flow = {in, out, NODIRECTION };
    // packet truncated or malformed?
    if (!pskb_may_pull(skb, ip_hdrlen(skb)))
        return IPFI_DROP;

    switch (hooknum)
    {
    case NF_IP_PRE_ROUTING:
        pre_counter++;
        daddr = ip_hdr(skb)->daddr; /* save original destination address */
        ret = ipfi_pre_process(skb, pre_counter, IPFI_INPUT_PRE, in);
        if (ret != NF_DROP && ret != NF_STOLEN && daddr != ip_hdr(skb)->daddr) {
            /* destination nat applied and destination address changed in pre routing */
            dst_release(skb_dst(skb));
            skb_dst_set(skb, NULL);
        }
        return ret;
    case NF_IP_LOCAL_IN:
        in_counter++;
        flow.direction = IPFI_INPUT;
        return ipfi_response(skb, &flow);
    case NF_IP_LOCAL_OUT:
        out_counter++;
        flow.direction = IPFI_OUTPUT;
        return ipfi_response(skb,  &flow);
    case NF_IP_FORWARD:
        fwd_counter++;
        flow.direction = IPFI_FWD;
        return ipfi_response(skb,  &flow);
    case NF_IP_POST_ROUTING:
        post_counter++;
        flow.direction = IPFI_OUTPUT_POST;
        return ipfi_post_process(skb,  &flow);
    default:
        return IPFI_DROP;
    }
    return IPFI_DROP;
}

void init_packet(ipfire_info_t * iit)
{
    memset(iit, 0, sizeof(ipfire_info_t));
}

void init_kernel_stats(struct kernel_stats *nl_kstats)
{
    memset(nl_kstats, 0, sizeof(struct kernel_stats));
}

/* updates sent counter, sends packet to userspace and calls
 * update_kernel_stats()
 */
inline int
send_packet_to_userspace_and_update_counters(ipfire_info_t * packet)
{
    struct sk_buff *skb_to_user = NULL;
    update_sent_counter(packet->flags.direction);
    skb_to_user = build_info_t_packet(packet);
    if(skb_to_user != NULL && skb_send_to_user(skb_to_user, LISTENER_DATA) < 0)
    {
        update_kernel_stats(IPFI_FAILED_NETLINK_USPACE, packet->response.value);
        return -1;
    }
    else if(skb_to_user == NULL)
    {
        IPFI_PRINTK("IPFIRE: failed to allocate memory for socket buffer in send_packet_to_userspace_and_update_counters()\n");
        return -1;
    }
    return 0;
}

int ipfi_pre_process(struct sk_buff *skb, unsigned long long packet_num,
                     int direction, const struct net_device *in)
{
    int ret = -1;
    short b1, b2;
    ipfire_info_t *packet, *saved_packet;
    int verdict;
    /* in pre routing we do not do any filtering. In normal cases we will return IPFI_ACCEPT as verdict in this hook.
         * In case of errors instead, we'll return IPFI_DROP, to interrupt packet processing. This happens in case of
         * checksum error in incoming packets or (unprobable) memory allocation errors
         */
    verdict = IPFI_ACCEPT;
    /* update statistics about pre processed packets */
    kstats.pre_rcv++;

    /* nat and masquerade options disabled: return IPFI_ACCEPT in pre process */
    if ((fwopts.masquerade == 0) && (fwopts.nat == 0)) {
        return IPFI_ACCEPT;
    }

    /* MASQUERADE or NAT are enabled: go on! */

    /* allocate memory for ipfire_info_t structures */
    packet = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_ATOMIC);
    saved_packet = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_ATOMIC);

    if(saved_packet == NULL || packet == NULL) /* alloc failed! */
    {
        IPFI_PRINTK("IPFIRE: ipfi_pre_process(): memory allocation failed. Dropping packet.\n");
        return IPFI_DROP;
    }

    /* structures allocated successfully: init them */
    init_packet(packet);
    init_packet(saved_packet);

    /* save old packet in case it will be modified by translation */
    b1 = build_ipfire_info_from_skb(skb, saved_packet, direction, packet_num, in, NULL);
    b2 = build_ipfire_info_from_skb(skb, packet, direction, packet_num, in, NULL);

    if(b1 < 0 || b2 < 0)
    {
        IPFI_PRINTK("build_ipfire_info_from_skb() failed in ipfi_pre_process(). Returning DROP...(fragment?)\n");
        kfree(packet);
        kfree(saved_packet);
        return IPFI_DROP;
    }

    /* if a packet comes back from a dnatted connection,
         * i.e. has been forwarded, we must de dnat it. Dynamic
         * rules are checked in this case.
         */
    ret = pre_de_dnat(skb, packet);

    /* implements pre processing of the packets: DNAT.
         * dnat_translation() requires direct match with DNAT
         * rules inserted by user.
         * Explicit rule match has the precedence on dynamic entries
         */
    if(ret < 0) /* no pre_de_dnat, maybe dnat_translation */
        ret = dnat_translation(skb, packet, IPFI_INPUT_PRE);

    /* now let's de-snat, or de-masquerade, if no match has previously succeeded */
    if(ret < 0)
        ret = pre_de_snat(skb, packet);

    /* checksum is calculated inside set_pairs_in_skb(), ipfi_translation.c */
    if (ret >= 0)
    {
        saved_packet->flags.nat = 1;
        saved_packet->flags.direction = IPFI_INPUT_PRE;

        /* we send to userspace old packet, to let see how translation changed it,
                 * if loguser is greater than 5 */
        if ((userspace_data_pid) && (loguser_enabled) && (is_to_send(saved_packet, &fwopts)))
            send_packet_to_userspace_and_update_counters(saved_packet);
        else		/* not sent because of log level */
            kstats.not_sent++;
    }
    else if (ret == BAD_CHECKSUM)
    {
        kstats.bad_checksum_in++;
        saved_packet->flags.badsum = 1;
        IPFI_PRINTK("IPFIRE: bad checksum on incoming packet %llu over %llu received.\n", kstats.bad_checksum_in, kstats.pre_rcv);
        /* send a packet signaling an error */
        send_packet_to_userspace_and_update_counters(saved_packet);
        verdict = IPFI_DROP;
    }
    /* free memory allocated for ipfire_info_t structures */
    kfree(packet);
    kfree(saved_packet);
    return verdict;
}

int ipfi_post_process(struct sk_buff *skb, unsigned long long packet_num,
                      int direction, const struct net_device *out)
{
    /* do post routing tasks. Checksumming is performed in set_pairs_in_skb(), the manipulation
         * function inside ipfi_translation.c
         */
    int de_dnat_done = -1, snat_done = -1;
    ipfire_info_t *post_packet;

    /* stats. Only one field is to be updated.
         * So don't call update_kernel_stats().
         */
    kstats.post_rcv++;
    /* masquerade and NAT disabled: nothing to do. We accept here */
    if ((fwopts.masquerade == 0) && (fwopts.nat == 0))
        return IPFI_ACCEPT;

    /* allocate memory for ipfire_info_t structures */
    post_packet = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_ATOMIC);
    if(post_packet == NULL)
    {
        IPFI_PRINTK("IPFIRE: memory alloc failed in ipfi_post_process():dropping.\n");
        return IPFI_DROP;
    }
    /* alloc successful */
    init_packet(post_packet);

    /* if MASQUERADE is enabled, we must source nat the packet.
         * This also goes for SNAT. */
    if (build_ipfire_info_from_skb(skb, post_packet, direction, packet_num, NULL, out) < 0)
    {
        kfree(post_packet); /* free and return */
        return IPFI_DROP;
    }

    /* if NAT is enabled, there might be packets forwarded to another machine.
         * In that case, before leaving local node, source address of leaving packet,
         * which is old address of sending node, must be set to our address, so
         * that destination machine responds to us, unless first packet arrived
         * from external network. This happens in the same flow of originating
         * connection.
         */
    if ((snat_done = post_snat_dynamic(skb, post_packet)) >= 0)
        goto send_touser;

    /* If NAT is enabled, there might be packets that have been destination natted
         * in pre routing phase. Those packets must be de-natted: source address must
         * be put equal to the original destination address of the dnatted packet.
         * We must check if packet has destination address _and_  port equal to source
         * address _and_ port of dnatted packet. This happens in the opposite flow with
         * respect to the one that originated communication.
         */
    de_dnat_done = de_dnat_translation(skb, post_packet);

    /* masquerade_translation() scans masquerade_post list */
    if ((snat_done = masquerade_translation(skb, post_packet)) >= 0)
        goto send_touser;

    /* snat_translation scans translation_post list */
    snat_done = snat_translation(skb, post_packet);

send_touser:

    if ((snat_done >= 0) || (de_dnat_done >= 0))
    {
        /* alloc ok: init packet */
        init_packet(post_packet);
        /* update post packet with new skb */
        build_ipfire_info_from_skb(skb, post_packet, direction, packet_num, NULL, out);
        post_packet->flags.nat = 1;

        if (snat_done >= 0)
            post_packet->flags.snat = 1;

        if ((userspace_data_pid) && (loguser_enabled) && (is_to_send(post_packet, &fwopts)))
            send_packet_to_userspace_and_update_counters(post_packet);
        else		/* not sent because of log level */
            kstats.not_sent++;
    }
    /* Don't check for bad checksum on outgoing packets.
         * See netfilter ip_conntrack_proto_tcp.c comment */

    /* free memory */
    kfree(post_packet);     /* free post packet */
    return IPFI_ACCEPT;
}

/* The following three functions extract from the socket buffer
 * skb the tcp/udp/icmp header.
 * Since allocate_headers() already extracts the IP header,
 * allocate_headers() itself passes this header to build_xxxh_usermess()
 * for convenience
 */
inline int build_tcph_usermess(const struct sk_buff *skb,
                               const struct iphdr* iph,
                               ipfire_info_t * ipfi_info)
{
    struct tcphdr *p_tcphead;	/* a pointer */
    struct tcphdr tcphead;	/* an object */

    /* we must get tcp header pointer this way, pointing after ip header in
         * our struct skb. Ip header and transport header point at the same
         * location in memory. We cannot use tcp_hdr() - introduced in linux-2.6.22
         * because in INPUT tcp_hdr() data has not been initialized.
         */
    p_tcphead = skb_header_pointer(skb, iph->ihl * 4, sizeof(tcphead), &tcphead);
    if (check_tcp_header_from_skb(skb, p_tcphead) < 0)	/* we can't examine this packet, we drop it */
        return -1;
    /* we fill in our userspace information */
    memcpy(&(ipfi_info->packet.transport_header.tcphead), p_tcphead, sizeof(tcphead));
    return 0;
}

/* See build_tcph_usermess() above for the comments */
inline int build_udph_usermess(const struct sk_buff *skb,
                               const struct iphdr* iph,
                               ipfire_info_t * ipfi_info)
{
    struct udphdr *p_udphead;
    struct udphdr udphead;

    /* Cannot use udp_hdr() in input */
    p_udphead = skb_header_pointer(skb, iph->ihl * 4, sizeof(udphead), &udphead);
    if (check_udp_header_from_skb(skb, p_udphead) < 0)	/* we can't examine this packet, we drop it */
        return -1;
    memcpy(&(ipfi_info->packet.transport_header).udphead, p_udphead, sizeof(udphead));
    return 0;
}

/* See build_tcph_usermess() above for the comments */
inline int build_icmph_usermess(const struct sk_buff *skb,
                                const struct iphdr* iph,
                                ipfire_info_t * ipfi_info)
{
    struct icmphdr *p_icmphead;
    struct icmphdr icmphead;
    /* Get ICMP header */
    p_icmphead = skb_header_pointer(skb, iph->ihl * 4, sizeof(struct icmphdr), &icmphead);

    if (p_icmphead == NULL)
        return network_header_null("build_icmph_usermess()", "ICMP header NULL!");
    memcpy(&(ipfi_info->packet.transport_header).icmphead, p_icmphead, sizeof(icmphead));
    return 0;
}

/* since version 0.98.7 we support the IGMP protocol */
inline int build_igmph_usermess(const struct sk_buff *skb,
                                const struct iphdr* iph,
                                ipfire_info_t * ipfi_info)
{
    struct igmphdr *p_igmphead;
    struct igmphdr igmphead;
    /* Get IGMP header */
    p_igmphead = skb_header_pointer(skb, iph->ihl * 4, sizeof(struct igmphdr), &igmphead);

    if (p_igmphead == NULL)
        return network_header_null("build_igmph_usermess()",  "IGMP header NULL!");
    memcpy(&(ipfi_info->packet.transport_header).igmphead, p_igmphead, sizeof(igmphead));
    return 0;
}

inline int copy_headers(const struct sk_buff *skb,
                        ipfire_info_t * fireinfo)
{
    struct iphdr *iph;
    iph = ip_hdr(skb);

    if(iph == NULL)
        return network_header_null("allocate_headers()", "IP HEADER null");

    /* protocol information */
    fireinfo->packet.iphead.protocol = iph->protocol;

    /* internet header */
    memcpy(&fireinfo->packet.iphead, iph, sizeof(struct iphdr));

    /* tcp, udp icmp headers? */
    if (iph->protocol == IPPROTO_TCP)
    {
        if (build_tcph_usermess(skb, iph, fireinfo) < 0)
            return -1;
    }
    else if (iph->protocol == IPPROTO_UDP)
    {
        if (build_udph_usermess(skb, iph, fireinfo) < 0)
            return -1;
    }
    else if (iph->protocol == IPPROTO_ICMP)
    {
        if (build_icmph_usermess(skb, iph, fireinfo) < 0)
            return -1;
    }
    else if (iph->protocol == IPPROTO_IGMP) /* since 0.98.7 */
    {
        if (build_igmph_usermess(skb, iph, fireinfo) < 0)
            return -1;
    }
    return 0;
}

int build_ipfire_info_from_skb(const struct sk_buff *skb,
                               ipfire_info_t * iit,
                               int direction,
                               const struct net_device *in,
                               const struct net_device *out) {
    if (skb == NULL)
        return network_header_null("build_ipfire_info_from_skb()", "socket buffer null");
    iit->flags.direction = direction;
    if (copy_headers(skb, iit) < 0)
        return -1;
    iit->netdevs.in_idx = in != NULL ? in->ifindex : -1;
    iit->netdevs.out_idx = out != NULL ? out->ifindex : -1;
    return 0;
}

int ipfi_response(struct sk_buff *skb, flow* _flow) {
    // ipfire_info_t *fireinfo = NULL;
    /* 0.98.4: When we have to DNAT in output direction, we have to
         * check if the original destination is allowed by the
         * filter rules. Imagine we have setup a proxy web and the
         * user wants to block connections to www.badsite.com.
         * If the output connections are redirected to the proxy
         * by means of an OUTPUT DNAT rule, the connection will
         * pass through also if it is not desired.
         */
    struct info_flags flags;
    struct response   res = iph_in_get_response(skb, direction, in, out, &flags);
    /* decide according to loguser if to send or not feedback */
    if ((userspace_data_pid) && (loguser_enabled)) {
        /* Checks for skb null */
        if (build_ipfire_info_from_skb(skb, fireinfo, direction, packet_num, in, out) < 0) {
            kfree(fireinfo); /* release just allocated memory */
            return IPFI_DROP;
        }
        if((is_to_send(skb, res, &fwopts) > 0)) {
            /*int sent = */update_sent_counter(direction);
            struct sk_buff* skb_touser = build_info_t_packet(fireinfo);
            if(skb_touser == NULL) /* shouldn't happen :r */
                IPFI_PRINTK("IPFIRE: failed to allocate memory for socket buffer in iph_in_get_response()\n");
            else if(skb_send_to_user(skb_touser, LISTENER_DATA) < 0)
                update_kernel_stats(IPFI_FAILED_NETLINK_USPACE, res.value);
        }

        /* if gui_notifier_enabled we send the info if there is no match (popup
                 * asking the user the verdict for the new seen packet - if directions are in or out -)
                 * OR if there was a rule matching and a notification was requested for tha
                 * packets matching _that_ rule.
                 */
        if(gui_notifier_enabled && ((res.value == 0 && direction != IPFI_FWD) ||
                                    (res.value  != 0 && res.notify)) )
        {
            /* previous socket buffer sent to userspace: the kernel will have freed it...
                     * so the pointer skb_touser is no more valid: create a new socket buffer
                     * with the same ipfire_info_t contents: this will be sent via the notifier
                     * socket.
                     */
            struct sk_buff* skb_touser = build_info_t_packet(fireinfo);
            if (skb_touser != NULL && skb_send_to_user(skb_touser,  GUI_NOTIF_DATA) < 0)
                update_kernel_stats(IPFI_FAILED_NETLINK_USPACE, res.value);
        }

    }
    if(fireinfo == NULL)	/* packets not sent because of log level */
        kstats.not_sent++;

    /* update the sum of the packets processed */
    kstats.sum++;

    if(res.value > 0)
    {
        /* in output direction we can do DNAT, if the packet locally
            * generated is allowed to leave for its destination (i.e. ret > 0).
                * No need to recalculate the header checksum. The work is done inside
                * ipfi_translation: set_pairs_in_skb().
            */
        if (fwopts.nat != 0 && direction == IPFI_OUTPUT )
        {
            if (dnat_translation(skb, fireinfo, IPFI_OUTPUT) >= 0)
            {
                // 		  recalculate_ip_checksum(skb, IPFI_OUTPUT);
                if (build_ipfire_info_from_skb(skb, fireinfo, direction, packet_num, NULL, out) < 0)
                {
                    kfree(fireinfo);
                    return IPFI_DROP;
                }
            }
        }
    } /* ret > 0 */

    /* update statistics */
    update_kernel_stats(direction, res.value);

    /* release temporary memory used by fireinfo */
    if(fireinfo != NULL)
        kfree(fireinfo);

    /* return the response */
    if (res.value > 0)
        return IPFI_ACCEPT;
    else if (res.value == 0)
        return default_policy;
    else
        return IPFI_DROP;
}

/* no more needed since 1.96 */
int recalculate_ip_checksum(struct sk_buff *skb, int direction)
{
    int len;
    int datalen;
    int iph_sum_old;
    struct iphdr *iph;
    struct tcphdr *th;
    struct udphdr *uh;
    struct udphdr udphead;
    struct tcphdr tcphead;

    if (skb == NULL)
        return network_header_null("recalculate_ip_checksum()",
                                   "socket buffer NULL");
    len = skb->len;
    iph = ip_hdr(skb);

    if(iph == NULL)
        return network_header_null("recalculate_ip_checksum()", "IP header NULL");

    datalen = skb->len - iph->ihl * 4;
    iph_sum_old = iph->check;
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *) iph, iph->ihl);

    /* tcp */
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        th = skb_header_pointer(skb, iph->ihl * 4,
                                sizeof(tcphead), &tcphead);

        /* check not null and not malformed */
        if (check_tcp_header(th, datalen) < 0)
            return -1;
        th->check = 0;
        th->check =  csum_tcpudp_magic(iph->saddr, iph->daddr, datalen,
                                       IPPROTO_TCP, skb_checksum(skb, iph->ihl * 4, datalen, 0));
        break;
    case IPPROTO_UDP:

        uh = skb_header_pointer(skb, iph->ihl * 4,
                                sizeof(udphead), &udphead);

        if (check_udp_header(uh, datalen) < 0)
            return -1;
        /* udp sum not present */
        if (!uh->check)
            break;
        uh->check = 0;
        uh->check =
                csum_tcpudp_magic(iph->saddr,
                                  iph->daddr,
                                  datalen,
                                  IPPROTO_UDP,
                                  csum_partial((char *) uh, datalen,
                                               0));
    default:
        break;
    }
    /* see include/skbuff.h: "B.Checksumming on output":
         * CHECKSUM_NONE: skb is checksummed by protocol or csum is not required.
         * If checksum is calculated here, no need to recalculate it. */
    if ((direction == IPFI_OUTPUT) || (direction == IPFI_OUTPUT_POST))
        skb->ip_summed = CHECKSUM_NONE;
    return 0;
}


module_init(ini);
module_exit(fini);
