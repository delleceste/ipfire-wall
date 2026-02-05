/* filter/rule_match.c: Rule matching logic for ipfire-wall */

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include "ipfi.h"
#include "ipfi_machine.h"

inline int direction_filter(int direction, const ipfire_rule * r)
{
    if (r->nflags.direction)
    {
        if (r->direction != direction)
            return -1;
        return 1;
    }
    return 0;
}

int device_filter(const ipfire_rule * r,
                  const struct net_device *in,
                  const struct net_device *out)
{
    /* don't bother if user fills in output rule within input context
        * or viceversa */
    if (r->nflags.indev && in != NULL) {
        if (in->ifindex == r->devpar.in_ifindex)
            return 1;
        else
            return -1;
    }

    if (r->nflags.outdev && out != NULL) {
        if(out->ifindex == r->devpar.out_ifindex)
            return 1;
        else
            return -1;
    }
    return 0;
}

int address_match(const struct iphdr * iph,
                  const ipfire_rule * r,
                  int direction,
                  const struct net_device *in,
                  const struct net_device *out)
{
    int match = 0;
    int i, addr_in_list;
    __u32 source_address, p_source_address;
    __u32 dest_address, p_dest_address;

    /* source address */
    /* Set correct source and destination address: the one corresponding
    * to the interface in packet if MYADDR was specified, the dotted
    * decimal one if ADDR is specified in flags */
    if (r->nflags.src_addr == MYADDR) {
        if (get_dev_ifaddr(&p_source_address, direction, in, out) < 0) {
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
        if (source_address != iph->saddr)
            return -1;
        else
            match = 1;
    }
    /* an interval is given: src address in packet must be contained in it.
    * Addresses cannot be mine */
    else if ((r->nflags.src_addr == ONEADDR) && (r->parmean.samean == INTERVAL))
    {
        if ((ntohl(r->ip.ipsrc[0]) <= ntohl(iph->saddr)) && (ntohl(r->ip.ipsrc[1]) >= ntohl(iph->saddr))) {
            match = 1;
        }
        else
            return -1;
    }
    /* address in packet must be different from address in rule */
    else if ((r->nflags.src_addr) && (r->parmean.samean == DIFFERENT_FROM))
    {
        if (source_address != iph->saddr)
            match = 1;
        else
            return -1;
    }
    /* finally: src address in packet must be not included in rule source ip interval */
    else if ((r->nflags.src_addr == ONEADDR) && (r->parmean.samean == INTERVAL_DIFFERENT_FROM))
    {
        if ((ntohl(r->ip.ipsrc[0]) <= ntohl(iph->saddr)) && (ntohl(r->ip.ipsrc[1]) >= ntohl(iph->saddr)))
            return -1;
        else		/* saddr of iphead not contained: ok */
            match = 1;
    }
    else if ((r->nflags.src_addr == ONEADDR) && (r->parmean.samean == MULTI))
    {
        for(i = 0; i < MAXMULTILEN && r->ip.ipsrc[i] != 0; i++)
        {
            if(r->ip.ipsrc[i] == iph->saddr)
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
            if(r->ip.ipsrc[i] == iph->saddr) /* one element of the list matches */
                return -1; /* then if one element matches source address, we must leave */
        }
    }
    /* destination address */
    if (r->nflags.dst_addr == MYADDR)
    {
        if (get_dev_ifaddr(&p_dest_address, direction, in, out) < 0)
        {
            return -1;
        }
        dest_address = p_dest_address;
    }
    else
        dest_address = r->ip.ipdst[0];

    if ((r->nflags.dst_addr > 0) && (r->parmean.damean == SINGLE))
    {
        if (dest_address != iph->daddr)
            return -1;
        else
            match = 1;
    }
    else if ((r->nflags.dst_addr == ONEADDR) && (r->parmean.damean == INTERVAL))
    {
        if ((ntohl(r->ip.ipdst[0]) <= ntohl(iph->daddr)) && (ntohl(r->ip.ipdst[1]) >= ntohl(iph->daddr)))
            match = 1;
        else
            return -1;
    }
    else if ((r->nflags.dst_addr > 0) && (r->parmean.damean == DIFFERENT_FROM))
    {
        if (dest_address != iph->daddr)
            match = 1;
        else
            return -1;
    }
    else if ((r->nflags.dst_addr == ONEADDR) && (r->parmean.damean == INTERVAL_DIFFERENT_FROM))
    {
        if ((ntohl(r->ip.ipdst[0]) <= ntohl(iph->daddr)) && (ntohl(r->ip.ipdst[1]) >= ntohl(iph->daddr)))
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
            if(r->ip.ipdst[i] == iph->daddr)
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
            if(r->ip.ipdst[i] == iph->daddr) /* one element of the list matches */
                return -1; /* then if one element matches destination address, we must leave with -1 */
        }
    }
    return match;
}

int port_match(const struct tcphdr *tcph,
               const struct udphdr *udph,
               const ipfire_rule * r,
               short protocol)
{
    int match = 0, sport_found = 0, dport_found = 0;
    int i;
    u16 sport;
    u16 dport;
    switch (protocol)
    {
    case IPPROTO_TCP:
        sport = tcph->source;
        dport = tcph->dest;
        break;
    case IPPROTO_UDP:
        sport = udph->source;
        dport = udph->dest;
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

int ip_layer_filter(const struct iphdr *iph, const ipfire_rule* r, int direction,
                    const struct net_device *in, const struct net_device *out)
{
    int match = 0;
    if ((match = address_match(iph, r, direction, in, out)) < 0) {
        return -1;
    }
    if (iph && r->nflags.proto) { // filter by proto
        if (r->ip.protocol != iph->protocol)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.tot_len)
    {
        if (r->ip.total_length != iph->tot_len)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.tos)
    {
        if (r->ip.tos != iph->tos)
            return -1;
        else
            match = 1;
    }
    return match;
}

int ipfi_tcp_filter(const struct tcphdr *tcph, const ipfire_rule * r)
{
    int match = 0;
    /* check tcp specific fields */
    if ((match = port_match(tcph, NULL, r, IPPROTO_TCP)) < 0)
    {
        return -1;
    }
    if (r->nflags.fin)
    {
        if (r->tp.fin != tcph->fin)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.syn)
    {
        if (r->tp.syn != tcph->syn)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.rst)
    {
        if (r->tp.rst != tcph->rst)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.psh)
    {
        if (r->tp.psh != tcph->psh)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.ack)
    {
        if (r->tp.ack != tcph->ack)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.urg)
    {
        if (r->tp.urg != tcph->urg)
            return -1;
        else
            match = 1;
    }
    return match;
}

int udp_filter(const struct udphdr *udph, const ipfire_rule * r)
{
    int match = 0;
    /* check tcp specific fields */
    if ((match = port_match(NULL, udph, r, IPPROTO_UDP)) < 0)
        return -1;
    return match;
}

int icmp_filter(const struct icmphdr * icmph, const ipfire_rule * r)
{
    int match = 0;
    /* icmp specific fields */
    if (r->nflags.icmp_type)
    {
        if (r->icmp_p.type != icmph->type)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.icmp_code)
    {
        if (r->icmp_p.code != icmph->code)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.icmp_echo_id)
    {
        if (r->icmp_p.echo_id != icmph->un.echo.id)
            return -1;
        else
            match = 1;
    }
    if (r->nflags.icmp_echo_seq)
    {
        if (r->icmp_p.echo_seq != icmph->un.echo.sequence)
            return -1;
        else
            match = 1;
    }
    /* disabled icmp_frag_mtu. */
    return match;
}
