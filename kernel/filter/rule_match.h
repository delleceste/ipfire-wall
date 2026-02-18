#ifndef IPFI_RULE_MATCH_H
#define IPFI_RULE_MATCH_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <common/ipfi_structures.h>

int direction_filter(int direction, const ipfire_rule *r);
int device_filter(const ipfire_rule *r, const struct net_device *in, const struct net_device *out);
int address_match(const struct iphdr *iph, const ipfire_rule *r, int direction, const struct net_device *in, const struct net_device *out, struct net *net);
int port_match(const struct tcphdr *tcph, const struct udphdr *udph, const ipfire_rule *r, short protocol);
int ip_layer_filter(const struct iphdr *iph, const ipfire_rule *r, int direction, const struct net_device *in, const struct net_device *out, struct net *net);
int ipfi_tcp_filter(const struct tcphdr *tcph, const ipfire_rule *r);
int udp_filter(const struct udphdr *udph, const ipfire_rule *r);
int icmp_filter(const struct icmphdr *icmph, const ipfire_rule *r);

#endif
