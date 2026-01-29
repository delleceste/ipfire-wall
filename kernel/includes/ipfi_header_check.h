#ifndef IPFI_HEADER_CHECK_H
#define IPFI_HEADER_CHECK_H

#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/version.h>

/* the following two check for headers not null and not malformed */			
int check_udp_header(const struct udphdr* uh, int udphlen);		
int check_tcp_header(const struct tcphdr* th, int tcphlen);
int check_tcp_header_from_skb(const struct sk_buff *skb, const struct tcphdr* tcph);
int check_udp_header_from_skb(const struct sk_buff *skb, const struct udphdr* udph);

/* Prints an error message and always returns -1.
 * It is used to signal on syslog a network IP or TCP or UDP 
 * header null and to return the -1 as error code.
 */
int network_header_null(const char *funcname, const char *message);


#endif
