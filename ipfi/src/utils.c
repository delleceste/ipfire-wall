/* Utilities to print packets read from kernel on the console or
 * in the IPFIRE log file */
 
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

#include "includes/utils.h"
#include <net/if.h>
#include <stddef.h>

/* FNV-1a 32-bit hash implementation */
uint32_t calculate_rule_id(const ipfire_rule *r) {
    uint32_t hash = 0x811c9dc5;
    const unsigned char *p;
    size_t i, len;

    if (strlen(r->rulename) > 0) {
        p = (const unsigned char *)r->rulename;
        len = strlen(r->rulename);
        for (i = 0; i < len; i++) {
            hash ^= p[i];
            hash *= 0x01000193;
        }
        return hash;
    }
    /* Hash criteria: from beginning of struct to notify field */
    p = (const unsigned char *)r;
    len = offsetof(ipfire_rule, pkmangle) + sizeof(struct packet_manip);
    for (i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= 0x01000193;
    }
    return hash;
}

ipfire_rule* lookup_rule_by_id(uint32_t id, int *policy) {
    extern ipfire_rule* denial_rules;
    extern ipfire_rule* accept_rules;
    extern ipfire_rule* translation_rules;
    extern int den_rules_num, acc_rules_num, transl_rules_num;
    int i;

    for (i = 0; i < acc_rules_num; i++) {
        if (accept_rules[i].rule_id == id) {
            if (policy) *policy = (int)ACCEPT;
            return &accept_rules[i];
        }
    }
    for (i = 0; i < den_rules_num; i++) {
        if (denial_rules[i].rule_id == id) {
            if (policy) *policy = (int)DENIAL;
            return &denial_rules[i];
        }
    }
    for (i = 0; i < transl_rules_num; i++) {
        if (translation_rules[i].rule_id == id) {
            if (policy) *policy = (int)TRANSLATION;
            return &translation_rules[i];
        }
    }
    return NULL;
}

#define LOGLINELEN			200 		
#define MAXFILENAMELEN 60

#define PROTONAMELEN	 6
#define SERVICENAMELEN  16

#define MAXLEN 64


/* Returns < 0 if the packet does not have to be printed, 0 if the filter 
 * or the info are null, > 0 if the filter matches 
 */
int filter_packet_to_print(const ipfire_info_t* p, const ipfire_rule_filter* f)
{
	unsigned short sport = 0, dport = 0;
	if(f == NULL || p == NULL)
		return 0;
	/* Direction */
	if(f->direction)
	{
		if(! ( 
			(f->in && p->flags.direction == IPFI_INPUT) || (f->out && p->flags.direction == IPFI_OUTPUT) ||
			(f->fwd && p->flags.direction == IPFI_FWD) || (f->pre && p->flags.direction == IPFI_INPUT_PRE) ||
			(f->post && p->flags.direction == IPFI_OUTPUT_POST)
		     )
		  )
			return -1;
	}
	/* protocol */
	if(f->protocol)
	{
		if( ! ((f->tcp && p->packet.iphead.protocol == IPPROTO_TCP) ||
			(f->udp && p->packet.iphead.protocol == IPPROTO_UDP) ||
			(f->icmp && p->packet.iphead.protocol == IPPROTO_ICMP) ||
			(f->igmp && p->packet.iphead.protocol == IPPROTO_IGMP)
		      )	
		  )
			return -1;
	}
	
	/* response */
	if(f->policy)
	{
		if( ! (
			(f->rule->nflags.policy == IPFI_ACCEPT && p->response.verdict == IPFI_ACCEPT) ||
			(f->rule->nflags.policy == IPFI_DROP && p->response.verdict == IPFI_DROP) ||
			(f->rule->nflags.policy == IPFI_IMPLICIT && p->response.verdict == IPFI_IMPLICIT) 
		      )
		  )
			return -1;
	}

	if(f->snat && !p->flags.snat)
		return -1;
	if( (f->dnat || f->masquerade) && !p->flags.nat)
		return -1;
	/* With f->nat we suppose we are interested in any kind of nat */
	if(f->nat && ! (p->flags.nat || p->flags.snat ))
		return -1;
	if(f->direction)
	{
		if(f->out && p->flags.direction != IPFI_OUTPUT)
			return -1;
		if(f->in && p->flags.direction != IPFI_INPUT)
			return -1;
		if(f->fwd && p->flags.direction != IPFI_FWD)
			return -1;
		if(f->pre && p->flags.direction != IPFI_INPUT_PRE)
			return -1;
		if(f->post && p->flags.direction != IPFI_OUTPUT_POST)
			return -1;
	}
	if(f->ip)
	{
		if(f->ip && !f->sip && !f->dip) /* any of sip or dip */
		{
			if(! ( 
				(f->rule->ip.ipsrc[0] == p->packet.iphead.saddr ) ||
				(f->rule->ip.ipsrc[0] == p->packet.iphead.daddr )
			     )
			  )
				return -1;
		}
		if(f->sip && (f->rule->ip.ipsrc[0] != p->packet.iphead.saddr))
			return -1;
		if(f->dip && (f->rule->ip.ipdst[0] != p->packet.iphead.daddr))
			return -1;
	}

	/* if more than one state is specified, we match packets within one or
	 * the other state. If no specific states are activated, it is enough to
	 * have both f->state and p->state active
	 */
	if(f->state && p->response.state && ! (f->setup | f->setupok | f->est | f->finwait | f->closewait |
			f->lastack | f->closed | f->timewait) )
		;

	else if(f->state && p->response.state &&
			! ( (f->setup &&  p->response.st.state == SYN_SENT ) ||
			    (f->setupok && p->response.st.state == SYN_RECV) ||
			    (f->est && p->response.st.state == ESTABLISHED ) ||
			    (f->finwait && p->response.st.state == FIN_WAIT) ||
			    (f->closewait && p->response.st.state == CLOSE_WAIT) ||
			    (f->lastack && p->response.st.state == LAST_ACK) ||
			    (f->closed && p->response.st.state == CLOSED ) ||
			    (f->timewait && p->response.st.state == IPFI_TIME_WAIT ) ||
			    (f->est && p->response.st.state == GUESS_ESTABLISHED) ||
			    (f->setupok && p->response.st.state == GUESS_SYN_RECV)
			  ) )
		return -1;
	else if(f->stateless)
		;
	else if(f->state && !p->response.state)
		return -1;


	/* source or destination port */
	if(f->port)
	{
		switch(p->packet.iphead.protocol)
		{
			case IPPROTO_TCP:
				sport = p->packet.transport_header.tcphead.th_sport;
				dport = p->packet.transport_header.tcphead.th_dport;
				break;
			case IPPROTO_UDP:
				sport = p->packet.transport_header.udphead.uh_sport;
				dport = p->packet.transport_header.udphead.uh_dport;
				break;
			default:
				sport = dport = 0;
				break;
		}
	}
	if(f->port && !f->sport && !f->dport)
	{
		if(! (
			(htons(f->rule->tp.sport[0]) == sport) ||
			(htons(f->rule->tp.sport[0]) == dport) 
		     )
		  )
			return -1;
	}
	else if(f->sport || f->dport)
	{
		if(f->sport && (htons(f->rule->tp.sport[0]) != sport) )
			return -1;
		if(f->dport && (htons(f->rule->tp.dport[0]) != dport) )
			return -1;
	}
	/* interfaces */
	/* interfaces */
	if(f->device)
	{
        char devnbuf[IFNAMSIZ];
		if(f->indevice)
		{
            if (p->netdevs.in_idx == -1 || 
                !if_indextoname(p->netdevs.in_idx, devnbuf) ||
                strcmp(f->rule->devpar.in_devname, devnbuf))
				return -1;
		}
		if(f->outdevice)
		{
            if (p->netdevs.out_idx == -1 || 
                !if_indextoname(p->netdevs.out_idx, devnbuf) ||
                strcmp(f->rule->devpar.out_devname, devnbuf))
				return -1;
		}
		if(!f->indevice && !f->outdevice) /* match any between in and out interfaces */
		{
            int match_in = 0;
            int match_out = 0;

            if (p->netdevs.in_idx != -1 && if_indextoname(p->netdevs.in_idx, devnbuf))
                    if (!strcmp(f->rule->devpar.in_devname, devnbuf)) match_in = 1;

            if (p->netdevs.out_idx != -1 && if_indextoname(p->netdevs.out_idx, devnbuf))
                    if (!strcmp(f->rule->devpar.in_devname, devnbuf)) match_out = 1;

			if(!match_in && !match_out)
				return -1;
		}

	}


	return 1;
}


/* deep copy of structure. We are not interested in alias */
void copy_servent(struct ipfire_servent *dst, 
			const struct servent* src)
{
	dst->s_port = src->s_port;
	strncpy(dst->s_name, src->s_name, SERVICENAMELEN - 1);
	/* terminate string anyway at position 15 */
	dst->s_name[SERVICENAMELEN - 1] = '\0';
	strncpy(dst->s_proto, src->s_proto, PROTONAMELEN -1);
	dst->s_proto[PROTONAMELEN -1] = '\0';
}

struct ipfire_servent *alloc_and_fill_services_list(void)
{
	int nentries = 0;
	int i = 0;
	struct ipfire_servent* se;
	struct servent *setmp;
	while(getservent() != NULL)
	{
		nentries ++;
	}
	/* allocate space, one more than necessary to terminate with null */
	se = (struct ipfire_servent*) malloc(sizeof(struct ipfire_servent) * (nentries+1) );
	if(se == NULL)
	{
		perror(RED "Failed to allocate space for service entries\n" NL);
		return NULL;
	}
	/* open and rewind /etc/services */
	setservent(0);
	while( ( (setmp = getservent() ) != NULL) & (i < nentries ) )
	{
		/* initialize the structure with zeros */
		memset(se + i, 0, sizeof(struct ipfire_servent) );
		copy_servent(se + i, setmp);
		i++;
	}
	se[i].last = 1;
	endservent();
	//printf("Allocated %d bytes for service table." NL, 
	//		sizeof(struct ipfire_servent) * nentries);
	return se;
}

/* given a protocol, two strings and two ports
 * in network byte order, copies service name 
 * as in etc/services in corresponding strings.
 * If no match is found, strings are empty ( "" )
 */
int resolv_ports(const struct ipfire_servent* ipfise,
	const unsigned short protocol, 
	char* srcserv, char* dstserv,
	__u16 sport, __u16 dport)
{
	char cproto[PROTONAMELEN];
	switch(protocol)
	{
		case IPPROTO_IGMP:
			strcpy(cproto, "igmp");
		case IPPROTO_ICMP:
			strcpy(cproto, "icmp");
		break;
		case IPPROTO_TCP:
			strcpy(cproto, "tcp");
		break;
		case IPPROTO_UDP:
			strcpy(cproto, "udp");
		break;
	}
        get_service_name(ipfise, srcserv, cproto, (int) sport);
	get_service_name(ipfise, dstserv, cproto, (int) dport);

	return 0;
}

/* given a pointer to mallocated ipfire_servent structure, 
 * this function looks for match in port and protocol and 
 * copies into name the name of the service, if a match
 * is found */
int get_service_name(const struct ipfire_servent* ise, char* name, char* proto, 
			int port)
{
	int i = 0;
	strcpy(name, "");
	while(!ise[i].last)
	{
		if( (! strcmp(ise[i].s_proto, proto) ) &
				(ise[i].s_port == port) )
		{
			strncpy(name, ise[i].s_name, SERVICENAMELEN-1);	
			name[SERVICENAMELEN -1] = '\0';
			return 1;
		}		
		i++;		
	}
	return 0;
}

void restore_color(int direction)
{
	switch(direction)
	{
		case IPFI_INPUT:
			printf(CLR GREEN );
			break;
		
		case IPFI_OUTPUT:
			printf(CLR CYAN );
			break;
		
		case IPFI_INPUT_PRE:
			printf(CLR DGREEN );
			break;
		
		case IPFI_OUTPUT_POST:
			printf(CLR "\e[0;36m" );
			break;
		
		case IPFI_FWD:
			printf(CLR YELLOW );
			break;
	}
}

void get_icmp_type_code(const int t, const int c, char* type, char *code)
{
	memset(type, 0, MAXLEN);
	memset(code, 0, MAXLEN);
	switch(t)
	{
		case 0:
			strncpy(type, "echo reply", MAXLEN);
			break;
		case 3:
			strncpy(type, "dest. unreach", MAXLEN);
			switch(c)
			{
				case 0:
					strncpy(code, "/net. unreach", MAXLEN);
					break;
				case 1:
					strncpy(code, "/host unreach", MAXLEN);
					break;
				case 2:
					strncpy(code, "/prot unreach", MAXLEN);
					break;
				case 3:
					strncpy(code, "/port unreach", MAXLEN);
					break;
				case 4:
					strncpy(code, "/fragmentation needed", MAXLEN);
					break;
				case 5:
					strncpy(code, "/source route failed", MAXLEN);
					break;
				case 6:
					strncpy(code, "/net. unknown", MAXLEN);
					break;
				case 7:
					strncpy(code, "/host unknown", MAXLEN);
					break;					
				case 8:
					strncpy(code, "/host isolated", MAXLEN);
					break;
				case 9:
					strncpy(code, "/net ano", MAXLEN);
					break;
				case 10:
					strncpy(code, "/host ano", MAXLEN);
					break;
				case 11:
					strncpy(code, "/net unr. tos", MAXLEN);
					break;
				case 12:
					strncpy(code, "/host unr. tos", MAXLEN);
					break;
				case 13:
					strncpy(code, "/packet filtered", MAXLEN);
					break;
				case 14:
					strncpy(code, "/precedence violation", MAXLEN);
					break;
				case 15:
					strncpy(code, "/precedence cut off", MAXLEN);
					break;	
			}		
			break;
		case 4:
			strncpy(type, "src quench", MAXLEN);
			break;
		case 5:
			strncpy(type, "redirect (change route)", MAXLEN);
			switch(c)
			{
				case 0:
					strncpy(code, "/redir. net", MAXLEN);
					break;	
				case 1:
					strncpy(code, "/redir. host", MAXLEN);
					break;	
				case 2:
					strncpy(code, "/redir. net for tos", MAXLEN);
					break;	
				case 3:
					strncpy(code, "/redir. host for tos", MAXLEN);
					break;		
			}
			break;
		
		case 8:
			strncpy(type, "echo request", MAXLEN);
			break;
		case 11:
			strncpy(type, "time exceeded", MAXLEN);
			switch(c)
			{
				case 0:
					strncpy(code, "/TTL count exceeded", MAXLEN);
					break;	
				case 1:
					strncpy(code, "/Fragm. reass. time exceeded", MAXLEN);
					break;	
			}
			break;
			
		case 12:
			strncpy(type, "parameter problem", MAXLEN);
			break;
		case 13:
			strncpy(type, "timestamp req.", MAXLEN);
			break;
		case 14:
			strncpy(type, "timestamp reply", MAXLEN);
			break;
		case 15:
			strncpy(type, "info request", MAXLEN);
			break;
			
		case 16:
			strncpy(type, "info reply", MAXLEN);
			break;
		case 17:
			strncpy(type, "address mask req.", MAXLEN);
			break;
		case 18:
			strncpy(type, "address mask reply.", MAXLEN);
			break;	
	}
}

void get_igmp_type_code(const int t, const int c, char* type, char *code)
{
	memset(type, 0, MAXLEN);
	memset(code, 0, MAXLEN);
	switch(t)
	{
		case 0x11:
			strncpy(type, "Membership query", MAXLEN);
			switch(c)
			{
				case 0:
					strncpy(code, "/IGMP vers. 1", MAXLEN);
					break;
				default:
					snprintf(code, MAXLEN, 
							"/Max response time: %d", c);
					break;
			}
			break;
		case 0x12:
			strncpy(type, "IGMPv1 Membership Report", MAXLEN);
			break;
		case 0x13:
			strncpy(type, "DVMRP", MAXLEN);
			switch(c)
			{
				case 1:
					strncpy(code, "/probe", MAXLEN);
					break;
				case 2:
					strncpy(code, "/route report", MAXLEN);
					break;
				case 3:
					strncpy(code, "/Old Ask Neighbors", MAXLEN);
					break;
				case 4:
					strncpy(code, "/Old Neighbours reply", MAXLEN);
					break;
				case 5:
					strncpy(code, "/Ask Neighbors", MAXLEN);
					break;
				case 6:
					strncpy(code, "/Neighbours reply", MAXLEN);
					break;
				case 7:
					strncpy(code, "/Prune", MAXLEN);
					break;
				case 8:
					strncpy(code, "/Graft", MAXLEN);
					break;
				case 9:
					strncpy(code, "/Graft Ack", MAXLEN);
					break;
					
			}
			break;
		case 0x14:
			strncpy(type, "PIM version 1", MAXLEN);
			switch(c)
			{
				case 0:
					strncpy(code, "/Query", MAXLEN);
					break;
				case 1:
					strncpy(code, "/Register", MAXLEN);
					break;
				case 2:
					strncpy(code, "/Register Stop", MAXLEN);
					break;
				case 3:
					strncpy(code, "/Join or Prune", MAXLEN);
					break;
				case 4:
					strncpy(code, "/RP Reachable", MAXLEN);
					break;
				case 5:
					strncpy(code, "/Assert", MAXLEN);
					break;
				case 6:
					strncpy(code, "/Graft", MAXLEN);
					break;
				case 7:
					strncpy(code, "/Graft Ack", MAXLEN);
					break;
				case 8:
					strncpy(code, "/Mode", MAXLEN);
					break;			
			}
			
			break;
		case 0x15:
			strncpy(type, "Cisco Trace Messages", MAXLEN);
			break;
		case 0x16:
			strncpy(type, "IGMPv2 Membership Report [RFC2236]", MAXLEN);
			break;
		case 0x17:
			strncpy(type, "IGMPv2 Leave Group [RFC2236]", MAXLEN);
			break;	
		case 0x1e:
			strncpy(type, "Multicast Traceroute Response", MAXLEN);
			break;
		case 0x1f:
			strncpy(type, "Multicast Traceroute", MAXLEN);
			break;
		case 0x22:
			strncpy(type, "IGMPv3 Membership Report [RFC3376]", MAXLEN);
			break;
		case 0x30:
			strncpy(type, "Multicast Router Advertisement", MAXLEN);
			break;
		case 0x31:
			strncpy(type, "Multicast Router Solicitation", MAXLEN);
			break;
		case 0x32:
			strncpy(type, "Multicast Router Termination", MAXLEN);
			break;
		default:
			strncpy(type, "/reserved [RFC3228, BCP57]", MAXLEN);
			
	}
	
}

int print_packet(const ipfire_info_t *pack, 
		 const struct ipfire_servent* ipfi_svent,
   const ipfire_rule_filter *filter)
{
	struct in_addr source_addr;
	struct in_addr dest_addr;
	struct in_addr igmp_group; /* for IGMP support */
	char src_address[INET_ADDRSTRLEN];
	char dst_address[INET_ADDRSTRLEN];
	char igmp_grp_address[INET_ADDRSTRLEN];
	int mtu_minlen = sizeof(struct iphdr) + sizeof(struct tcphdr);
	char sport_res[16] = "";
	char dport_res[16] = "";
	char icmp_type[MAXLEN];
	char icmp_code[MAXLEN];
	char igmp_type[MAXLEN];
	char igmp_code[MAXLEN];
    char in_name[IFNAMSIZ] = "n.a.";
    char out_name[IFNAMSIZ] = "n.a.";

	source_addr.s_addr = pack->packet.iphead.saddr;
	dest_addr.s_addr = pack->packet.iphead.daddr;
	

	if(pack->flags.state_max_entries)
	{
		PRED, PUND, printf(TR("WARNING")), PCL, printf(TR(": maximum number of entries reached for the state tables."));
		PNL;
		return -1;
	}
	else if(pack->flags.nat_max_entries)
	{
		PRED, PUND, printf(TR("WARNING")), PCL, printf(TR(": maximum number of entries reached for the NAT tables."));
		PNL;
		return -1;
	}
	else if(pack->flags.snat_max_entries)
	{
		PRED, PUND, printf(TR("WARNING")), PCL, printf(TR(": maximum number of entries "
		"reached for the source nat tables"));
		PNL;
		PGRN, printf(TR("HINT")); PCL;
		printf(TR(":    in the options, the administrator should"));
		PNL, printf(TR("         increase the maximum number of the source nat table entries."));
		PNL;
		return -1;
	}
	/* See if we have to filter out the packet to print */
	if(filter_packet_to_print(pack, filter) < 0)
		return -1;
	
	inet_ntop(AF_INET, (void*)  &source_addr, src_address, 
		  INET_ADDRSTRLEN);
	inet_ntop(AF_INET, (void*)  &dest_addr, dst_address, 
		  INET_ADDRSTRLEN);

    if (pack->netdevs.in_idx > 0) if_indextoname(pack->netdevs.in_idx, in_name);
    if (pack->netdevs.out_idx > 0) if_indextoname(pack->netdevs.out_idx, out_name);

	if( (pack->flags.nat) & (!pack->flags.snat) )
		printf("[" YELLOW "DNAT" CLR "]");
	else if( (pack->flags.snat) )
		printf("[" MAROON "SNAT" CLR "]");
	
	if(pack->flags.badsum)
		PRED, printf(TR("CKSUM ERR!")), PCL;
	else {
        if(pack->response.verdict == IPFI_DROP)
            printf(RED "[X " CLR);
        else if(pack->response.verdict == IPFI_ACCEPT)
            printf(GREEN "[OK " CLR);
        else if(pack->response.verdict == IPFI_IMPLICIT)
            printf(VIOLET "[IMPL]" CLR);
        else
            printf(VIOLET "[? %d]" CLR, pack->response.verdict);

        
        if (pack->response.verdict == IPFI_DROP) printf(RED "]" CLR);
        else if (pack->response.verdict == IPFI_ACCEPT) printf(GREEN "]" CLR);
    }

			switch(pack->flags.direction)
			{
				case IPFI_INPUT:
					printf("\e[1;32mIN:  ");
					break;
				case IPFI_OUTPUT:
					printf("\e[1;36mOUT: ");
					break;
				case IPFI_FWD:
					printf("\e[1;33mFWD: ");
					break;
				case IPFI_INPUT_PRE:
					printf("\e[0;32mPRE: ");
					break;
				case IPFI_OUTPUT_POST:
					printf("\e[0;36mPOST:");
					break;
			}
			if(pack->flags.direction == IPFI_FWD)
				printf("[%s->%s] ", in_name, out_name);
			else
			{
				if(strcmp(in_name, "n.a.") )
				{
					printf("[%s] ", in_name);
					if(strlen(in_name) == 2) /* lo */
						printf("  "); /* just to align print */
				}
		
				if(strcmp(out_name, "n.a.") )
				{
					printf("[%s] ", out_name);
					if(strlen(out_name) == 2) /* lo */
						printf("  ");
				}
			}

			if(ipfi_svent != NULL)
			{		
				resolv_ports(ipfi_svent, 
					     pack->packet.iphead.protocol, sport_res, dport_res,
	  pack->packet.transport_header.tcphead.source,
   pack->packet.transport_header.tcphead.dest);
			}
	
			switch(pack->packet.iphead.protocol)
			{
				case IPPROTO_TCP:
					printf("|TCP| ");
					printf("%s:", src_address);
					if(strlen(sport_res) > 0)
					{
						printf( UNDERL "%s", sport_res);
						restore_color(pack->flags.direction);
					}
					else
						printf("%u", ntohs(pack->packet.transport_header.tcphead.source) );
					printf(GRAY"-->");
					restore_color(pack->flags.direction);
		
					printf("%s:", dst_address);
					if(strlen(dport_res) > 0)
					{
						printf( UNDERL "%s" , dport_res);
						restore_color(pack->flags.direction);
						printf(" |");
					}
					else
						printf("%u |", ntohs(pack->packet.transport_header.tcphead.dest));
		
					if(pack->packet.transport_header.tcphead.fin)
						printf("F|");
					if(pack->packet.transport_header.tcphead.syn)
						printf("S|");	
					if(pack->packet.transport_header.tcphead.rst)
					{
						printf(RED "R" );
						restore_color(pack->flags.direction);
						printf("|");
					}
					if(pack->packet.transport_header.tcphead.psh)
						printf("P|");
					if(pack->packet.transport_header.tcphead.ack)
						printf("A|");
					if(pack->packet.transport_header.tcphead.urg)
					{
						printf(DRED "U|");
						restore_color(pack->flags.direction);
					}
					break;
		

				case IPPROTO_UDP:
					printf("|UDP| "); 
		
					printf("%s:", src_address);
					if(strlen(sport_res) > 0)
					{
						printf( UNDERL "%s", sport_res);
						restore_color(pack->flags.direction);
					}
					else
						printf("%u", ntohs(pack->packet.transport_header.udphead.source ));
					printf(GRAY "-->");
					restore_color(pack->flags.direction);
		
					printf("%s:", dst_address);
					if(strlen(dport_res) > 0)
					{
						printf( UNDERL "%s", dport_res);
						restore_color(pack->flags.direction);
						printf(" ");
					}
					else
						printf("%u ", ntohs(pack->packet.transport_header.udphead.dest) );
			
					break;
				case IPPROTO_ICMP:
					printf("|ICMP| SRC:%s --> DST:%s |",
					       src_address, dst_address);
					get_icmp_type_code(pack->packet.transport_header.icmphead.type,
							pack->packet.transport_header.icmphead.code, icmp_type,
       						icmp_code);	
					printf("{%s%s}|", icmp_type, icmp_code);
					break;
				case IPPROTO_IGMP:
					get_igmp_type_code(pack->packet.transport_header.igmphead.igmp_type,
							pack->packet.transport_header.igmphead.igmp_code, igmp_type,
							igmp_code);	
					igmp_group = pack->packet.transport_header.igmphead.igmp_group;
					inet_ntop(AF_INET, (void*)  &igmp_group, igmp_grp_address, 
							INET_ADDRSTRLEN);
					printf("|"), PVIO, PBOLD, printf("IGMP");
					restore_color(pack->flags.direction);
					printf("| SRC:%s --> DST:%s |",
					       src_address, dst_address);	
					printf("GROUP: %s|",igmp_grp_address);
					printf("{%s%s}|", igmp_type, igmp_code);
					break;
				case IPPROTO_GRE:
				  printf("|"), PGRAY, PBOLD, printf("CISCO GRE (RFC 1701, 1702)");
				  restore_color(pack->flags.direction);
				  printf("| SRC:%s --> DST:%s |", src_address, dst_address);
				  break;
				case IPPROTO_PIM:
				  printf("|"), PGRAY, PBOLD, printf("INDEPENDENT MULTICAST [\"PIM\"]");
				  restore_color(pack->flags.direction);
				  printf("| SRC:%s --> DST:%s |", src_address, dst_address);
				  break;
				default:
					printf("Protocol ");
					switch(pack->packet.iphead.protocol)
					{
						case IPPROTO_IGMP:
							printf(GRAY "IGMP" CLR);
							break;
						case IPPROTO_IPIP:
							printf(GRAY "IPIP [TUNNELS]" CLR);
							break;
						case IPPROTO_EGP:
							printf( "\"" GRAY "EXTERIOR GATEWAY" CLR "\"");
							break;
						case IPPROTO_PUP:
							printf(GRAY "PUP" CLR);
							break;
			
						case IPPROTO_IDP:
							printf(GRAY "XNS IDP" CLR);
							break;
						case IPPROTO_RSVP:
							printf(GRAY "RSVP" CLR);
							break;
						case IPPROTO_GRE:
// 							printf( "\"" GRAY "CISCO GRE (RFC 1701, 1702)" CLR "\"");
							break;
						case IPPROTO_IPV6:
							printf("\"" GRAY "IPv6-in-IPv4 tunnelling" CLR "\"" );
							break;
			
						case IPPROTO_ESP:
							printf("\"" GRAY "ENCAPSULATION SECURITY PAYLOAD [ESP]" CLR "\"" );
							break;
						case IPPROTO_AH:
							printf("\"" GRAY "AUTHENTICATION HEADER" CLR "\"" );
							break;
						case IPPROTO_PIM:
							printf( "\"" GRAY "INDEPENDENT MULTICAST" CLR "\"[" 
									GRAY "PIM" CLR "]");
							break;
						case IPPROTO_COMP:
							printf("\"" GRAY "COMPRESSION HEADER" CLR "\"" );
							break;
			
						case IPPROTO_SCTP:
							printf(GRAY "STREAM CONTROL TRASPORT PROTOCOL" CLR);
							break;
						case IPPROTO_RAW:
							printf( GRAY "RAW" CLR );
							break;
					}
					restore_color(pack->flags.direction);
					printf(" not supported!");
					break;
			}
			if( (pack->flags.state) && (pack->response.verdict == IPFI_ACCEPT) )
			{
				if(pack->response.st.state == SYN_SENT)
					printf(BLUE "SETUP" CLR);
				else if(pack->response.st.state == SYN_RECV)
					printf(BLUE "SETUP OK" CLR);
				else if(pack->response.st.state == ESTABLISHED)
					printf( BLUE "EST" CLR); 
				else if(pack->response.st.state == LAST_ACK)
					printf(BLUE "LAST ACK" CLR);
				else if(pack->response.st.state == CLOSE_WAIT)
					printf(BLUE "CLOSE WAIT" CLR);
				else if(pack->response.st.state == INVALID_STATE)
					printf(RED "?" CLR);
				else if(pack->response.st.state == FIN_WAIT)
					printf(BLUE "FIN WAIT" CLR);
				else if(pack->response.st.state == IPFI_TIME_WAIT)
					printf(BLUE "TIME WAIT" CLR);
				else if(pack->response.st.state == NOTCP)
					printf(YELLOW "???" CLR);
				else if(pack->response.st.state == UDP_NEW)
					printf(YELLOW "NEW" CLR);
				else if(pack->response.st.state == UDP_ESTAB)
					printf(YELLOW "STREAM" CLR);
				else if(pack->response.st.state == ICMP_STATE)
					printf(DRED "ICMP" CLR);
				else if(pack->response.st.state == IGMP_STATE)
				  printf(DVIOLET "IGMP" CLR);
				else if(pack->response.st.state == GRE_STATE)
				  printf(CYAN "GRE" CLR);
				else if(pack->response.st.state == GUESS_ESTABLISHED)
					printf(MAROON "EST?" CLR);
				else if(pack->response.st.state == CLOSED)
					printf(BLUE "CLOSED" CLR);
				else if(pack->response.st.state == NOTCP)
					printf(YELLOW "S" CLR);
				else if(pack->response.st.state == GUESS_CLOSING)
					printf(MAROON "CLOSING?" CLR);
				else if(pack->response.st.state == INVALID_FLAGS)
					printf(RED "INVALID FLAGS!" CLR);
				else if(pack->response.st.state == NULL_FLAGS)
					printf(RED "NULL syn fin rst ack FLAGS!"CLR );
				else if(pack->response.st.state == GUESS_SYN_RECV)
					printf(MAROON "SETUP OK?" CLR);
				else if(pack->response.st.state != IPFI_NOSTATE)
					printf("STATE: %d", pack->response.st.state);
			
			}
			else
				printf("  ");

            if (pack->response.rule_id != 0 && pack->response.verdict != IPFI_IMPLICIT) {
                ipfire_rule *matched = lookup_rule_by_id(pack->response.rule_id, NULL);
                if (matched && strlen(matched->rulename) > 0)
                    printf(" [%s]", matched->rulename);
                else if (pack->response.rule_id != 0)
                    printf(" [%u]", pack->response.rule_id);
            }

			if(filter != NULL) /* if we are here we have passed the filter */
				PCL, printf(" "),  PVIO, PBOLD, printf("F" CLR);

			printf(NL);
			return 0;
}


