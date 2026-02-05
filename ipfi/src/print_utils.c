#include "includes/utils.h"
#include <net/if.h>

int log_packet(const ipfire_info_t *pack, int loglevel)
{
	struct in_addr source_addr;
	struct in_addr dest_addr;
	char c[LOGLINELEN];
	char src_address[INET_ADDRSTRLEN];
	char dst_address[INET_ADDRSTRLEN];
    char in_name[IFNAMSIZ] = "n.a.";
    char out_name[IFNAMSIZ] = "n.a.";

	source_addr.s_addr = pack->packet.iphead.saddr;
	dest_addr.s_addr = pack->packet.iphead.daddr;
	inet_ntop(AF_INET, (void*)  &source_addr, src_address, 
					INET_ADDRSTRLEN);
	inet_ntop(AF_INET, (void*)  &dest_addr, dst_address, 
					INET_ADDRSTRLEN);
	
	/* see if we have to log */
	if(loglevel < 6)
	{
		/* don't log translation */
		if( (pack->flags.direction == IPFI_INPUT_PRE) |
			(pack->flags.direction == IPFI_OUTPUT_POST) )
			return 0;
	}
	if(loglevel < 3)
	{
		/* log only implicit */
		if(pack->response.verdict != IPFI_IMPLICIT)
			return 0;
	}
	if(loglevel < 5)
	{
		/* log only explicit and implicit denial */
		if(pack->response.verdict == IPFI_ACCEPT)
			return 0;
	}

	/* 1. NAT FIELD */
	if( (pack->flags.nat) & (!pack->flags.snat) )
	{
		flogpack(DNAT);
		flogpack(EMPTY); /* two empty fields for state.. */
		flogpack(EMPTY); /* .. and response */
		goto direction;
	}
	else if( (pack->flags.snat) )
	{
		flogpack(SNAT);
		flogpack(EMPTY);
		flogpack(EMPTY);
		goto direction;
	}
	else /* not dnat nor snat */
		flogpack(EMPTY); /* nat field */
	
	/* RESPONSE FIELD */
	if(pack->response.verdict == IPFI_DROP)
	{
		flogpack(DEN);
		flogpack(EMPTY); /* fill state field */
	}
	else if(pack->response.verdict == IPFI_ACCEPT)
	{
		flogpack(PERM);
		if(pack->flags.state)
			flogpack(STATE);
		else
			flogpack(NOSTATE);
	}
	else
	{
		flogpack(BOH);
		flogpack(EMPTY); /* state */
	}
	
	/* DIRECTION FIELD, ALWAYS PRESENT */
	direction:
	switch(pack->flags.direction)
	{
		case IPFI_INPUT:
			flogpack(IN);
		break;
		case IPFI_OUTPUT:
			flogpack(OUT);
		break;
		case IPFI_FWD:
			flogpack(FWD);
		break;
		case IPFI_INPUT_PRE:
			flogpack(PRE);
		break;
		case IPFI_OUTPUT_POST:
			flogpack(POST);
		break;
	}
	
	/* DEVICE NAME FIELD */
    if (pack->netdevs.in_idx > 0) if_indextoname(pack->netdevs.in_idx, in_name);
    if (pack->netdevs.out_idx > 0) if_indextoname(pack->netdevs.out_idx, out_name);

	snprintf(c, LOGLINELEN, "|%s", in_name);
	flog(c);
	snprintf(c, LOGLINELEN, "|%s", out_name);
	flog(c);
	
	/* PROTOCOL, ALWAYS */
	switch(pack->packet.iphead.protocol)
	{
		case IPPROTO_TCP:
		flogpack(TCP);
		snprintf(c, LOGLINELEN, "|%s|%d|%s|%d",
			src_address, 		
			ntohs(pack->packet.transport_header.tcphead.th_sport ),
			dst_address,
			ntohs(pack->packet.transport_header.tcphead.th_dport ) );
		flog(c);	
		
		/* SYN */		
		/* SYN */		
		if(pack->packet.transport_header.tcphead.th_flags & TH_SYN)
			flogpack(SYN);
		else
			flogpack(SYN0);
		/* ACK */
		if(pack->packet.transport_header.tcphead.th_flags & TH_ACK)
			flogpack(ACK);
		else
			flogpack(ACK0);
		/* FIN */
		if(pack->packet.transport_header.tcphead.th_flags & TH_FIN)
			flogpack(FIN);
		else
			flogpack(FIN0);
		/* URG */		
		if(pack->packet.transport_header.tcphead.th_flags & TH_URG)
			flogpack(URG);
		else
			flogpack(URG0);
		/* PSH */
		if(pack->packet.transport_header.tcphead.th_flags & TH_PUSH)
			flogpack(PSH);
		else
			flogpack(PSH0);
		/* RST */
		if(pack->packet.transport_header.tcphead.th_flags & TH_RST)
			flogpack(RST);
		else
			flogpack(RST0);
		
		break;
		case IPPROTO_UDP:
		flogpack(UDP);
		snprintf(c, LOGLINELEN, "|%s|%d|%s|%d",
			src_address, 		
			ntohs(pack->packet.transport_header.udphead.uh_sport ),
			dst_address,
			ntohs(pack->packet.transport_header.udphead.uh_dport ) );	
		flog(c);
		/* fill 6 flags  fields with don't cares */
		flog("|0|0|0|0|0|0");		
		break;
		case IPPROTO_ICMP:
		flogpack(ICMP);
		snprintf(c, LOGLINELEN, "|%s|%s",
			src_address, 		
			dst_address);	
		flog(c);
		/* fill 6 flags  fields with don't cares */
		flog("|0|0|0|0|0|0");	
		break;
		default:
			flogpack(OTHER_PROTO);
			flog("|0");
			flog("|0|0|0|0|0|0|0|0|0|0");
		break;
	}
	/* finally, log rule name */
    if (pack->response.rule_id != 0 && pack->response.verdict != IPFI_IMPLICIT) {
        ipfire_rule *matched = lookup_rule_by_id(pack->response.rule_id, NULL);
        if (matched && strlen(matched->rulename) > 0)
        {
            snprintf(c, LOGLINELEN, "|%s", matched->rulename);
            flog(c);
        } else {
            snprintf(c, LOGLINELEN, "|%u", pack->response.rule_id);
            flog(c);
        }
    }
	else
		flog("|x");
	
	flog("|\n");
	return 0;
}


/* Seconds are converted in days, hours, minutes and seconds, saved
 * in *d, *h, *m and *s.
 */
int seconds_to_dhms(unsigned seconds, unsigned* d, unsigned short *h, 
		    unsigned short *m, unsigned short* s)
{
	unsigned min = 60;
	unsigned hour = 60 * min;
	unsigned day = 24 * hour;

	unsigned remainder;
	
	*d = seconds / day;
	remainder = seconds % day;
	
	*h = remainder / hour;
	remainder = (seconds % day) % hour;
	
	*m = remainder / min;
	*s = ( (seconds % day) % hour %min);	
	
	return 0;
}
