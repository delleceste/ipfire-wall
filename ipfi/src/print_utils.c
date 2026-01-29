#include "includes/utils.h"

int log_packet(const ipfire_info_t *pack, int loglevel)
{
	struct in_addr source_addr;
	struct in_addr dest_addr;
	char c[LOGLINELEN];
	char src_address[INET_ADDRSTRLEN];
	char dst_address[INET_ADDRSTRLEN];
	source_addr.s_addr = pack->iphead.saddr;
	dest_addr.s_addr = pack->iphead.daddr;
	inet_ntop(AF_INET, (void*)  &source_addr, src_address, 
					INET_ADDRSTRLEN);
	inet_ntop(AF_INET, (void*)  &dest_addr, dst_address, 
					INET_ADDRSTRLEN);
	
	/* see if we have to log */
	if(loglevel < 6)
	{
		/* don't log translation */
		if( (pack->direction == IPFI_INPUT_PRE) |
			(pack->direction == IPFI_OUTPUT_POST) )
			return 0;
	}
	if(loglevel < 3)
	{
		/* log only implicit */
		if(pack->response != 0)
			return 0;
	}
	if(loglevel < 5)
	{
		/* log only explicit and implicit denial */
		if(pack->response > 0)
			return 0;
	}

	/* 1. NAT FIELD */
	if( (pack->nat) & (!pack->snat) )
	{
		flogpack(DNAT);
		flogpack(EMPTY); /* two empty fields for state.. */
		flogpack(EMPTY); /* .. and response */
		goto direction;
	}
	else if( (pack->snat) )
	{
		flogpack(SNAT);
		flogpack(EMPTY);
		flogpack(EMPTY);
		goto direction;
	}
	else /* not dnat nor snat */
		flogpack(EMPTY); /* nat field */
	
	/* RESPONSE FIELD */
	if(pack->response < 0)
	{
		flogpack(DEN);
		flogpack(EMPTY); /* fill state field */
	}
	else if(pack->response > 0)
	{
		flogpack(PERM);
		if(pack->state)
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
	switch(pack->direction)
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
	snprintf(c, LOGLINELEN, "|%s", pack->devpar.in_devname);
	flog(c);
	snprintf(c, LOGLINELEN, "|%s", pack->devpar.out_devname);
	flog(c);
	
	/* PROTOCOL, ALWAYS */
	switch(pack->protocol)
	{
		case IPPROTO_TCP:
		flogpack(TCP);
		snprintf(c, LOGLINELEN, "|%u|%s|%d|%s|%d",
			pack->packet_id,
			src_address, 		
			ntohs(pack->transport_header.tcphead.source ),
			dst_address,
			ntohs(pack->transport_header.tcphead.dest ) );
		flog(c);	
		
		/* SYN */		
		if(pack->transport_header.tcphead.syn)
			flogpack(SYN);
		else
			flogpack(SYN0);
		/* ACK */
		if(pack->transport_header.tcphead.ack)
			flogpack(ACK);
		else
			flogpack(ACK0);
		/* FIN */
		if(pack->transport_header.tcphead.fin)
			flogpack(FIN);
		else
			flogpack(FIN0);
		/* URG */		
		if(pack->transport_header.tcphead.urg)
			flogpack(URG);
		else
			flogpack(URG0);
		/* PSH */
		if(pack->transport_header.tcphead.psh)
			flogpack(PSH);
		else
			flogpack(PSH0);
		/* RST */
		if(pack->transport_header.tcphead.rst)
			flogpack(RST);
		else
			flogpack(RST0);
		
		break;
		case IPPROTO_UDP:
		flogpack(UDP);
		snprintf(c, LOGLINELEN, "|%u|%s|%d|%s|%d",
			pack->packet_id,
			src_address, 		
			ntohs(pack->transport_header.udphead.source ),
			dst_address,
			ntohs(pack->transport_header.udphead.dest ) );	
		flog(c);
		/* fill 6 flags  fields with don't cares */
		flog("|0|0|0|0|0|0");		
		break;
		case IPPROTO_ICMP:
		flogpack(ICMP);
		snprintf(c, LOGLINELEN, "|%u|%s|0|%s|0",
			pack->packet_id,
			src_address, 		
			dst_address);	
		flog(c);
		/* fill 6 flags  fields with don't cares */
		flog("|0|0|0|0|0|0");	
		break;
		default:
			flogpack(OTHER_PROTO);
			snprintf(c, LOGLINELEN, "|%u", pack->packet_id);
                        flog(c);
			flog("|0|0|0|0|0|0|0|0|0|0");
		break;
	}
	#ifdef ENABLE_RULENAME
	/* finally, log rule name */
	if(strlen(pack->rulename) > 0)
	{
		snprintf(c, LOGLINELEN, "|%s", pack->rulename);
		flog(c);
	}
	else
		flog("|x");
	#endif
	
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

