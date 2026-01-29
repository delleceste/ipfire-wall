#include "includes/utils.h"


int print_packet(const ipfire_info_t *pack, 
	const struct ipfire_servent* ipfi_svent,
	const ipfire_rule_filter *filter)
{
	struct in_addr source_addr;
	struct in_addr dest_addr;
	char src_address[INET_ADDRSTRLEN];
	char dst_address[INET_ADDRSTRLEN];
	char sport_res[16] = "";
	char dport_res[16] = "";
	source_addr.s_addr = pack->iphead.saddr;
	dest_addr.s_addr = pack->iphead.daddr;

	/* See if we have to filter out the packet to print */
	if(filter_packet_to_print(pack, filter) < 0)
		return -1;
	
	inet_ntop(AF_INET, (void*)  &source_addr, src_address, 
					INET_ADDRSTRLEN);
	inet_ntop(AF_INET, (void*)  &dest_addr, dst_address, 
					INET_ADDRSTRLEN);
	if( (pack->nat) & (!pack->snat) )
	{
		printf("[" YELLOW "DNAT" CLR "]");
		goto direction;
	}
	else if( (pack->snat) )
	{
		printf("[" MAROON "SNAT" CLR "]");
		goto direction;
	}
	
	if(pack->badsum)
		PRED, printf(TR("CKSUM ERR!")), PCL;
	else if(pack->response < 0)
		printf(RED "[X %d]" CLR, -pack->response);
	else if(pack->response > 0)
		printf(GREEN "[OK %d]" CLR, pack->response);
	else
		printf(VIOLET "[?X]  " CLR);
	direction:
	switch(pack->direction)
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
	if(pack->direction == IPFI_FWD)
		printf("[%s->%s] ", pack->devpar.in_devname,
					pack->devpar.out_devname);
	else
	{
		if(strcmp(pack->devpar.in_devname, "n.a.") )
		{
			printf("[%s] ", pack->devpar.in_devname);
			if(strlen(pack->devpar.in_devname) == 2) /* lo */
				printf("  "); /* just to align print */
		}
		
		if(strcmp(pack->devpar.out_devname, "n.a.") )
		{
			printf("[%s] ", pack->devpar.out_devname);
			if(strlen(pack->devpar.out_devname) == 2) /* lo */
				printf("  ");
		}
	}
//	printf("%lu:", pack->packet_id); /* removed this since 0.98.6 */

	if(ipfi_svent != NULL)
	{		
		resolv_ports(ipfi_svent, 
			pack->protocol, sport_res, dport_res,
			pack->transport_header.tcphead.source,
			pack->transport_header.tcphead.dest);
	}
	
	switch(pack->protocol)
	{
		case IPPROTO_TCP:
			printf("|TCP| ");
		printf("%s:", src_address);
		if(strlen(sport_res) > 0)
		{
			printf( UNDERL "%s", sport_res);
			restore_color(pack->direction);
		}
		else
			printf("%u", ntohs(pack->transport_header.tcphead.source) );
		printf(GRAY"-->");
		restore_color(pack->direction);
		
		printf("%s:", dst_address);
		if(strlen(dport_res) > 0)
		{
			printf( UNDERL "%s" , dport_res);
			restore_color(pack->direction);
			printf(" |");
		}
		else
			printf("%u |", ntohs(pack->transport_header.tcphead.dest));
		
	    if(pack->transport_header.tcphead.fin)
			printf("F|");
		if(pack->transport_header.tcphead.syn)
			printf("S|");	
		if(pack->transport_header.tcphead.rst)
		{
			printf(RED "R" );
			restore_color(pack->direction);
			printf("|");
		}
		if(pack->transport_header.tcphead.psh)
			printf("P|");
		if(pack->transport_header.tcphead.ack)
			printf("A|");
		if(pack->transport_header.tcphead.urg)
		{
			printf(DRED "U|");
			restore_color(pack->direction);
		}
		break;
		

		case IPPROTO_UDP:
		printf("|UDP| "); 
		
		printf("%s:", src_address);
		if(strlen(sport_res) > 0)
		{
			printf( UNDERL "%s", sport_res);
			restore_color(pack->direction);
		}
		else
			printf("%u", ntohs(pack->transport_header.udphead.source ));
		printf(GRAY "-->");
		restore_color(pack->direction);
		
		printf("%s:", dst_address);
		if(strlen(dport_res) > 0)
		{
			printf( UNDERL "%s", dport_res);
			restore_color(pack->direction);
			printf(" ");
		}
		else
			printf("%u ", ntohs(pack->transport_header.udphead.dest) );
			
		break;
		case IPPROTO_ICMP:
		printf("|ICMP| SRC:%s --> DST:%s |",
		src_address,
		dst_address);	
		printf("TYPE:%u|CODE: %u|",
			pack->transport_header.icmphead.type,
			pack->transport_header.icmphead.code);
		break;
		
		case IPPROTO_IGMP: /* minimum support here */
			printf("|IGMP| SRC:%s --> DST:%s |", src_address, dst_address);	
			break;
		
		default:
		printf("Protocol ");
		switch(pack->protocol)
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
				printf( "\"" GRAY "CISCO GRE (RFC 1701, 1702)" CLR "\"");
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
		restore_color(pack->direction);
		printf(" not supported!");
		break;
	}
	if( (pack->state) && (pack->response > 0) )
	{
			if(pack->st.state == SYN_SENT)
				printf(BLUE "SETUP" CLR);
			else if(pack->st.state == SYN_RECV)
				printf(BLUE "SETUP OK" CLR);
			else if(pack->st.state == ESTABLISHED)
				printf( BLUE "EST" CLR); 
			else if(pack->st.state == LAST_ACK)
				printf(BLUE "LAST ACK" CLR);
			else if(pack->st.state == CLOSE_WAIT)
				printf(BLUE "CLOSE WAIT" CLR);
			else if(pack->st.state == INVALID)
				printf(RED "?" CLR);
			else if(pack->st.state == FIN_WAIT)
				printf(BLUE "FIN WAIT" CLR);
			else if(pack->st.state == IPFI_TIME_WAIT)
				printf(BLUE "TIME WAIT" CLR);
			else if(pack->st.state == NOTCP)
				     printf(YELLOW "???" CLR);
			else if(pack->st.state == UDP_NEW)
			       printf(YELLOW "NEW" CLR);
			else if(pack->st.state == UDP_ESTAB)
				        printf(YELLOW "STREAM" CLR);
			else if(pack->st.state == ICMP_STATE)
				          printf(DRED "ICMP" CLR);
			else if(pack->st.state == IGMP_STATE)
				printf(DVIOLET "IGMP" CLR);
			else if(pack->st.state == GUESS_ESTABLISHED)
				printf(MAROON "EST?" CLR);
			else if(pack->st.state == CLOSED)
				printf(BLUE "CLOSED" CLR);
			else if(pack->st.state == NOTCP)
				printf(YELLOW "S" CLR);
			else if(pack->st.state == GUESS_CLOSING)
				printf(MAROON "CLOSING?" CLR);
			else if(pack->st.state == INVALID_FLAGS)
				printf(RED "INVALID FLAGS!" CLR);
			else if(pack->st.state == NULL_FLAGS)
				printf(RED "NULL syn fin rst ack FLAGS!"CLR );
			else if(pack->st.state == GUESS_SYN_RECV)
				printf(MAROON "SETUP OK?" CLR);
			else if(pack->st.state != NOSTATE)
				printf("STATE: %d", pack->st.state);
			
	}
	else
		printf("  ");
	#ifdef ENABLE_RULENAME
	/* finally, print rule name */
	if(strlen(pack->rulename) > 0)
	{
		if(pack->response > 0)
			printf(GREEN "[" CLR "%s" GREEN "]", pack->rulename);
		else if(pack->response < 0)
			printf(RED "[" CLR "%s" RED "]", pack->rulename);
		else
			printf(MAROON "[" CLR "%s" MAROON "]", pack->rulename);
	}	
	#endif
	if(filter != NULL) /* if we are here we have passed the filter */
		 PCL, printf(" "),  PVIO, PBOLD, printf("F" CLR);

	printf(NL);
	return 0;
}

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
		snprintf(c, LOGLINELEN, "|%lu|%s|%d|%s|%d",
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
		snprintf(c, LOGLINELEN, "|%lu|%s|%d|%s|%d",
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
		snprintf(c, LOGLINELEN, "|%lu|%s|0|%s|0",
			pack->packet_id,
			src_address, 		
			dst_address);	
		flog(c);
		/* fill 6 flags  fields with don't cares */
		flog("|0|0|0|0|0|0");	
		break;
		default:
			flogpack(OTHER_PROTO);
			snprintf(c, LOGLINELEN, "|%lu", pack->packet_id);
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

