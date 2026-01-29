#include "includes/ipfire_userspace.h"
#include "includes/colors.h"
#include "includes/filter.h"
#include "includes/languages.h"


/* Returns a filter rule. 
 * The caller must free() this returned structure after use!
 */
ipfire_rule_filter* setup_filter(const char* filter)
{
	char s[MAXFILTERLINELEN];
	unsigned short port;
	struct in_addr ipaddr;
	int ret, pos;
	int ipok;
	ipfire_rule_filter *f;
	if(strcmp(filter, "\n") == 0)
		return NULL;
	f = (ipfire_rule_filter *) malloc(sizeof(ipfire_rule_filter ) );
	if(f == NULL)
	{
		perror("MEMORY ERROR! setup_filter()");
		return NULL;
	}
	memset(f, 0, sizeof(ipfire_rule_filter) );
	/* Create space for the ipfire_rule attached to the filter */
  	f->rule = (ipfire_rule* ) malloc(sizeof(ipfire_rule) );
	
	if(f->rule == NULL)
	{
		perror("MEMORY ERROR! setup_filter(), creating ipfire_rule");
		return NULL;
	}
	memset(f->rule, 0 , sizeof(ipfire_rule) );

	if(string_contains_pattern(filter, "accept"))
	{
		f->policy = 1;
		f->rule->nflags.policy = IPFI_ACCEPT;
	}
	if(string_contains_pattern(filter, "drop"))
	{
		f->policy = 1;
		f->rule->nflags.policy = IPFI_DROP;
	}
	if(string_contains_pattern(filter, "implicit"))
	{
		f->policy = 1;
		f->rule->nflags.policy = IPFI_IMPLICIT;
	}
			
	if(string_contains_pattern(filter, "output") )
	{
		f->out = 1;
		f->direction = 1;
	}
	if(string_contains_pattern(filter, "input") )
	{
		f->direction = 1;
		f->in = 1;
	}
	if(string_contains_pattern(filter, "fwd") )
	{
		f->direction = 1;
		f->fwd = 1;
	}
	if(string_contains_pattern(filter, "pre") )
	{
		f->direction = 1;
		f->pre = 1;
	}
	if(string_contains_pattern(filter, "post") )
	{
		f->direction = 1;
		f->post = 1;
	}

	if(string_contains_pattern(filter, "tcp") )
	{
		f->protocol = 1;
		f->tcp = 1;
	}
	if(string_contains_pattern(filter, "udp") )
	{
		f->protocol = 1;
		f->udp = 1;
	}
	if(string_contains_pattern(filter, "icmp") )
	{
		printf("string contains icmp!\n");
		f->protocol = 1;
		f->icmp = 1;
	}

	if(string_contains_pattern(filter, "nat") )
	{	
		f->nat = 1;
	}
	
	if(string_contains_pattern(filter, "dnat") )
	{	
		f->nat = f->dnat = 1;
	}
	if(string_contains_pattern(filter, "masquerade") )
	{	
		f->nat = f->snat = f->masquerade = 1;
	}
	if(string_contains_pattern(filter, "snat") )
	{	
		f->nat = f->snat = 1;
	}
	if(string_contains_pattern(filter, "state") )
	{	
		f->state = 1;
	}
	if(string_contains_pattern(filter, "stateless") )
	{	
		f->stateless = 1;
	}

	if((ret = string_contains_pattern(filter, "id") ) )
	{
	//	pos =  get_integer(filter + ret);
		sscanf(filter + ret, "%s", s);
		pos = atoi(s);
		f->position = 1;
		f->rule->position = pos;
	}

	if((ret = string_contains_pattern(filter, "port") ) )
	{
		PRED, printf("%s", TR("WARNING"));
		printf("%s", TR("The parameter port has effect only on the packet printing filtering,")); PNL;
		printf("%s", TR("not on the rule filtering.")); PNL;
		sscanf(filter + ret, "%s", s);
		port = (unsigned short) atoi(s);
		f->port = 1;
		f->rule->tp.sport[0] = port;
	}

	if((ret = string_contains_pattern(filter, "dport") ) )
	{
		sscanf(filter + ret, "%s", s);
		port = (unsigned short) atoi(s);
		f->port = f->dport = 1;
		f->rule->tp.dport[0] = port;
		
	}
	if((ret = string_contains_pattern(filter, "sport") ) )
	{
		sscanf(filter + ret, "%s", s);
		port = (unsigned short) atoi(s);
		f->port = f->sport = 1;
		f->rule->tp.sport[0] = port;
	}

	/* Only mysip or sip, not both */
	if((ret = string_contains_pattern(filter, "addr") ) )
	{
		PRED, printf("%s", TR("WARNING"));
		printf("%s", TR("The parameter addr has effect only on the packet printing filtering,")); PNL;
		printf("%s", TR("not on the rule filtering.")); PNL;

		f->ip = 1; 
		if(sscanf(filter + ret, "%s", s) )
		{
			ipok = inet_pton(AF_INET, s, &ipaddr);
			if(ipok > 0)
			{
				f->rule->nflags.src_addr = ONEADDR;
				/* we saave in ipsrc the ip */
				f->rule->ip.ipsrc[0] = ipaddr.s_addr;
			}
			else if(ipok == 0)
				printf("bad family");
			else
				printf("Address not valid!");
		}
	}
	

	if((ret = string_contains_pattern(filter, "mysip") ) )
	{
		f->ip = f->sip = 1; 
		f->rule->nflags.src_addr = MYADDR;
	}
	else if((ret = string_contains_pattern(filter, "sip") ) )
	{
		f->ip = f->sip = 1; 
		if(sscanf(filter + ret, "%s", s) )
		{
			ipok = inet_pton(AF_INET, s, &ipaddr);
			if(ipok > 0)
			{
				f->rule->nflags.src_addr = ONEADDR;
				f->rule->ip.ipsrc[0] = ipaddr.s_addr;
			}
			else if(ipok < 0)
				printf("bad family");
			else
				printf("Address not valid!");
		}
		else
			PRED, printf("%s", TR("scanf() failed") ); PNL, PNL;
	}
	
	/* Only mydip or dip, not both */
	if((ret = string_contains_pattern(filter, "mydip") ) )
	{
		f->ip = f->dip = 1;
		f->rule->nflags.dst_addr = MYADDR;
	}
	else if((ret = string_contains_pattern(filter, "dip") ) )
	{
		f->ip = f->dip = 1;
		if(sscanf(filter + ret, "%s", s) )
		{
			ipok = inet_pton(AF_INET, s, &ipaddr);
			if(ipok > 0)
			{
				f->rule->nflags.dst_addr = ONEADDR;
				f->rule->ip.ipdst[0] = ipaddr.s_addr;
			}
			else if(ipok < 0)
				printf("bad family");
			else
				printf("Address not valid!");
		}
		else
			PRED, printf("%s", TR("scanf() failed") ); PNL, PNL;
	}

	if((ret = string_contains_pattern(filter, "if") ) )
	{
		if(sscanf(filter + ret, "%s", s) )
		{
			f->device = 1;
			strncpy(f->rule->devpar.in_devname, s, IFNAMSIZ);
		}
		else
			printf("Nessuna interfaccia valida!");
	}
	if((ret = string_contains_pattern(filter, "inif") ) )
	{
		if(sscanf(filter + ret, "%s", s) )
		{
			f->device = 1;
			f->indevice = 1;
			strncpy(f->rule->devpar.in_devname, s, IFNAMSIZ);
		}
		else
			printf("Nessuna interfaccia valida!");
	}


	if((ret = string_contains_pattern(filter, "outif") ) )
	{
		if(sscanf(filter + ret, "%s", s) )
		{
			f->device = 1;
			f->outdevice = 1;
			strncpy(f->rule->devpar.out_devname, s, IFNAMSIZ);
		}
		else
			printf("Nessuna interfaccia valida!");
	}

	if(string_contains_pattern(filter, "setup") )
		f->state = f->setup = 1;
	if(string_contains_pattern(filter, "setupok") )
		f->state = f->setupok = 1;
	if(string_contains_pattern(filter, "est") )
		f->state = f->est = 1;
	if(string_contains_pattern(filter, "finwait") )
		f->state = f->finwait = 1;
	if(string_contains_pattern(filter, "closewait") )
		f->state = f->closewait = 1;
	if(string_contains_pattern(filter, "lastack") )
		f->state = f->lastack = 1;
	if(string_contains_pattern(filter, "timewait") )
		f->state = f->timewait = 1;
	if(string_contains_pattern(filter, "closed") )
		f->state = f->closed = 1;


	return f;

}

/* This one frees the ipfire_rule dynamically allocated 
 * by the setup_filter().
 * It must be called to free the dynamically allocated resources.
 */
void free_filter_rule(ipfire_rule_filter *f)
{
	if(f == NULL)
		return;
	if(f->rule != NULL)
		free(f->rule);
	if(f != NULL)
		free(f);
}

/* Returns 0 if pattern is NOT contained in string,
 * the position of the end of the pattern in the string if the
 * pattern is contained in string.
 */
int string_contains_pattern(const char *string, const char* pattern)
{
	int slen;
	int plen;
	int i;
	slen = strlen(string);
	plen = strlen(pattern);
	/* remove \n if present */
	/*if(string[slen - 1] == '\n')
	{
	string[slen - 1] = '\0';
	slen = strlen(string);
}
	*/
	if(plen > slen)
		return 0;
	for(i = 0; i <= slen - plen; i++)
	{
		if(strncmp(string + i, pattern, plen) == 0)
			return i + plen; /* returns the position of the end of the pattern */
	}
	return 0;

}

void print_filter(const ipfire_rule_filter *f)
{
	char stringip[INET_ADDRSTRLEN]; /* to store ip addresses, inet_ntop() */
	if(f == NULL)
	{
		PVIO, printf("%s", TR("The FILTER view is disabled") ); PNL, PNL;
		return;
	}
	printf(DVIOLET);
	printf("++++++++++++++++++ FILTER ++++++++++++++++++++++++"); PNL;
	if(f->direction)
	{
		printf("%s", TR("DIRECTION:") );
		if(f->in)
			printf(" INPUT ");
		if(f->out)
			printf(" OUTPUT ");
		if(f->pre)
			printf(" PRE ROUTING ");
		if(f->post)
			printf(" POST ROUTING ");
		if(f->fwd)
			printf(" FORWARD ");
		PNL;
	}
	if(f->protocol)
	{
		printf("%s", TR("PROTOCOL:"));
		if(f->tcp)
			printf(" TCP ");
		if(f->udp)
			printf(" UDP ");
		if(f->icmp)
			printf(" ICMP ");
		PNL;
	}
	if(f->policy)
	{
		printf("%s", TR("POLICY:") );
		if(f->rule->nflags.policy == IPFI_ACCEPT)
			printf("%s", TR(" ACCEPT "));
		else if(f->rule->nflags.policy == IPFI_DROP)
			printf("%s", TR(" DROP "));
		else 
			printf("%s", TR(" IMPLICIT ") );
		PNL;
	}
	if(f->state)
	{
		printf("%s", TR("STATE MATCH: "));
		if(f->setup)
			printf("SETUP ");
		if(f->setupok)
			printf("SETUP OK ");
		if(f->est)
			printf("EST ");
		if(f->finwait)
			printf("FIN WAIT ");
		if(f->closewait)
			printf("CLOSE WAIT ");
		if(f->lastack)
			printf("LAST ACK ");
		if(f->timewait)
			printf("TIME WAIT ");
		if(f->closed)
			printf("CLOSED ");
		if(! (f->setup & f->setupok & f->est & f->finwait &
				    f->closewait & f->lastack & f->timewait & f->closed ) )
			printf("%s", TR("STATEFUL RULES OR PACKETS") );
		PNL;
	}
	if(f->position)
	{
		printf("%s", TR("POSITION (for rules): "));
		printf("%d", f->rule->position);
		PNL;
	}
	if(f->nat)
	{
		printf("NAT: ");
		if(f->dnat)
			printf("%s", TR("DESTINATION ") );
		if(f->snat)
			printf("%s", TR("SOURCE ") );
		if(f->masquerade)
			printf("%s", TR("MASQUERADE "));
		PNL;
	}
	if(f->device)
	{
		printf("%s", TR("DEVICE: "));
		if(! f->indevice && ! f->outdevice)
		{
			printf("%s (IN OR OUT) ", f->rule->devpar.in_devname);
		}
		else
		{
			if(f->indevice)
				printf("INPUT: %s ", f->rule->devpar.in_devname);
			if(f->outdevice)
				printf("OUTPUT: %s ", f->rule->devpar.out_devname);
		}

	}
	if(f->ip)
	{
		printf("%s", TR("IP ADDRESS: "));
		if(!f->dip && !f->sip)
			printf("%s", TR("%s (ANY BETWEEN SOURCE OR DESTINATION)"), inet_ntop(AF_INET, 
			       (void *) &(f->rule->ip.ipsrc), stringip, INET_ADDRSTRLEN ) );
		if(f->sip)
			printf("%s", TR("SOURCE: %s "), inet_ntop(AF_INET, 
			       (void *) &(f->rule->ip.ipsrc), stringip, INET_ADDRSTRLEN ) );

		if(f->dip)
			printf("%s", TR("DESTINATION: %s "), inet_ntop(AF_INET, 
			       (void *) &(f->rule->ip.ipdst), stringip, INET_ADDRSTRLEN ) );
		PNL;

	}
	if(f->port)
	{
		printf("%s", TR("PORT: "));
		if(!f->dport && !f->sport)
			printf("%s", TR("%u (ANY BETWEEN SOURCE OR DESTINATION)"), f->rule->tp.sport);
		if(f->sport)
			printf("%s", TR("SOURCE: %u "), f->rule->tp.sport);
		if(f->dport)
			printf("%s", TR("DESTINATION: %u "), f->rule->tp.dport);
		PNL;
	}
	


	printf(DVIOLET);
	printf("++++++++++++++++++++++++++++++++++++++++++++++++++"); PNL;

}



void print_filter_help()
{
	printf("-----------------------------------------------\n");
	PUND, PGRN, printf("%s", TR("KEYWORDS:")); PNL;
	printf("%s", TR("POLICY:") ); PCL;
	PGRAY, printf(" accept, drop, implicit (only for the console messages)."); PNL;
	printf("%s", TR("DIRECTION: ")); PCL;
	PGRAY, printf(" input, output, fwd, pre, post."); PNL;
	printf("%s", TR("PROTOCOL:")); 
	PGRAY, printf(" tcp, udp, icmp."); PNL;
	printf("%s", TR("ADDRESS TRANSLATION:"));
	PGRAY, printf("%s", TR(" nat (all nat/masq), snat, dnat, masquerade.")); PNL;
	printf("%s", TR("STATE:"));
	PGRAY, printf("%s", TR(" state (matches all stateful rules/packets)")); PNL;
	PGRAY, printf("       setup, setupok, est, finwait, closewait, lastack, timewait, closed."); PNL;
	PGRAY, printf("%s", TR("       stateless (in conjunction with specific flags, to show")), PNL;
	PGRAY, printf("%s", TR("       the specific states and the stateless packets together).")); PNL;
	PNL;
	PUND, PGRN, printf("%s", TR("KEYWORDS followed by a VALUE:") ); PNL;
	printf("%s", TR("POSITION IN THE RULES LIST:"));
	PGRAY, printf(" id n"); PNL;
	printf("%s", TR("IP ADDRESS:"));
	PGRAY, printf("%s", TR(" sip x.y.z.w,  dip a.b.c.d; mysip, mydip (for rules)")); PNL;
	PGRAY, printf("%s", TR("            addr h.i.l.m, (for packets only, matches any between src and dst.)")); PNL;
	printf("%s", TR("PORTS (for tcp and UDP):"));
	PGRAY, printf(" sport x, dport y, port a (for packets only, matches any between src and dst.)"); PNL;
	printf("%s", TR("NETWORK INTERFACES:"));
	PGRAY, printf("%s", TR(" if name (matches input or output), inif name, outif name") );
	PNL, PNL;
	printf("-----------------------------------------------\n");
	PUND, PGRN, printf("%s", TR("EXAMPLES:")); PNL;
	printf("%s", TR("The following shows the packets/rules in the output direction")); PNL;
	printf("%s", TR("with protocol tcp, destination ip 192.168.0.2, accepted by the firewall")); PNL;
	printf("%s", TR("(or a permission rule if one is filtering on rules), and passing through")); PNL;
	printf("%s", TR("the \"eth0\" network interface:")); PNL; PNL;
	PGRN; printf("out tcp dip 192.168.0.2 accept if eth0"); PNL; PNL;
	printf("-----------------------------------------------\n"); PNL;
}

/* This one prepares a string to provide a filter to 
 * setup_filter(). 
 * Returns a memory allocated char * which must be freed by
 * the  caller after use.
 */
char *setup_filter_pattern()
{
	char* sfilter = (char *)malloc(sizeof(char) * MAXFILTERLINELEN);
	/* together with fgets with MAXFILTERLINELEN-1 assures that the 
	* string will be 0 terminated.
	*/
	memset(sfilter, 0, MAXFILTERLINELEN);
	do{
		PNL;
		printf("%s", TR("------------ SETUP THE FILTER ------------"));
		PNL;
		printf("%s", TR("[type \"help\" (+return) for the list of the available keywords.]")); PNL;
		fgets(sfilter, MAXFILTERLINELEN-1, stdin); 
		if(strncmp(sfilter, "help", 4) ==0)
			print_filter_help();
	}while(strncmp(sfilter, "help", 4) ==0);

	return sfilter;
}


