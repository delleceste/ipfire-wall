#include <ipfire_structs.h>
#include "includes/ipfire_userspace.h"
#include "includes/languages.h"

/* functions treating parameters received by command line */
void init_cmdopts(struct cmdopts* cmdo)
{
  memset(cmdo, 0, sizeof(struct cmdopts));
  cmdo->noflush_on_exit = 0;
  cmdo->loguser = 4; /* medium: 0 ... 7 */
}

/* initializes file names to default values */
int init_useropts(struct userspace_opts *uops)
{
  char home[PWD_FIELDS_LEN]; /* 64 chars */
  int len;
		
  memset(uops->logfile_name, 0, MAXFILENAMELEN);
  strcpy(uops->permission_filename, "");
  strcpy(uops->blacklist_filename, "");
  strcpy(uops->translation_filename, "");
  strcpy(uops->options_filename, "");
  strcpy(uops->blacksites_filename, "");
  strcpy(uops->mailer_options_filename, "");
	
  len = get_user_info(HOMEDIR, home);
  
  /* PWD_FIELDS_LEN is 20, filenames are MAXFILENAMELEN (60) */
  /* default log file */
  strcat(uops->logfile_name, home);
  strcat(uops->logfile_name, "/.IPFIRE/ipfire.log");
	
  strcat(uops->permission_filename, home);
  strcat(uops->permission_filename, "/.IPFIRE/allowed");
	
  strcat(uops->blacklist_filename, home);
  strcat(uops->blacklist_filename, "/.IPFIRE/blacklist");
	
  strcat(uops->translation_filename, home);
  strcat(uops->translation_filename, "/.IPFIRE/translation");
	
  strcat(uops->options_filename, home);
  strcat(uops->options_filename, "/.IPFIRE/options");
	
  strcat(uops->blacksites_filename, home);
  strcat(uops->blacksites_filename, "/.IPFIRE/blacksites");
  
  strcat(uops->mailer_options_filename, home);
  strcat(uops->mailer_options_filename, "/.IPFIRE/mailer/options");
	
  uops->clearlog = 0;
  uops->loglevel = 1;
  uops->resolv_services = 0;
  uops->dns_refresh = 14400; /* every 4 hours */
  uops->dns_resolver = 0;
  
  uops->policy = -1; /* default, drop (0). accept is (1), uninit or error -1 */
  uops->proc_rmem_max = -1;
  uops->proc_rmem_default = -1;
  
	
  return 0;
}

void init_command(command* cmd)
{
  memset( (void *) cmd, 0, sizeof(command));
  /* initialize loguser to a mean value */
  cmd->loguser = 4;  
  /* lifetime, in seconds, of dynamic entries in tables */
  cmd->snatted_lifetime = 100;
  cmd->dnatted_lifetime = 100;
  cmd->state_lifetime = 200;
  cmd->setup_shutd_state_lifetime = 120;
  cmd->max_nat_entries = 262144;
  cmd->max_loginfo_entries = 512;
  cmd->max_state_entries = 8192;
  cmd->loginfo_lifetime = 20;
}

void toupper_username(char* upperun)
{
  int i = 0;
  if(get_user_info(USERNAME, upperun) < 0)
    {
      printf(RED "Error getting username!" NL);
      strcpy(upperun, "UNKNOWN!");
    }
  else
    {
      while( (i < strlen(upperun)) && 
	     (i < PWD_FIELDS_LEN -1))
	{
	  upperun[i] = toupper(upperun[i]);
	  i++;
	}
      upperun[i] = '\0';
    }
}

/* if type is USERNAME, user name is copied in info,
 * else if type is HOMEDIR, home directory name is
 * copied in info */
int get_user_info(int type, char* info)
{
  struct passwd* pwd;
  pwd = getpwuid(getuid());
  if(pwd == NULL)
    return -1;
  if(type == USERNAME)
    strncpy(info, pwd->pw_name, PWD_FIELDS_LEN);
  else if(type == HOMEDIR)
    strncpy(info, pwd->pw_dir, PWD_FIELDS_LEN);
  return strlen(info);
}

int load_module(void)
{
  char modprobe_command[1024];
  char* argv[3];
  int ret, status;
	
  if( (ret = module_already_loaded()) > 0)
    return 1;
  else if(ret < 0)
    return -1;
	
  if(get_modprobe_command(modprobe_command) < 0)
    return -1;

  switch (fork()) {
  case 0:
    argv[0] = (char *)modprobe_command;
    argv[1] = (char *)MODULENAME;
    argv[2] = NULL;
    execv(argv[0], argv);

    /* not usually reached */
    exit(1);
  case -1:
    perror(TR("Fork failed"));
    return -1;

  default: /* parent */
    /* wait suspends execution of process until one of its children
     * terminates. */
    wait(&status);
  }
  /* WIFEXITED says if son exited normally (true), WEXITSTATUS
   * returns the exit status of the child, to use if WIFEXITED returned
   * true */
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 0;
	
  return -1;
}


int unload_module(void)
{
  char modprobe_command[1024];
  char *argv[4];
  char rem[3] = "-r";
  int status;
	
  if(get_modprobe_command(modprobe_command) < 0)
    return -1;
	
  switch (fork()) {
  case 0:
    argv[0] = (char *)modprobe_command;
    argv[1] = (char *)rem;
    argv[2] = (char *)MODULENAME;
    argv[3] = NULL;
    execv(argv[0], argv);

    /* not usually reached */
    exit(1);
  case -1:
    return -1;

  default: /* parent */
    wait(&status);
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 0;
	
  return -1;
}

int get_modprobe_command(char* mpcmd)
{
  int procfile;
  memset(mpcmd, 0, 1024);
  procfile = open(PROC_SYS_MODPROBE, O_RDONLY);
  if (procfile < 0)
    return -1;
	
  /* buffer passed (mpcmd) is 1024 sized */
  switch (read(procfile, mpcmd, 1024))
    {
    case -1: 
      goto fail;
    case 1024: 
      goto fail; /* Partial read.  Wierd */
    }
  if (mpcmd[strlen(mpcmd)-1]=='\n') 
    mpcmd[strlen(mpcmd)-1]=0;
  close(procfile);
  return 0;
 fail:
  close(procfile);
  return -1;
}

/* returns -1 in case of error, 0 if ipfi is not loaded,
 * 1 if ipfi kernel module is already loaded. */
int module_already_loaded(void)
{
  FILE* fp;
  char line[1024];
  fp = fopen(PROC_MODULES, "r");
  if(fp == NULL)
    {
      PRED, printf(TR("Error opening file %s fo reading")
	     , PROC_MODULES), PNL, PNL;
      return -1;
    }
  while(fgets(line, 1024, fp) != NULL)
    {
      if( ! strncmp(line, MODULENAME, strlen(MODULENAME)))
	{
	  fclose(fp);
	  /* found a line in /proc/modules matching "ipfi" */
	  return 1;
	}
    }
  fclose(fp);
  return 0; /* not loaded */
}

#ifdef ENABLE_RULENAME
void get_rule_name(const char* line, char* name)
{
  unsigned i = 0, j = 0;
	
  while(line[i] != '=')
    i++;
	
  i++; /* pass by '=' */
	
  while( (line[i] != '\0') && (i < MAXLINELEN) &
	 (j < RULENAMELEN - 1))
    {
      name[j] = line[i];
      i++, j++;
    }
  name[j] = '\0';
}
#endif

/* address in string addr in the form x.y.z.w/a.b.c.d
 * or x.y.z.w/n is converted in a string of the form 
 * h.i.l.m-p.q.r.s */
int cidr_to_interval(char* addr)
{
	__u32 inetaddress;
	__u32 inetmask;
	__u32 start_address, end_address;
	short dotted_decimal;
	dotted_decimal = get_address_and_mask(addr,
					      &inetaddress, &inetmask);
	
	if(dotted_decimal < 0)
		return -1;
	
	if(dotted_decimal > 0)
	{
		addr_and_dotted_mask_to_inet_interval(inetaddress, 
				inetmask, &start_address, &end_address); 
	}
	else
	{
		addr_and_integer_to_inet_interval(inetaddress, 
				inetmask, &start_address, &end_address);
	}
	
	if(addresses_to_string_interval(addr, start_address, 
	   end_address) < 0)
		return -1;

	return 0;	
}

int fill_ip_interval(const char* addr, ipfire_rule* r, int direction)
{
	int i = 0, j = 0;
	char firstaddr[INET_ADDRSTRLEN];
	char endaddr[INET_ADDRSTRLEN];
	struct in_addr add1, add2;
	
	/* pass first blanks */
	while((i < strlen(addr)) && (isblank(addr[i])))
		i++;
	if(i == strlen(addr))
	{
	  printf("\e[1;31m* \e[0mcommon.c: fill_ip_interval(): cursor for input argument would go beyond boundaries!\n");
	  return -1;
	}
	/* get first address */
	while((i < strlen(addr)) && (j < INET_ADDRSTRLEN-1) && (!isblank(addr[i])) && (addr[i] != '-'))
	{
		firstaddr[j] = addr[i];
		j++, i++;
	}
	firstaddr[j] = '\0';
	/* if we did not find a "-", llok for it */
	if((i < strlen(addr)) && (addr[i] != '-'))
	{
		while(addr[i] != '-')
			i++;
	}
	/* now we found it: pass through */
	i++;
	/* now pass other blanks */
	while( (i < strlen(addr)) && (isblank(addr[i])))
		i++;
	if(i == strlen(addr))
	{
	  printf("\e[1;31m* \e[0mcommon.c: fill_ip_interval() [step 2]: cursor for input argument would go beyond boundaries!\n");
	  return -1;
	}
	/* finally, get second address */
	j=0;
	while((i < strlen(addr)) && (j < INET_ADDRSTRLEN-1) && (!isblank(addr[i])) && (addr[i] != '\0'))
	{
		endaddr[j] = addr[i];
		i++, j++;
	}
	endaddr[j] = '\0';
	if(inet_pton(AF_INET, firstaddr, &add1) <= 0)
	{
		PRED, perror(TR("fill_ip_interval(): error getting first address!")); PCL;
		return -1;
	}	
	if(inet_pton(AF_INET, endaddr, &add2) <= 0)
	{
		PRED, perror(TR("fill_ip_interval(): error getting second address!")); PCL;
		return -1;
	}
	/* first ip must be less than second */
	if(check_ip_interval( ntohl(add1.s_addr), ntohl(add2.s_addr)) < 0)
		return -1;
	
	/* now we have all we need: fill in rule fields */
	if(direction == SOURCE)
	{
		r->nflags.src_addr = 1;	
		r->parmean.samean = INTERVAL;
		/* INTERVAL: ipsrc[0] -> start of interval. ipsrc[1] -> end of interval */
		r->ip.ipsrc[0] = add1.s_addr;	
		r->ip.ipsrc[1] = add2.s_addr;		
	}
	else
	{
		r->nflags.dst_addr = 1;	
		r->parmean.damean = INTERVAL;
		/* INTERVAL: ipsrc[0] -> start of interval. ipsrc[1] -> end of interval */
		r->ip.ipdst[0] = add1.s_addr;	
		r->ip.ipdst[1] = add2.s_addr;
	}
	return 0;
}

/* simple ip */
int fill_plain_address(const char* naddr, ipfire_rule* r, 
		       int direction)
{
	int i = 0, k = 0, j = 0;
	struct in_addr add;
	char inetaddr[INET_ADDRSTRLEN];
	
	while(k < strlen(naddr) && (!isdigit(naddr[k])))
		k++;
	if(k >= strlen(naddr))
	{
	  printf("\e[1;31m*\e[0m common.c: fill_plain_address(): passed address would go beyond boudaries!\n");
	  return -1;
	}
	
	for(i = k, j = 0; i < MAXLINELEN &&
		   j < INET_ADDRSTRLEN - 1; i++, j++)
		inetaddr[j] = naddr[i];
	inetaddr[j] = '\0';
	if(inet_pton(AF_INET, inetaddr, &add) <= 0)
	{
		perror(TR("common.c: fill_plain_address(): error in input address"));
		return -1;
	}
	
	if(direction == SOURCE)
	{
		r->nflags.src_addr = 1;
		r->parmean.samean = SINGLE;
		/* SINGLE: ipsrc[0], fist element of the vector */
		r->ip.ipsrc[0] = (__u32) add.s_addr;
	}
	else
	{
		r->nflags.dst_addr = 1;
		r->parmean.damean = SINGLE;
		r->ip.ipdst[0] = (__u32) add.s_addr; /* ipdst[0] */
	}
	return 0;
}

/* given an address and a netmask in integer decimal form,
 * fills in min and max values of internet addresses according
 * to netmask value */
void addr_and_integer_to_inet_interval(const __u32 inetaddress, 
				       const __u32 inetmask, __u32* start_address, __u32* end_address)
{
	struct in_addr addr;
	/* init netmask to 255.255.255.255 */
	__u32 nmask = 0xFFFFFFFF;
	__u32 not_mask;
  /* left shift of a number of bits equal to those
  * which have to be set to zero in mask.  */
	nmask = htonl(nmask << (32 - inetmask));
	addr.s_addr = nmask;
	/* calculate minimum value of ip address */
	*start_address = inetaddress & nmask;
	/* now maximum value */
	not_mask = ~nmask;
	*end_address = (*start_address | not_mask);
}

/* given two addresses in network byte order, transforms
 * them into strings and then forms an interval of the form
 * 192.168.0.0-192.168.0.100 */
int addresses_to_string_interval(char* addr, 
				 const __u32 starta, const __u32 enda)
{
	char a[INET_ADDRSTRLEN]; /* address1 */
	char b[INET_ADDRSTRLEN]; /* address2 */
	char interval[MAXLINELEN];
	
	strcpy(interval, "");
	
	if(inet_ntop(AF_INET, (void*) &starta, a, INET_ADDRSTRLEN) < 0)
	{
		perror(RED "Error in addresses_to_string_interval()\n"
				"[start address]" CLR);
		return -1;
	}
	if(inet_ntop(AF_INET, (void*) &enda, b, INET_ADDRSTRLEN) < 0)
	{
		perror(RED "Error in addresses_to_string_interval()\n"
				"[end address]" CLR);
		return -1;
	}
	
	strncat(interval, a, INET_ADDRSTRLEN);
	strcat(interval, "-");
	strncat(interval, b, INET_ADDRSTRLEN);
	strncpy(addr, interval, MAXLINELEN);
	return 0;
}

/* given an address and a netmask in dotted decimal form,
 * fills in min and max values of internet addresses according
 * to netmask value */
void addr_and_dotted_mask_to_inet_interval(const __u32 address, 
					   const __u32 mask, __u32* start_address, 
	__u32* end_address)
{
	/* inver bits of mask */
	__u32 not_mask = ~mask;
	/* start address: and with netmask */
	*start_address = address & mask;
	/* end address: or with inverted mask */
	*end_address = (*start_address | not_mask);
}


int check_ip_interval(u32 ip1, u32 ip2)
{
	char addr[INET_ADDRSTRLEN];
	if(ip1 >= ip2)
	{
		PRED, printf(TR("First address [%s] must be less than second [%s]!"),
			     inet_ntop(AF_INET, &ip1, addr, INET_ADDRSTRLEN), 
				       inet_ntop(AF_INET, &ip2, addr, INET_ADDRSTRLEN)); PNL;
			     return -1;
	}
	return 0;
}

/* parses addr and returns 1 if mask is expressed in 
 * dotted decimal form (i.e. 192.168.1.100/255.255.255.0),
 * 0 otherwise (i.e. 192.168.1.100/24). -1 in case of error. */
int get_address_and_mask(const char* addr, 
			 __u32* address, __u32* mask)
{
	int i = 0, j = 0;
	int dots = 0;
	char tmpaddr[MAXLINELEN];
	*address = 0;
	*mask = 0;
		
	while( ( i < strlen(addr)) && ( i < MAXLINELEN))
	{
		if(addr[i] == '/')
			break;
		tmpaddr[j] = addr[i];
		i++, j++;
	}	
	tmpaddr[j] = '\0';
	
	if( i == strlen(addr)) /* did not find '/' */
		return -1;
	
	if(inet_pton(AF_INET, tmpaddr, (struct in_addr*) address) <= 0)
	{
		printf(RED "BAD address \"%s\"!" NL, tmpaddr);
		perror("");
		return -1;
	}
	
	i++; /* pass '/' */
	j = 0;
	while( ( i < strlen(addr)) && ( i < MAXLINELEN))
	{
		tmpaddr[j] = addr[i];
		if(addr[i] == '.')
			dots++;
		i++, j++;
	}
	if( (dots != 3) && (dots != 0))
		return -1;
	
	tmpaddr[j] = '\0';
	if(dots == 3)
	{
		if(inet_pton(AF_INET, tmpaddr, (struct in_addr*) mask) <= 0)
		{
			printf(RED "BAD mask \"%s\"!" NL, tmpaddr);
			perror("");
			return -1;
		}
		return 1;
	}
	else if(dots == 0)
	{
		*mask = (__u32) atoi(tmpaddr);
		return 0;
	}
	
	return -1;	
}


/* calls fill_ip_interval to fill rule with right addresses making
 * part of the interval, then changes values of meanings */
int fill_not_ip_interval(const char* addr, ipfire_rule* r, int direction)
{
	if(fill_ip_interval(addr, r, direction) < 0)
		return -1;
	/* change meanings now */
	if(direction == SOURCE)
		r->parmean.samean = INTERVAL_DIFFERENT_FROM;
	else
		r->parmean.damean = INTERVAL_DIFFERENT_FROM;
	return 0;
}

/* given a string, without leading "!",  fills in
 * r with appropriate values for ip addresses */
int fill_not_ip(const char* naddr, ipfire_rule* r, int direction)
{
	struct in_addr add;
	
	if(inet_pton(AF_INET, naddr, &add) <= 0)
	{
		perror(TR("common.c: fill_not_ip(): error in input address"));
		return -1;
	}
	
	if(direction == SOURCE)
	{
		r->nflags.src_addr = 1;
		r->parmean.samean = DIFFERENT_FROM;
		/* DIFFERENT_FROM: fill in first element */
		r->ip.ipsrc[0] = (__u32) add.s_addr;
	}
	else
	{
		r->nflags.dst_addr = 1;
		r->parmean.damean = DIFFERENT_FROM;
		r->ip.ipdst[0] = (__u32) add.s_addr; /* DIFFERENT_FROM: fill in first element */
	}
	return 0;
}


/* returns 0 if it's not an interval, the position of
 * dividing character "-" otherwise */
int is_interval(const char* line)
{
	int i = 0;
	while(line[i] != '\0')
	{
		if((i < strlen(line)) && (line[i] == '-' ))
			return i;
		i++;
	}
	return 0;
}

/* returns 1 if address in string addr
 * is expressed in cidr form */
int is_cidr(const char* addr)
{
	int i = 0;
	while( (i < strlen(addr)) && (i < MAXLINELEN))
	{
		if(addr[i] == '/')
			return 1;
		i++;
	}
	return 0;
}

/* removes first n nondigits from string addr */
void remove_exclmark(char* addr)
{
	int i = 0, j = 0;
	int addrlen = strlen(addr);
	char cleanaddr[MAXLINELEN];
	while(i < strlen(addr) && (!isdigit(addr[i])))
		i++;
	if(i == strlen(addr))
	{
	  printf("\e[1;31m* \e[0mcommon.c: remove_exclmark(): cursor for input argument would go beyond boundaries!\n");
	  return;
	}
	while((j < MAXLINELEN -1) &&  (i < addrlen) && (addr[i] != '\0')) /* &
		( (isdigit(addr[i])) | (addr[i] == '.' ))) */
	{
		cleanaddr[j] = addr[i];
		i++, j++;
	}
	cleanaddr[j] = '\0';
	strncpy(addr, cleanaddr, addrlen);
}

/* gets a line from standard input performing some
 * operations as returning 0 if line is made of a single
 * newline, -1 in case of error. */
int get_line(char * dest)
{
	fgets(dest, MAXLINELEN, stdin);
	/* throw away newline */
	if(strlen(dest) > 0)
		dest[strlen(dest) - 1] = '\0';
	if( (strlen(dest) == 1) && (strncmp(dest, "x", 1) == 0))
		return -1;
	else if(strlen(dest) == 0)
		return 0;
	return 1;
}

/* transport layer specific functions */

int fill_port_interval(const char* port, ipfire_rule* r, int direction)
{
	int i = 0, j = 0;
	char firstport[6];
	char endport[6];
	int port1, port2;
	
	/* pass first blanks */
	while((i < strlen(port)) && (isblank(port[i])))
		i++;		
	/* get first port */
	while((j < 5) && (i < strlen(port)) && (!isblank(port[i])) && (port[i] != '-'))
	{
		firstport[j] = port[i];
		j++, i++;
	}
	firstport[j] = '\0';
	/* if we did not find a "-", llok for it */
	if((i < strlen(port)) && (port[i] != '-'))
	{
		while((i < strlen(port)) && (port[i] != '-'))
			i++;
	}
	/* now we found it: pass through */
	i++;
	/* now pass other blanks */
	while((i < strlen(port)) && (isblank(port[i])))
		i++;	
	/* finally, get second port */
	j=0;
	while((i < strlen(port)) && (j < 5) && (!isblank(port[i])) && (port[i] != '\0'))
	{
		endport[j] = port[i];
		i++, j++;
	}
	endport[j] = '\0';
	
	port1 = (int) atoi(firstport);
	port2 = (int) atoi(endport);
	
	if(check_port_interval(port1, port2) < 0)
		return -1;
	/* values are ok */
	if(direction == SOURCE)
	{
		r->nflags.src_port = 1;
		/* INTERVAL: start -> sport[0], end -> sport[1] */
		r->tp.sport[0] =htons( (u16) port1);
		r->tp.sport[1] =htons( (u16) port2);
		r->parmean.spmean = INTERVAL;
	}
	else
	{
		r->nflags.dst_port = 1;
		r->tp.dport[0] = htons( (u16) port1);
		r->tp.dport[1] = htons( (u16) port2);
		r->parmean.dpmean = INTERVAL;
	}
	
	return 0;
}

int fill_not_port_interval(const char* port, ipfire_rule* r, int direction)
{
	if(fill_port_interval(port, r, direction) < 0)
		return -1;
	/* change meanings */
	if(direction == SOURCE)
		r->parmean.spmean = INTERVAL_DIFFERENT_FROM;
	else
		r->parmean.dpmean = INTERVAL_DIFFERENT_FROM;
	return 0;
}

int fill_plain_port(const char* port, ipfire_rule* r, int direction)
{
	char cport[6];
	u16 pt;
	int i = 0, j = 0, k = 0;
	
	while(k < strlen(port) && (!isdigit(port[k])))
		k++;
	if(k >= strlen(port))
	{
	  printf("\e[1;31m *\e[0mcommon.c: fill_plain_port(): cursor in port argument would go out of bounds.");
	  return -1;
	}
	
	for(i = k, j = 0; i < MAXLINELEN &&
		   j < 5; i++, j++)
		cport[j] = port[i];
	cport[j] = '\0';
	
	if( (atoi(cport) < MINPORT) | (atoi(cport) > MAXPORT))
		return -1;
	
	pt = htons( (u16) atoi(cport));
	
	if(direction == SOURCE)
	{
		r->nflags.src_port = 1;
		r->parmean.spmean = SINGLE;
		r->tp.sport[0] = pt;
	}
	else
	{
		r->nflags.dst_port = 1;
		r->parmean.dpmean = SINGLE;
		r->tp.dport[0] = pt;
	}
	return 0;
}

/* checks if ports specified are ok and if first port is
 * less than second. Equal values are not allowed */
int check_port_interval(int p1, int p2)
{
	if( (p1 < MINPORT) | (p1 > MAXPORT))
	{
		PRED, printf(TR("Bad value for the first port! Must be between %d and %d!")
				, MINPORT, MAXPORT ), PNL;
				return -1;
	}
	
	if( (p2 < MINPORT) | (p2 > MAXPORT))
	{
		PRED, printf(TR("Bad value for the second port! Must be between %d and %d!")
				, MINPORT, MAXPORT ), PNL;      return -1;	
	}
	
	if(p1 >= p2)
	{
		PRED, printf(TR("%d, the first port, is not less than %d, the second!"),
			     p1, p2), PNL;
			     return -1;
	}
	
	return 0;
}

int fill_not_port(const char* port, ipfire_rule* r, int direction)
{
	int pt;
	printf("fill_not_port()\n");
	if( ( (pt = atoi(port)) < MINPORT) || (pt > MAXPORT ))
	{
		PRED, printf(TR("Value of port must be between %d and %d, not %d!"),
			     MINPORT, MAXPORT, pt ), PNL;
			     return -1;
	}
	
	if(direction == SOURCE)
	{
	  printf("source\n");
		r->nflags.src_port = 1;
		r->parmean.spmean = DIFFERENT_FROM;
		r->tp.sport[0] = htons( (u16) pt);
	}
	else
	{
	  printf("destn");
		r->nflags.dst_port = 1;
		r->parmean.dpmean = DIFFERENT_FROM;
		r->tp.dport[0] = htons( (u16) pt);
	}
	printf("esco con successo da fill_not_port()\n");
	return 0;
}


int get_string(char *string, const char* line)
{
  unsigned int i = 0;
  unsigned int j = 0;

  while( (i < strlen(line)) && (i < MAXLINELEN) && (line[i] != '=') )
    i++;
  if(i == strlen(line) || i == MAXLINELEN)
  {
    printf("\e[1;31m*\e[0m common.c: get_string(): index of input argument would go beyond boundaries!\n");
    return -1;
  }
  
  i++; /* pass the '=' */
  
  /* accept a number of spaces after the '=', and when we get a character
   * different from a space, we assume it is the first character of the address
   */
  while((i < strlen(line))  && (i < MAXLINELEN)  && (line[i] == ' '))
    i++;
  if(i == strlen(line) || i == MAXLINELEN)
  {
    printf("\e[1;31m*\e[0m common.c: get_string(): index of input argument would go beyond boundaries!\n");
    return -1;
  }
  /* read the rest of the string containing the address */
  while( (i < strlen(line)) && (i < MAXLINELEN) && (j < 16))
    /* 16 is the value of IFNAMSIZ and 15 is the maximum number
     * of digits of an ipv4 address */
    {
      string[j]=line[i];
      i++;
      j++;
    }
  string[j]='\0'; /* terminate string */
  return 0;
}

/* copy into string at most limit characters */
int get_string_n(char *string, const char* line, int limit)
{
  unsigned int i = 0;
  unsigned int j = 0;
  while(  (i < strlen(line))  && (i < MAXLINELEN) && (line[i] != '='))
    i++;
  
  if(i == strlen(line) || i == MAXLINELEN)
  {
    printf("\e[1;31m*\e[0m common.c: get_string_n(): index of input argument would go beyond boundaries!\n");
    return -1;
  }
  i++; /* pass '=' */
  
  /* accept a number of spaces after the '=', and when we get a character	 
   * different from a space, we assume it is the first character of the address
   */
  while( (line[i] == ' ') && (i < strlen(line))  && (i < MAXLINELEN))
    i++;
  
  if(i == strlen(line) || i == MAXLINELEN)
  {
    printf("\e[1;31m*\e[0m common.c: get_string_n(): index of input argument would go beyond boundaries!\n");
    return -1;
  }
  /* read the rest of the string containing the address */
  while( (i < strlen(line)) && (j < limit) && (i < MAXLINELEN) && (line[i] != '\n'))
    /* 16 is the value of IFNAMSIZ and 15 is the maximum number
     * of digits of an ipv4 address */
    {
      string[j]=line[i];
      i++;
      j++;
    }
  string[j]='\0'; /* terminate string */
	return 0;
}

int get_integer(const char* line)
{
  unsigned int i = 0;
  unsigned int j = 0;
  char temp[15];
  while((i < strlen(line)) && (i < MAXLINELEN) &&  (line[i] != '='))
    i++;
  if(i == strlen(line) || i == MAXLINELEN)
  {
    printf("\e[1;31m*\e[0m common.c: get_integer(): index of input argument would go beyond boundaries!\n");
    return -1;
  }
  i++;
  while( (i < strlen(line)) && (j < 14) && (i < MAXLINELEN))
    {
      temp[j] = line[i];
      j++;
      i++;
    }
  temp[j] = '\0';
  return atoi(temp);
}

int get_address(struct in_addr *addr, const char* line)
{
  char ch_address[16];
  get_string(ch_address, line);
  return inet_pton(AF_INET, ch_address, addr);
}

void init_rule(ipfire_rule* rule)
{
  memset( (void*) rule, 0, sizeof(ipfire_rule));
#ifdef ENABLE_RULENAME
  strcpy(rule->rulename, "");
#endif
}


/* checks if timeouts are too long and, if so, sets them to the maximum
 * value allowed. See ipfire_userspace.h near definition of MAX_TIMEOUT 
 */
void check_max_lifetime_values(command* opt)
{
	if(opt->snatted_lifetime > MAX_TIMEOUT)
	{
		printf(VIOLET "Warning: value %lu for snat timeout too high:\n"
				"setting it to maximum allowed: %lu seconds." NL,
				opt->snatted_lifetime, MAX_TIMEOUT);
		opt->snatted_lifetime = MAX_TIMEOUT;
	}
	if(opt->dnatted_lifetime > MAX_TIMEOUT)
	{
		printf(VIOLET "Warning: value %lu for dnat timeout too high:\n"
				"setting it to maximum allowed: %lu seconds." NL,
		opt->dnatted_lifetime, MAX_TIMEOUT);
		opt->dnatted_lifetime = MAX_TIMEOUT;
	}
	if(opt->state_lifetime > MAX_TIMEOUT)
	{
		printf(VIOLET "Warning: value %lu for state timeout too high:\n"
				"setting it to maximum allowed: %lu seconds." NL,
		opt->state_lifetime, MAX_TIMEOUT);
		opt->state_lifetime = MAX_TIMEOUT;
	}
	if(opt->loginfo_lifetime > MAX_LOGINFO_TIMEOUT)
	{
		printf(VIOLET "Warning: value %lu for loginfo timeout too high:\n"
				"setting it to maximum allowed: %lu seconds." NL,
		opt->loginfo_lifetime, MAX_LOGINFO_TIMEOUT);
		opt->loginfo_lifetime = MAX_LOGINFO_TIMEOUT;
	}
	if(opt->setup_shutd_state_lifetime > MAX_TIMEOUT)
	{
		printf(VIOLET "Warning: value %lu for state setup/shutdown"
				" timeout too high:\n"
				"setting it to maximum allowed: %lu seconds." NL,
		opt->setup_shutd_state_lifetime, MAX_TIMEOUT);
		opt->setup_shutd_state_lifetime = MAX_TIMEOUT;
	}
}

int get_options(command* opt, struct userspace_opts *uo,
		struct cmdopts* cmdo)
{
  FILE* fpopt;
  /* configuration file names */
  char line[MAXLINELEN];
  short loglevel = 1;
  short loguser = 1;
  if( (fpopt = fopen(uo->options_filename, "r")) == NULL)
    {
      PRED, perror(TR("Error opening options file for reading"));
      PCL;
      return -1;
    }
  while(fgets(line, MAXLINELEN, fpopt) != NULL)
    {
      if(getuid() != 0)
	goto normal_user_options;
		
      if(strncmp(line, "NAT=YES", 7) == 0)
	opt->nat = 1;
      else if(strncmp(line, "MASQUERADE=YES", 14) == 0)
	opt->masquerade = 1;
      else if(strncmp(line, "STATEFUL=YES", 12) == 0)
	opt->stateful = 1;
      /* all permission rules will be stateful, also if a rule does
       * not have state flag specified. */
      else if(strncmp(line, "ALL_STATEFUL=YES", 12) == 0)
	opt->all_stateful = 1;		
      else if(strncmp(line, "USER_ALLOWED=YES" , 16) == 0)
	{
	  cmdo->user_allowed = 1;
	  opt->user_allowed = 1;
	}
      else if(strncmp(line, "NOFLUSH_ON_EXIT=YES", 19) == 0)
	{
	  cmdo->noflush_on_exit = 1;
	  opt->noflush_on_exit = 1;
	}
      else if(strncmp(line, "SNAT_TABLES_LIFETIME=", 21) == 0)
	      opt->snatted_lifetime = (unsigned) get_integer(line);
      else if(strncmp(line, "DNAT_TABLES_LIFETIME=", 21) == 0)
	      opt->dnatted_lifetime = (unsigned) get_integer(line);
      else if(strncmp(line, "STATE_TABLES_LIFETIME=", 22) == 0)
	      opt->state_lifetime = (unsigned) get_integer(line);
      else if(strncmp(line, "STATE_TABLES_SETUP_SHUTD_LIFETIME=", 34) == 0)
	      opt->setup_shutd_state_lifetime = (unsigned) get_integer(line);
      else  if(strncmp(line, "LOGINFO_LIFETIME=", 17) == 0)
	opt->loginfo_lifetime = (unsigned) get_integer(line);
      else  if(strncmp(line, "MAX_LOGINFO_ENTRIES=", 20) == 0)
	      opt->max_loginfo_entries = (unsigned) get_integer(line);
      else  if(strncmp(line, "MAX_NAT_ENTRIES=", 16) == 0)
	      opt->max_nat_entries = (unsigned) get_integer(line);	
      else  if(strncmp(line, "MAX_STATE_ENTRIES=", 17) == 0)
	      opt->max_state_entries = (unsigned) get_integer(line);
      else  if(strncmp(line, "PROC_RMEM_DEFAULT=", 17) == 0)
	      uo->proc_rmem_default = (unsigned) get_integer(line);
      else  if(strncmp(line, "PROC_RMEM_MAX=", 14) == 0)
	      uo->proc_rmem_max = (unsigned) get_integer(line);
      else  if(strncmp(line, "PROC_IPFIRE_POLICY=", 19) == 0)
	      uo->policy = (unsigned) get_integer(line);
      check_max_lifetime_values(opt);
      			
    normal_user_options:
      /* normal user fields */
      if(strncmp(line, "KLOGLEVEL=", 10) == 0)
	loglevel = (short) get_integer(line);
      else if(strncmp(line, "LOGUSER=", 8) == 0)
	loguser = (short) get_integer(line);
      else if(strncmp(line, "DNS_RESOLVE=YES", 15) == 0)
	uo->dns_resolver = 1;
      else if(strncmp(line, "DNS_REFRESH=", 12) == 0)
	uo->dns_refresh = get_integer(line);
      /* configuration file names*/
      else if(strncmp(line, "PERMISSION_FILENAME=", 20) == 0)
			get_string_n(uo->permission_filename, line,  MAXLINELEN);
      else if(strncmp(line, "BLACKLIST_FILENAME=", 19) == 0)
			get_string_n(uo->blacklist_filename, line,  MAXLINELEN);
      else if(strncmp(line, "TRANSLATION_FILENAME=", 21) == 0)
			get_string_n( uo->translation_filename, line, MAXLINELEN);	
      else if(strncmp(line, "BLACKSITES_FILENAME=", 20) == 0)
			get_string_n( uo->blacksites_filename, line, MAXLINELEN);
      else if(strncmp(line, "MAILER_OPTIONS_FILENAME=", 24) == 0)
			get_string_n(uo->mailer_options_filename, line, MAXLINELEN);	  
      else if(strncmp(line, "LOGFILENAME=", 12) == 0)
	    get_string_n(uo->logfile_name, line, MAXLINELEN);
      else if(strncmp(line, "LANGUAGE_FILENAME=", 18) == 0)
	    get_string_n(uo->language_filename, line, MAXLINELEN);
      else if(strncmp(line, "LOGLEVEL=", 9) == 0)
	uo->loglevel = get_integer(line);
      else if(strncmp(line, "RESOLVE_SERVICES=YES", 20) == 0)
	uo->resolv_services = 1;	
    }
  if(fclose(fpopt) < 0)
    perror(RED "Error closing config file" CLR);
  if( (loglevel <0) | (loglevel > 7))
    {
      printf(RED "KLOGLEVEL must be set to 0 ... 7, not %d! Setting to 7." NL, loglevel);
      opt->loglevel = 7;
      cmdo->kloglevel = 7;
    }
  else
    {
      opt->loglevel = loglevel;
      cmdo->kloglevel = loglevel;
    }
  if( (loguser <0) | (loguser > 7))
    {
      printf(RED "LOGUSER must be set to 0 ... 7, not %d! Setting to 7." NL, loguser);
      opt->loguser = 7;
      cmdo->loguser = 7;
    }
  else
    {
      opt->loguser = loguser;
      cmdo->loguser = loguser;
    }
  if( (uo->loglevel < 0) | (uo->loglevel > 7))
    {
      printf(RED "LOGLEVEL must be set to 0 ... 7, not %d! Setting to 7." 
	     NL, uo->loglevel);
      uo->loglevel = 7;
    }
  return 0;
}

int parse_cmdline(struct cmdopts* cmdo, 
		  struct userspace_opts* uo, command* cmd, 
		  int argc, char* argv[],
		  int *different_ruleset_by_cmd)
{
  int i = 1;
  uid_t user;
	
  while( i < argc)
    {
      if( (!strcmp(argv[i], "-noflush")) ||
	  (!strcmp(argv[i], "/noflush")))
	 {
	  if((user = getuid()) == 0)
	    {
	      cmdo->noflush_on_exit = 1;
	      cmd->noflush_on_exit = 1;
	    }
	  else
	    PVIO, printf(TR("Option \"%s\": warning: you are user %d."), argv[i], user),
	       PNL,
		   printf(TR("You must be root to let rules active in firewall")), PNL,
		   printf(TR("after turning off userspace interface!")), PNL; 
	 }
      /* read /etc/services and resolv ports into names */
      else if( (!strcmp(argv[i], "-services")) || 
	       (!strcmp(argv[i], "/services")))
		uo->resolv_services = 1;
	  else if( (!strcmp(argv[i], "-mailer")) || 
	       (!strcmp(argv[i], "/mailer")))
		{
			if(i+2 >= argc)
	    	{
	     		 PRED, printf(TR("Parameter \"%s\" must be followed by an integer"), argv[i]);
		   		 printf(TR("and an indicator among sec, min, hour, days"));
				 PNL;
	    		  return -1;
	    	}
	  		uo->mail = 1;
			if(strncmp(argv[i+2], "sec", 3) == 0)
				uo->mail_time = atoi(argv[i+1]);
			else if(strncmp(argv[i+2], "min", 3) == 0)
	  			uo->mail_time = atoi(argv[i+1]) * 60;
			else if(strncmp(argv[i+2], "hour", 4) == 0)
	  			uo->mail_time = atoi(argv[i+1]) * 60 * 60;
			else if(strncmp(argv[i+2], "days", 4) == 0)
	  			uo->mail_time = atoi(argv[i+1]) * 60 * 60 * 24;			
	  		i = i + 2;
		}
      else if( (!strcmp(argv[i], "-noservices")) ||
	       (!strcmp(argv[i], "/noservices")))
		uo->resolv_services = 0;
		
      else if( (!strcmp(argv[i], "-kloglevel")) ||
	       (! strcmp (argv[i], "/kloglevel")))
	{
	  if(i+1 >= argc)
	    {
	      PRED, printf(TR("Parameter \"%s\" must be followed by an integer from 0 to 7"), argv[i]);
			PNL;
	      return -1;
	    }
	  cmdo->kloglevel = atoi(argv[i+1]);
	  cmd->loglevel = cmdo->kloglevel;
	  i = i + 1;
	}		
      else if( (!strcmp(argv[i], "-loguser")) ||
	       (! strcmp (argv[i], "/loguser")))
	{
	  if(i+1 >= argc)
	    {
	      printf(TR("Parameter \"%s\" must be followed by an integer from 0 to 7"), argv[i]);
			PNL;
	      return -1;
	    }
	  if(getuid() == 0)
	    {
	      cmdo->loguser = atoi(argv[i+1]);
	      cmd->loguser = cmdo->loguser;
	    }
	  else
	    PNL, PRED, printf(TR("Only root can modify user log level!" )), PNL;
			
	  i = i + 1;
	}
		
      else if( (!strcmp(argv[i], "-dns")) ||
	       (! strcmp (argv[i], "/dns")))
	{
	  if(i+1 >= argc)
	    {
	      PRED;
          printf(TR("Parameter \"%s\" must be followed by an integer indicating,"), 
			argv[i]);
		  PNL; printf(TR("in seconds, the refresh time.")); PNL;
	      return -1;
	    }
	  uo->dns_resolver = 1;
	  uo->dns_refresh = atoi(argv[i+1]);
			
	  i = i + 1;
	}
      else if( (!strcmp(argv[i], "-nodns")) ||
	       (! strcmp (argv[i], "/nodns")))
	uo->dns_resolver = 0;
		
      else if( (!strcmp(argv[i], "-log")) ||
	       (! strcmp (argv[i], "/log")))
	{
	  if(i+1 >= argc)
	    {
	      printf(TR("Parameter \"%s\" must be followed by an integer from 0 to 7"), argv[i]);
			PNL;
	      return -1;
	    }
	  uo->loglevel = atoi(argv[i+1]);
	  i = i + 1;
	}
      else if( (!strcmp(argv[i], "-logfile")) ||
	       (! strcmp (argv[i], "/logfile")))
	{
	  if(i+1 >= argc)
	    {
	      PRED, printf(TR("Parameter \"%s\" must be followed by a file name:"), argv[i]);
		  PNL; printf(TR("e.g.: \"/var/log/ipfire.log\"")); PNL;
	      return -1;
	    }
	  if(getuid() == 0)
	    {
	      strncpy(uo->logfile_name, argv[i+1], MAXFILENAMELEN);
	      *different_ruleset_by_cmd = 1;
	    }
	  else
	    PNL, PRED, printf(TR("Only root can modify log file name!")), PNL;
			
	  i = i + 1;
	}
      else if( (!strcmp(argv[i], "-allowed")) ||
	       (! strcmp (argv[i], "/allowed")))
	{
	  if(i+1 >= argc)
	    {
	      PRED, printf(TR("Parameter \"%s\" must be followed by a file name:"), argv[i]);
		  printf(TR("e.g.: \"/home/user/allowed\"" )), PNL;
	      return -1;
	    }
	  strncpy(uo->permission_filename, argv[i+1], MAXFILENAMELEN);
	  *different_ruleset_by_cmd = 1;
	  i = i + 1;
	}
      else if( (!strcmp(argv[i], "-blacklist")) ||
	       (! strcmp (argv[i], "/blacklist")))
	{
	  if(i+1 >= argc)
	    {
	      PRED, printf(TR("Parameter \"%s\" must be followed by a file name:"), argv[i]);
		  printf(TR("e.g.: \"/home/user/blacklist\"" )), PNL;
	      return -1;
	    }
	  strncpy(uo->blacklist_filename, argv[i+1], MAXFILENAMELEN);
	  *different_ruleset_by_cmd = 1;
	  i = i + 1;
	}
      else if( (!strcmp(argv[i], "-blacksites")) ||
	       (! strcmp (argv[i], "/blacksites")))
	{
	  if(i+1 >= argc)
	    {
	      PRED, printf(TR("Parameter \"%s\" must be followed by a file name:"), argv[i]);
		  printf(TR("e.g.: \"/home/user/blacksites\"" )), PNL;
	      return -1;
	    }
	  strncpy(uo->blacksites_filename, argv[i+1], MAXFILENAMELEN);
	  i = i + 1;
	}
      else if( (!strcmp(argv[i], "-translation")) ||
	       (! strcmp (argv[i], "/translation")))
	{
	  if(i+1 >= argc)
	    {
	      PRED, printf(TR("Parameter \"%s\" must be followed by a file name:"), argv[i]);
		  printf(TR("e.g.: \"/home/user/translation_bis\"" )), PNL;
	      return -1;
	    }
	  strncpy(uo->translation_filename, argv[i+1], MAXFILENAMELEN);
	  *different_ruleset_by_cmd = 1;
	  i = i + 1;
	}
      else if( (!strcmp(argv[i], "-lang")) ||
	       (! strcmp (argv[i], "/lang")))
	{
	  if(i+1 >= argc)
	    {
	      PRED, printf(TR("Parameter \"%s\" must be followed by a string containing a filename with translated strings, positioned in the .IPFIRE/languages directory of the home user.")
		      , argv[i]);
		  PNL;
	      return -1;
	    }
	  strncpy(uo->language_filename, argv[i+1], MAXFILENAMELEN);
	  i = i + 1;
	}	
      else if(( !strcmp(argv[i], "-clearlog")) ||
	      (! strcmp(argv[i], "/clearlog")))
	{
	  if(getuid() == 0)
	    uo->clearlog = 1;
	  else
	    PNL, PRED, printf(TR("You must be root to clear logfile!")), PNL, PNL;
	}
      else if(( !strcmp(argv[i], "-allstate")) ||
	      (! strcmp(argv[i], "/allstate")))
	{
	  if(getuid() == 0)
	    {
	      cmd->stateful = 1;
	      cmd->all_stateful = 1;
	    }
	  else
	    PNL, PRED, printf(TR("You must be root to set all stateful option!" )), PNL, PNL;
	}
      else if( (!strcmp(argv[i], "-quiet")) ||
	       (! strcmp(argv[i], "/quiet")))
	cmdo->quiet = 1;
		
      else if( (!strcmp(argv[i], "-user")) ||
	       (! strcmp(argv[i], "/user")))
	{
	  if( (user = getuid()) == 0)
	    {
	      cmdo->user_allowed = 1;
	      cmd->user_allowed = 1;
	    }
	  else
	    PVIO, printf(TR("Option \"%s\": warning: you are user %d."),argv[i], user),
		printf(TR("You must be root to set this privilege.")), PNL;
	}
      /* run as daemon? */
      else if( (!strcmp(argv[i], "-daemon")) ||
	       (! strcmp(argv[i], "/daemon")) ||
	       (! strcmp(argv[i], "daemon")))
	cmdo->daemonize = 1;
      else if( (!strcmp(argv[i], "-quiet_daemon")) ||
	       (! strcmp(argv[i], "/quiet_daemon")) ||
	       (! strcmp(argv[i], "quiet_daemon")))
	cmdo->quiet_daemonize = 1;
			
      else if( (!strcmp(argv[i], "-nouser")) ||
	       (! strcmp(argv[i], "/nouser")))
	{
	  if( (user = getuid()) == 0)
	    {
	      cmdo->user_allowed = 0;
	      cmd->user_allowed = 0;
	    }
	  else
	    PVIO, printf(TR("Option \"%s\": warning: you are user %d."),argv[i], user),
		printf(TR("You must be root to set this privilege.")), PNL;
	}
		
      /* load rules in firewall and then exit */
      else if( (!strcmp(argv[i], "-load")) ||
	       (! strcmp(argv[i], "/load")) ||
	       (! strcmp(argv[i], "load")))
	{
	  if( (user = getuid()) == 0)
	    {
	      uo->justload = 1;
	      cmdo->noflush_on_exit = 1;
	      cmd->noflush_on_exit = 1;
	    }
	  else
	    PVIO, printf(TR("Option \"%s\": warning: you are user %d."),argv[i], user),
		printf(TR("You must be root to set \"justload\".")), PNL;
	}
      /* used to cause little printing, when started by rc script.
       * Implies "-load" */
      else if( (!strcmp(argv[i], "-rc")) ||
	       (! strcmp(argv[i], "/rc")) ||
	       (! strcmp(argv[i], "rc")))
	{
	  if( (user = getuid()) == 0)
	    {
	      uo->justload = 1;
	      uo->rc = 1;
	      cmdo->noflush_on_exit = 1;
	      cmd->noflush_on_exit = 1;
	    }
	  else
	    PVIO, printf(TR("Option \"%s\": warning: you are user %d."),argv[i], user),
		printf(TR("You must be root to set \"justload\" or \"rc\" options.")), PNL;

	}
      else if( (!strcmp(argv[i], "-flush")) ||
	       (! strcmp(argv[i], "/flush")) ||
	       (! strcmp(argv[i], "flush")))
	{
	  if( (user = getuid()) == 0)
	    {
	      uo->flush = 1;
	      cmdo->noflush_on_exit = 0;
	      cmd->noflush_on_exit = 0;
	    }
	  else
	    PVIO, printf(TR("Option \"%s\": warning: you are user %d."),argv[i], user),
		printf(TR("You must be root to load rules and exit.")), PNL;
	}
      else if( (!strcmp(argv[i], "-rmmod")) ||
	       (! strcmp(argv[i], "/rmmod")) ||
	       (! strcmp(argv[i], "rmmod")))
	{
	  if( (user = getuid()) == 0)
	    {
	      uo->rmmod = 1;
	    }
	  else
	    PVIO, printf(TR("Option \"%s\": warning: you are user %d."),argv[i], user),
		printf(TR("You must be root to unload module at exit.")), PNL;
	}
				
      else
		PVIO, printf(TR("Ignoring unknown option %s."),
	       argv[i]), PNL;
		
      i++;
    }
  return 0;
}


/* sends a command to kernel space. After this is done, memory 
 * dynamically allocated is freed. int type_of_message can be
 * one among COMMAND (to allocate space for a command 
 * structure) or LISTENER_DATA (to allocate space for a listener_message
 * data structure)
 *
 */
int send_to_kernel( void* mess, const struct netl_handle* handle,
		    int type_of_message)
{
  size_t len = 0;
  void *p;
  struct nlmsghdr* messhead = NULL;
  command cmdack;
		
  if(type_of_message == CONTROL_DATA)
    len = sizeof(command);
  else if(type_of_message == LISTENER_DATA)
    len = sizeof(listener_message);
  /* payload should be 40 bytes, nlmsg_len 52 */
  if( (messhead = alloc_and_fill_nlheader(len)) == NULL)
    libnetl_perror("send_to_kernel()");
	
  p = fill_payload(messhead, mess, len); /* memcpy does not return error codes */
  
  if(!p)
  {
    printf("send_to_kernel(): cannot send message for problems in sizes\n");
    return -1;
  }
	
  if(send_to_kern(handle,  (void*) messhead, messhead->nlmsg_len ) < 0)
    {
      libnetl_perror(RED "main()" CLR);
      printf("Freeing message memory.\n");
      netl_free_nlmess(messhead);
      return -1;
    }
  /* if the message is a command, we must wait for an acknowledgement,
   * sent by the kernel to verify we are active and listening at the correct
   * pid. */
  if (type_of_message == CONTROL_DATA) /*&& 
      ( ((command*) mess)->cmd != HELLO ) &&
      ( ((command*) mess)->cmd != SIMPLE_GOODBYE ))*/
    {
      
  	if(read_from_kern(handle, (unsigned char *) &cmdack, sizeof(command)) < 0)
    	{
     		 printf(TR("send_to_kernel(): error receiving ack from kernel!"));
		 netl_free_nlmess(messhead);
	  	return -1;
    	}
  	if(cmdack.cmd == ACKNOWLEDGEMENT)
    	{
		netl_free_nlmess(messhead);
      		return 1;
    	}
  	else
    	{
		PRED, printf(TR("Bad ACKNOWLEDGEMENT value (%d) (Should be 50)!"),
	      		cmdack.cmd);
		netl_free_nlmess(messhead);
      		return -1;
    	}
	
    }
  /* once sent, message space can be freed */
  netl_free_nlmess(messhead);
  return 0;
}

/* constructs hello command filling in sizes of data
 * structures */
int build_hello_command(command* cmdh, char* argv0 )
{
  cmdh->cmd = HELLO;
  memset(&cmdh->content.fwsizes, 0, 
	 sizeof(struct firesizes));
  cmdh->content.fwsizes.infosize = sizeof(ipfire_info_t);
  cmdh->content.fwsizes.rulesize = sizeof(ipfire_rule);
  cmdh->content.fwsizes.cmdsize = sizeof(command);
  cmdh->content.fwsizes.uid = getuid();
  strncpy(cmdh->content.fwsizes.uspace_firename, argv0, TASK_COMM_LEN);
  /* no matter if argv0 is longer than TASK_COMM_LEN (16), we
   * terminate correctly the string we are going to pass to 
   * kernel space inside the hello command 
   */
  cmdh->content.fwsizes.uspace_firename[TASK_COMM_LEN - 1] = '\0';
  return 0;
}

int build_option_command(command* cmd)
{
  cmd->cmd = OPTIONS;
  cmd->options=1;
  /* there is no rule in an option command: create a dummy rule */
  memset(&cmd->content.rule, 0, sizeof(cmd->content.rule));  
  return 0;	
}

int build_rule_command(command *cmd)
{
  cmd->is_rule = 1;
  cmd->cmd = ADDRULE;
  return 0;
}

unsigned long lrcv = 0;
unsigned count = 0;
/* function that checks if some packets have been lost
 * during receiving on netlink socket. */
int check_stats(struct netlink_stats* ns, const ipfire_info_t* msg)
{
  /* update total sum */
  ns->difference = 0;
  ns->lost = 0;
  ns->direction_now = msg->direction;
  count ++;
	
  switch(msg->direction)
    {
    case IPFI_INPUT:
      /* if firewall is already up counters mismatch.
       * This does not affect lost packets counter: it is
       * reset every time userspace exits */
      if( (ns->in_rcv == 0) && (msg->packet_id > 0))
	ns->in_rcv = msg->packet_id-1;
      /* lost packets */
      ns->difference = msg->packet_id - ns->in_rcv;
      ns->in_rcv += ns->difference;
      ns->lost = msg->logu_id - ns->last_in_rcv;
      ns->last_in_rcv = msg->logu_id +1;
      break;
			
    case IPFI_OUTPUT:
      if( (ns->out_rcv == 0) && (msg->packet_id > 0))
	ns->out_rcv = msg->packet_id-1;
      ns->difference = msg->packet_id - ns->out_rcv;
      ns->out_rcv += ns->difference;
      ns->lost = msg->logu_id - ns->last_out_rcv;
      ns->last_out_rcv = msg->logu_id +1;
      break;
			
    case IPFI_INPUT_PRE:
      if( (ns->pre_rcv == 0) && (msg->packet_id > 0))
	ns->pre_rcv = msg->packet_id-1;
      ns->difference = msg->packet_id - ns->pre_rcv;
      ns->pre_rcv += ns->difference;
      ns->lost = msg->logu_id - ns->last_pre_rcv;
      ns->last_pre_rcv = msg->logu_id +1;
      break;
			
    case IPFI_OUTPUT_POST:
      if( (ns->post_rcv == 0) && (msg->packet_id > 0))
	ns->post_rcv = msg->packet_id-1;
      ns->difference = msg->packet_id - ns->post_rcv;
      ns->post_rcv += ns->difference;
      ns->lost = msg->logu_id - ns->last_post_rcv;
      ns->last_post_rcv = msg->logu_id +1;
      break;
			
    case IPFI_FWD:
      if( (ns->fwd_rcv == 0) && (msg->packet_id > 0))
	ns->fwd_rcv = msg->packet_id-1;
      ns->difference = msg->packet_id - ns->fwd_rcv;
      ns->fwd_rcv += ns->difference;
      ns->lost = msg->logu_id - ns->last_fwd_rcv;
      ns->last_fwd_rcv = msg->logu_id +1;
      break;	
    }
	
  /* lost packets */
	
  /* total of lost packets */
  ns->total_lost += ns->lost;
  /* update total packets _received_ by _kernel_ */
  ns->sum_now += ns->difference;
	
  /* packets which are not sent by kernel, nor lost */
  ns->not_sent_nor_lost += 
    ns->difference - 1 - ns->lost;
  /* lost packets, recalculate percentage */
  if(( ns->lost > 0) && (ns->sum_now != 0))
    ns->percentage = (float) 
      ( ( ( (float) ns->total_lost / (float) ns->sum_now)) * 100);

  return ns->lost;
}

/* prints information about packets lost */
int print_lostpack_info(const struct  netlink_stats* nls)
{
  PVIO, printf(TR("WARNING: lost some packets:")), PNL;
  switch(nls->direction_now)
    {
    case IPFI_INPUT:
      printf(DGREEN), printf(TR("INPUT: ")), PCL;
      break;
    case IPFI_OUTPUT:
      PBLU, printf(TR("OUTPUT: ")), PCL;
      break;
    case IPFI_INPUT_PRE:
      printf(MAROON "PRE: "CLR );
      break;
    case IPFI_OUTPUT_POST:
      printf(MAROON "POST: "CLR );
      break;
    case IPFI_FWD:
      PYEL, printf(TR("FWD: ")), PCL;
      break;
    }
  printf(TR("LOST %lu PACKETS FROM KERNEL. TOTAL UNTIL NOW: %lu/%lu [%.5f %%]" ),
	 nls->difference, nls->total_lost, nls->sum_now, (float)nls->percentage), PNL;
  return 0;	
}

/* save_rules() sends file pointer and a rule
 * to be written on file */
int write_rule(FILE* fp, const ipfire_rule arule, int index)
{
  int i;
	char address[INET_ADDRSTRLEN];

	if(arule.nflags.policy == BLACKSITE)
	{
		fprintf(fp, "BSRULE\n");
	}
	else
	{
		fprintf(fp, "RULE\n");
	}
	
#ifdef ENABLE_RULENAME
	/* COMMENT */
	if(strlen(arule.rulename) > 0)
		fprintf(fp, "NAME=%s\n", arule.rulename);
#endif
	
// 	fprintf(fp, "POSITION=%d\n", index+1);
	
	/* DIRECTION */
	if(arule.direction == IPFI_INPUT)
		fprintf(fp, "DIRECTION=INPUT\n");
	else if(arule.direction == IPFI_OUTPUT)
		fprintf(fp, "DIRECTION=OUTPUT\n");
	else if(arule.direction == IPFI_FWD)
		fprintf(fp, "DIRECTION=FORWARD\n");
	else if(arule.direction == IPFI_OUTPUT_POST)
		fprintf(fp, "DIRECTION=POST\n");
	else if(arule.direction == IPFI_INPUT_PRE)
		fprintf(fp, "DIRECTION=PRE\n");
	
	if( (arule.direction == NODIRECTION)  && (
	     (arule.nat) | (arule.masquerade)))
		PNL, PNL, PRED, 
  printf(TR("ERROR: MASQUERADE/NAT RULE AND NO DIRECTION SPECIFIED! [RULE%d]"), index+1), PNL, PNL;
  
	
  /* NETWORK DEVICE */
  if(arule.nflags.indev)
	  fprintf(fp, "INDEVICE=%s\n",arule.devpar.in_devname);
  if(arule.nflags.outdev)
	  fprintf(fp, "OUTDEVICE=%s\n",arule.devpar.out_devname);
	
  /* SOURCE ADDRESSES */
   /* multiple source addresses */
   if( (arule.nflags.src_addr == ONEADDR) && (arule.parmean.samean == MULTI))
   {
     /* first address, in [0] */
       fprintf(fp, "SRCADDR=%s\n", inet_ntop(
		  AF_INET, (struct in_addr*) &arule.ip.ipsrc[0], address, INET_ADDRSTRLEN));
       /* other addresses */  
       for(i = 1; i < MAXMULTILEN && arule.ip.ipsrc[i] != 0; i++)

	  fprintf(fp, "SRCADDR%d=%s\n", i+1, inet_ntop(AF_INET, (struct in_addr*) &arule.ip.ipsrc[i], address, INET_ADDRSTRLEN));
   }
   /* multiple source addresses, but different from */
   else if( (arule.nflags.src_addr == ONEADDR) && (arule.parmean.samean == MULTI_DIFFERENT))
   {
     /* first address, in [0] */
       fprintf(fp, "SRCADDR_NOT=%s\n", inet_ntop(
		  AF_INET, (struct in_addr*) &arule.ip.ipsrc[0], address, INET_ADDRSTRLEN));
       /* other addresses */  
       for(i = 1; i < MAXMULTILEN && arule.ip.ipsrc[i] != 0; i++)
	  fprintf(fp, "SRCADDR%d_NOT=%s\n", i+1, inet_ntop(
		  AF_INET, (struct in_addr*) &arule.ip.ipsrc[i], address, INET_ADDRSTRLEN));
   }
  else if( (arule.nflags.src_addr == ONEADDR) && (arule.parmean.samean != DIFFERENT_FROM))
	  fprintf(fp, "SRCADDR=%s\n", inet_ntop(AF_INET, (struct in_addr*) &arule.ip.ipsrc[0], address, INET_ADDRSTRLEN));
  else if( (arule.nflags.src_addr == ONEADDR) && (arule.parmean.samean == DIFFERENT_FROM))
	  fprintf(fp, "SRCADDR_NOT=%s\n", inet_ntop(
		  AF_INET, &arule.ip.ipsrc[0], address, INET_ADDRSTRLEN));
  else if( (arule.nflags.src_addr == MYADDR) &&  (arule.parmean.samean == SINGLE))
	  fprintf(fp, "MYSRCADDR\n");
	
  else if( (arule.nflags.src_addr == MYADDR) && (arule.parmean.samean == DIFFERENT_FROM))
	  fprintf(fp, "MYSRCADDR_NOT\n");
	
  if( (arule.nflags.src_addr == ONEADDR) && (arule.parmean.samean == INTERVAL))
	  fprintf(fp, "_END_SRCADDR=%s\n", inet_ntop(
		  AF_INET, (struct in_addr*) &arule.ip.ipsrc[1], address, INET_ADDRSTRLEN));
					
  if( (arule.nflags.src_addr == ONEADDR) && (arule.parmean.samean == INTERVAL_DIFFERENT_FROM))
	  fprintf(fp, "_END_SRCADDR_NOT=%s\n", inet_ntop(
		  AF_INET, (struct in_addr*) &arule.ip.ipsrc[1], address, INET_ADDRSTRLEN));
					
	
  /* DESTINATION ADDRESSES */
   /* multiple destination addresses */
   if( (arule.nflags.dst_addr == ONEADDR) && (arule.parmean.damean == MULTI)) /* start with multi */
   {
     /* first address, in [0] */
       fprintf(fp, "DSTADDR=%s\n", inet_ntop(AF_INET, (struct in_addr*) &arule.ip.ipdst[0], address, INET_ADDRSTRLEN));
       /* other addresses */  
       for(i = 1; i < MAXMULTILEN && arule.ip.ipdst[i] != 0; i++)
	  fprintf(fp, "DSTADDR%d=%s\n", i+1, inet_ntop(AF_INET, (struct in_addr*) &arule.ip.ipdst[i], address, INET_ADDRSTRLEN));
   }
   /* multiple destination addresses, but different from */
   else if( (arule.nflags.dst_addr == ONEADDR) && (arule.parmean.damean == MULTI_DIFFERENT))
   {
     /* first address, in [0] */
       fprintf(fp, "DSTADDR_NOT=%s\n", inet_ntop(AF_INET, (struct in_addr*) &arule.ip.ipdst[0], address, INET_ADDRSTRLEN));
       /* other addresses */  
       for(i = 1; i < MAXMULTILEN && arule.ip.ipdst[i] != 0; i++)
	  fprintf(fp, "DSTADDR%d_NOT=%s\n", i+1, inet_ntop(AF_INET, (struct in_addr*) &arule.ip.ipdst[i], address, INET_ADDRSTRLEN));
   }
  else if( (arule.nflags.dst_addr == ONEADDR) && (arule.parmean.damean != DIFFERENT_FROM))
	  fprintf(fp, "DSTADDR=%s\n", inet_ntop(AF_INET, &arule.ip.ipdst[0], address, INET_ADDRSTRLEN));
  else if( (arule.nflags.dst_addr == ONEADDR) && (arule.parmean.damean == DIFFERENT_FROM))
	  fprintf(fp, "DSTADDR_NOT=%s\n", inet_ntop(AF_INET, &arule.ip.ipdst[0], address, INET_ADDRSTRLEN));
	
  else if( (arule.nflags.dst_addr == MYADDR) && (arule.parmean.damean == SINGLE))
	  fprintf(fp, "MYDSTADDR\n");
	
  else if( (arule.nflags.dst_addr == MYADDR) && (arule.parmean.damean == DIFFERENT_FROM))
	  fprintf(fp, "MYDSTADDR_NOT\n");
	
  if( (arule.nflags.dst_addr == ONEADDR) && (arule.parmean.damean == INTERVAL))
	  fprintf(fp, "_END_DSTADDR=%s\n", inet_ntop(AF_INET, &arule.ip.ipdst[1], address, INET_ADDRSTRLEN));
  if( (arule.nflags.dst_addr == ONEADDR) && (arule.parmean.damean == INTERVAL_DIFFERENT_FROM))
	  fprintf(fp, "_END_DSTADDR_NOT=%s\n", inet_ntop(AF_INET, &arule.ip.ipdst[1], address, INET_ADDRSTRLEN));
	
  /* PROTOCOL, TOTAL_LENGTH, TOS */
  if(arule.nflags.proto)
	  fprintf(fp, "PROTOCOL=%d\n", arule.ip.protocol);
  if(arule.nflags.tot_len)
	  fprintf(fp, "TOTAL_LENGTH=%d\n", arule.ip.total_length);
  if(arule.nflags.tos)
	  fprintf(fp, "TOS=%d\n", arule.ip.tos);

  /* TRANSPORT: SOURCE AND DESTINATION PORTS */	
  if((arule.nflags.src_port) && (arule.parmean.spmean == MULTI))
  {
    fprintf(fp, "SRCPORT=%d\n", ntohs(arule.tp.sport[0]));
    for(i = 1; i < MAXMULTILEN && arule.tp.sport[i] != 0; i++)
      fprintf(fp, "SRCPORT%d=%d\n", i+1, ntohs(arule.tp.sport[i]));
  }
  else if((arule.nflags.src_port) && (arule.parmean.spmean == MULTI_DIFFERENT))
  {
    fprintf(fp, "SRCPORT_NOT=%d\n", ntohs(arule.tp.sport[0]));
    for(i = 1; i < MAXMULTILEN && arule.tp.sport[i] != 0; i++)
      fprintf(fp, "SRCPORT%d_NOT=%d\n", i+1, ntohs(arule.tp.sport[i]));
  }
  else if( (arule.nflags.src_port) && (arule.parmean.spmean != DIFFERENT_FROM))
	  fprintf(fp, "SRCPORT=%d\n", ntohs(arule.tp.sport[0]));
  else if((arule.nflags.src_port) && (arule.parmean.spmean == DIFFERENT_FROM))
	  fprintf(fp, "SRCPORT_NOT=%d\n", ntohs(arule.tp.sport[0]));
  if( (arule.nflags.src_port) && (arule.parmean.spmean == INTERVAL))
	  fprintf(fp, "_END_SRCPORT=%d\n", ntohs(arule.tp.sport[1]));
	
  /* DESTINATION PORTS */
  if((arule.nflags.dst_port) && (arule.parmean.dpmean == MULTI))
  {
    fprintf(fp, "DSTPORT=%d\n", ntohs(arule.tp.dport[0]));
    for(i = 1; i < MAXMULTILEN && arule.tp.dport[i] != 0; i++)
      fprintf(fp, "DSTPORT%d=%d\n", i+1, ntohs(arule.tp.dport[i]));
  }
  else if((arule.nflags.dst_port) && (arule.parmean.dpmean == MULTI_DIFFERENT))
  {
    fprintf(fp, "DSTPORT_NOT=%d\n", ntohs(arule.tp.dport[0]));
    for(i = 1; i < MAXMULTILEN && arule.tp.dport[i] != 0; i++)
      fprintf(fp, "DSTPORT%d_NOT=%d\n", i+1, ntohs(arule.tp.dport[i]));
  }	
  if( (arule.nflags.dst_port) && (arule.parmean.dpmean != DIFFERENT_FROM))
	  fprintf(fp, "DSTPORT=%d\n", ntohs(arule.tp.dport[0]));
  else if( (arule.nflags.dst_port) && (arule.parmean.dpmean == DIFFERENT_FROM))
	  fprintf(fp, "DSTPORT_NOT=%d\n", ntohs(arule.tp.dport[0]));
	
  if( (arule.nflags.dst_port) && (arule.parmean.dpmean == INTERVAL))
	  fprintf(fp, "_END_DSTPORT=%d\n", ntohs(arule.tp.dport[1]));
	
  /* TCP FLAGS */
  /* SYN */
  if( (arule.nflags.syn) && (arule.tp.syn))
	  fprintf(fp, "SYN=TRUE\n");
  else if( (arule.nflags.syn) && (!arule.tp.syn))
	  fprintf(fp, "SYN=FALSE\n");
  
  /* FIN */
  if( (arule.nflags.fin) && (arule.tp.fin))
	  fprintf(fp, "FIN=TRUE\n");
  else if( (arule.nflags.fin) && (!arule.tp.fin))
	  fprintf(fp, "FIN=FALSE\n");

  /* PSH */
  if( (arule.nflags.psh) && (arule.tp.psh))
	  fprintf(fp, "PSH=TRUE\n");
  else if( (arule.nflags.psh) && (!arule.tp.psh))
	  fprintf(fp, "PSH=FALSE\n");

  /* ACK */
  if( (arule.nflags.ack) && (arule.tp.ack))
	  fprintf(fp, "ACK=TRUE\n");
  else if( (arule.nflags.ack) && (!arule.tp.ack))
	  fprintf(fp, "ACK=FALSE\n");

  /* Reset */
  if( (arule.nflags.rst) && (arule.tp.rst))
	  fprintf(fp, "RST=TRUE\n");
  else if( (arule.nflags.rst) && (!arule.tp.rst))
	  fprintf(fp, "RST=FALSE\n");

  /* URG */
  if( (arule.nflags.urg) && (arule.tp.urg))
	  fprintf(fp, "URG=TRUE\n");
  else if( (arule.nflags.urg) && (!arule.tp.urg))
	  fprintf(fp, "URG=FALSE\n");

	
  /* ICMP RELATED */
  if(arule.nflags.icmp_type)
	  fprintf(fp, "ICMP_TYPE=%d\n", arule.icmp_p.type);
  if(arule.nflags.icmp_code)
	  fprintf(fp, "ICMP_CODE=%d\n", arule.icmp_p.code);
  if(arule.nflags.icmp_echo_id)
	  fprintf(fp, "ICMP_ECHO_ID=%d\n", arule.icmp_p.echo_id);
  if(arule.nflags.icmp_echo_seq)
	  fprintf(fp, "ICMP_ECHO_SEQ=%d\n", arule.icmp_p.echo_seq);
  /* frag mtu removed */
	
  /* STATEFUL TRACKING */
  if(arule.state)
	  fprintf(fp, "KEEP_STATE=YES\n");
  if(arule.notify)
	  fprintf(fp, "NOTIFY=YES\n");
  if(arule.natural)
     fprintf(fp, "NATURAL_LANGUAGE=YES\n");
  /* NAT / MASQUERADE */
  if(arule.nat)
	  fprintf(fp, "NAT=YES\n");
  if(arule.snat)
	  fprintf(fp, "SNAT=YES\n");
  if( (arule.masquerade) && (!arule.nat))
	  fprintf(fp, "MASQUERADE=YES\n");
  if(arule.nflags.ftp)
	  fprintf(fp, "FTP_SUPPORT=YES\n");
	
  if(arule.nat)
  {
	  if(arule.nflags.newaddr)
		  fprintf(fp, "NEWADDR=%s\n", inet_ntop(
			  AF_INET, &arule.newaddr, address, INET_ADDRSTRLEN));
	  if(arule.nflags.newport)
		  fprintf(fp, "NEWPORT=%d\n", ntohs(arule.newport));
  }
  /*
   * packet mangling options 
   */
  if(arule.pkmangle.mss.enabled)
  {
    switch(arule.pkmangle.mss.option)
    {
      case MSS_VALUE:
	fprintf(fp, "MSS_VALUE=%d\n", arule.pkmangle.mss.mss);
	break;
      case ADJUST_MSS_TO_PMTU:
	fprintf(fp, "MSS_VALUE=TO_PMTU\n");
	break;
    }
  }
	
  return 1;
}

/* writes headers in configuration files, i.e. comments
 * to those files for a user who wants to explore them */
void write_header(FILE* fp, int whichfile)
{
	if(whichfile == ACCEPT)
	{
		fprintf(fp, "# IPFIRE PERMISSION RULES\n");
		fprintf(fp, 
			"# DENIAL RULES ARE READ BY FIREWALL FIRST.\n"
					"# AFTER THESE, PERMISSION RULES ARE VISITED\n"
					"# TO SEE IF THERE IS A MATCH. FIRST MATCH CAUSES\n"
					"# FILTERING FUNCTION TO RETURN.\n"
					"# REMEMBER THAT PACKETS WHICH DO NOT MATCH\n"
					"# WITH ANY RULE ARE IMPLICITLY DROPPED.\n");
	}
	else if(whichfile == DENIAL)
	{
		fprintf(fp, "# IPFIRE DENIAL RULES\n");
		fprintf(fp, 
			"# DENIAL RULES ARE READ BY FIREWALL FIRST.\n"
					"# AFTER THESE, PERMISSION RULES ARE VISITED\n"
					"# TO SEE IF THERE IS A MATCH. FIRST MATCH CAUSES\n"
					"# FILTERING FUNCTION TO RETURN.\n"
					"# REMEMBER THAT PACKETS WHICH DO NOT MATCH\n"
					"# WITH ANY RULE ARE IMPLICITLY DROPPED.\n");
	}
	else if(whichfile == TRANSLATION)
	{
		fprintf(fp, "# IPFIRE TRANSLATION RULES\n");
		fprintf(fp,
			"# HERE SOURCE AND DESTINATION NAT RULES\n"
					"# ARE STORED. ALSO MASQUERADE INSTRUCTIONS\n"
					"# ARE GIVEN IN THIS FILE.\n"
					"# AT THIS LEVEL NO FILTERING IS DONE.\n"
					"# SOURCE NAT CAN BE DONE IN POST ROUTING PHASE.\n"
					"# DESTINATION NAT CAN BE DONE IN PRE ROUTING OR\n"
					"# OUTPUT PHASES.\n#\n"
					"# ONLY ROOT CAN ADD OR DELETE TRANSLATION RULES.\n"
					"#\n");			
	}
	
#ifndef ENABLE_RULENAME
	fprintf(fp,
		"#\n"
				"# WARNING: RULE NAMES HAVE BEEN DISABLED AT\n"
				"# COMPILATION TIME. THIS SUBTRACTS 20 BYTES TO\n"
				"# DATA STRUCTURES USED FOR KERNEL / USER\n"
				"# COMMUNICATION, AND MAKES LIGHTER KERNELSPACE\n"
				"# FIREWALL PROCESSING. IF YOU HAVE A POWERFUL\n"
				"# MACHINE AND NOT MUCH NETWORK TRAFFIC, YOU CAN\n"
				"# ENABLE THIS FUNCTION REBUILDING _BOTH_ USERSPACE\n"
				"# AND KERNELSPACE STUFF WITH THE FLAG\n"
				"# \"-DENABLE_RULENAME\". THEN YOU CAN GIVE A NAME TO\n"
				"# YOUR RULES AND SEE IT IN LOGS AND CONSOLE.\n"
				"#\n");
#endif
	
	fprintf(fp,
		"# THIS FILE IS WRITTEN BY IPFIRE-wall PROGRAM.\n"
				"# DO NOT EDIT BY HAND UNLESS YOU ARE VERY SURE!\n"
				"# HAVE FUN :)\n"
				"# GIACOMO STRANGOLINO: delleceste@gmail.com\n"
				"# http://www.giacomos.it"
				"# MAY 2005 - SEPTEMBER 2006.\n#\n");
}
