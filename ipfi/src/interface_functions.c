#include "includes/ipfire_userspace.h"
#include <net/if.h>
#include "includes/ipfire_structs.h"
#include "includes/libnetl.h"
#include "includes/filter.h"
#include "../g_getcharlib/g_getcharlib.h"
#include "includes/interface.h"
#include "includes/mailer.h"
#include "includes/languages.h"

int print_request(const struct netl_handle* nh_control);
int state_table_request(const struct netl_handle* nh_control);
int snat_table_request(const struct netl_handle* nh_control);
int dnat_table_request(const struct netl_handle* nh_control);
void print_timeout_dhms(unsigned int timeout);
int print_state_table_entry(const struct state_info* tr, int counter);
int print_dnat_table_entry(const struct dnat_info* , int counter);
int print_snat_table_entry(const struct snat_info* , int counter);
int send_goodbye(struct netl_handle *nh_control );
void print_protocol(int state);
void print_state(int state);
void print_direction(int direction);

/* The two following are used in version 0.98.4 to manage the rule
 * adding/deletion for blocked sites.
 */
int blocked_sites_management(const char* filename);
char** remove_line(char **list, int nlines, int cancline);

extern command opts;
extern int multisock;
extern struct sockaddr_in mc_addr; /* socket address structure */

int print_request(const struct netl_handle* nh_control)
{
  ipfire_rule dummy_rule;
  command list_from_kern;
  command print_req_cmd;
  init_rule(&dummy_rule);
  unsigned counter = 0;
  print_req_cmd.cmd = PRINT_RULES;
  char *str_filter = NULL;
  ipfire_rule_filter *filter = NULL;

  /* Ask the user to setup a visualization filter */
  str_filter = setup_filter_pattern();
  if(str_filter == NULL)
          printf(TR("Errore allocating the string for the filter!\n"));
  else
  {
        filter = setup_filter(str_filter);
        if(filter == NULL)
                PVIO, PUND,  printf(TR("No filter will be applied.") ); PNL;
        free(str_filter); /* we do not need the string any more: we now have "filter" */
  }

  if(send_to_kernel( (void*) &print_req_cmd, nh_control, CONTROL_DATA) < 0)
    PRED, printf(TR("print_request(): ERROR SENDING PRINT REQUEST TO KERNEL!")), PNL;
  PGRN, printf(TR("- - - Rules loaded in firewall - - -")), PNL;
  while(1)
    {
      counter ++;
      if(read_from_kern(nh_control, (unsigned char*) &list_from_kern, 
			sizeof(command) ) < 0)
	{
	  libnetl_perror("print_request():");
	  return -1;
	}
      if(list_from_kern.cmd == PRINT_FINISHED)
	{
		printf(TR("- - - - End of list. NOTE: rules are grouped by "));
	  PUND;  printf(TR("DIRECTION")); PCL; printf(". - - - -\n");
	  return 0;
	}
    //  printf(BLACK "- - - - - - - - - - - - - - - " GREEN "%d" BLACK " - - - - - - - - - - - - - - - -" NL, 
//	     counter);
      print_rules(&list_from_kern.content.rule, 1, filter);
//       printf(GRAY "- - - - - - - - - - - - - - - - - - - - - - - - - " NL);
      //printf(NL);

    }
  return 0;
}

/* prints significative options */
int print_command(const command* cmd)
{
  
	size_t snatt_size;
	size_t dnatt_size;
	size_t logt_size;
	size_t statet_size;
	
  if(cmd->cmd == ADDING_FAILED)
    PRED, printf(TR("Rule adding/removing failed: generic error from kernel!")), PNL;
  else if(cmd->cmd == ADDING_FAILED_NORIGHTS)
    PRED, printf(TR("Rule adding/removing failed. You have not the permission to make such change." )), PNL;
	
  if(cmd->is_rule)
    {
      if(! (cmd->cmd == RULE_ALREADY_PRESENT) )
	printf(GRAY "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
      PGRN, printf(TR("RULE") ), PCL, printf(TR(" [owner: %d]:"), 
	     cmd->content.rule.owner); PNL;
      print_rules(&cmd->content.rule, 1, NULL);
      printf(GRAY "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
      return 0;
    }

    /* table sizes. struct timer_list in kernel is smaller
    * of corresponding userspace struct of 4 bytes, so 
    * "-4". Check dmesg, with kernel loglevel > 5. */
 /* WE CANNOT include NO MORE dummystructs.h
    * include/linux/timer.h is no more available! 
    * So, ask directly the kernel for the structure sizes.
 */
    command cmdsizes;
    memset(&cmdsizes, 0, sizeof(cmdsizes) );
    cmdsizes.cmd = KSTRUCT_SIZES;
    cmdsizes.is_rule = 0;
    if(send_command_to_kernel(&cmdsizes) < 0)
	    printf(RED "Error sending to the kernel the request for the structures sizes!" NL NL);
    if(read_command_from_kernel(&cmdsizes) < 0 )
	    printf(RED "Error reading from the kernel the request for the structures sizes!" NL NL);
  
    snatt_size = cmdsizes.content.fwsizes.snatsize;
    dnatt_size = cmdsizes.content.fwsizes.dnatsize;
    logt_size = cmdsizes.content.fwsizes.loginfosize;
    statet_size = cmdsizes.content.fwsizes.statesize;
  
  printf(TR("- - OPTIONS - -")); PNL;
	
  if(cmd->nat)
    printf(TR("NAT: ")), PGRN, printf(TR("ENABLED" )), PNL;
  else
    printf(TR("NAT: ")), PRED, printf(TR( "DISABLED" )), PNL;
  if(cmd->masquerade)
    printf(TR("MASQUERADE:")), PGRN, printf(TR(" ENABLED") ), PNL;
  else
    printf(TR("MASQUERADE:")), PRED, printf(TR(" DISABLED" )), PNL;
  if(cmd->stateful)
    printf(TR("STATEFUL FIREWALL:")), PGRN, printf(TR(" ENABLED")), PNL;
  else
     printf(TR("STATEFUL FIREWALL:")), PRED, printf(TR(" DISABLED")), PNL;
  if(cmd->all_stateful)
    printf(TR("ALL RULES WILL BE TREATED AS STATEFUL.")), PNL;
	
  printf( TR("KERNEL LOGLEVEL: %d LOG KERNEL/USER LEVEL: %d"), cmd->loglevel, cmd->loguser),
  	PNL, PNL;
	
  if(cmd->user_allowed)
    PGRN, printf(TR("- User is allowed to insert his own rules.")), PNL;
  else
    PVIO, printf(TR("- User is not allowed to modify firewall rules.")), PNL;
  
  if(cmd->noflush_on_exit)
    printf(TR("- Rules won't be removed from firewall at exit.") ), PNL;
  else
    printf(TR("- Your rules will be removed as soon as you turn off user interface.")), PNL;
  
  printf(TR("- Destination nat tables lifetime: %lu seconds, max %lu entries."),
	 cmd->dnatted_lifetime, cmd->max_nat_entries), PNL;
  PGRAY, printf(TR("  DNat table size: %u bytes -> max memory for nat tables: %.2f kB"),
	 dnatt_size, (float)(cmd->max_nat_entries * 
			     dnatt_size) / 1024 ), PNL;
  printf(TR("- Source nat tables lifetime: %lu seconds, max %lu entries."), 
	 cmd->snatted_lifetime, cmd->max_nat_entries), PNL;
  PGRAY, printf(TR("  SNat table size: %u bytes -> max memory for snat tables: %.2f KB"),
	 snatt_size, (float) (cmd->max_nat_entries * 
			      snatt_size) / 1024 ), PNL;
  printf(TR("- State conn. tables lifetime: %lus. Max %lu entries. [Setup/shutdown:%lus.]"), 
	 cmd->state_lifetime, cmd->max_state_entries, cmd->setup_shutd_state_lifetime), PNL;
  PGRAY, printf(TR("  State table size: %u bytes -> max memory for state tables: %.2f KB") ,
	 statet_size,  (float)(cmd->max_state_entries * 
			       statet_size) / 1024 ), PNL;
  if(cmd->loguser == 1)
  {
  	printf(TR("- Loginfo entries lifetime: %lu, max %lu entries."),
	 	cmd->loginfo_lifetime, cmd->max_loginfo_entries), PNL;
  	PGRAY, printf(TR("  Loginfo table size: %u bytes -> max memory for loginfo tables: %.2f KB"),
	 	logt_size,  (float)(cmd->max_loginfo_entries * 
			     logt_size) / 1024  ), PNL;
  }
  else
  {
  	printf(TR("- Selective log is disabled (this is not recommended).")), PNL,
  	printf(TR("  Set kernel/user log level to 1 to enable it.")), PNL;
  }
  printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
  return 0;
}


void init_table(struct state_info *st)
{
  memset(st, 0, sizeof(struct state_info) );
}

/* requests state tables to kernel and prints responses */
int state_table_request(const struct netl_handle* nh_control)
{
  int counter = 0;
  struct state_info st;
  command table_req;
  int bytes_read;
  printf(NL  "\t- - - - " UNDERL ); 
  printf(TR("TABLE OF STATEFUL CONNECTIONS")); printf(CLR " - - - -" NL NL); 
  init_command(&table_req);
  table_req.cmd = PRINT_STATE_TABLE;
  init_table(&st);
  if(send_to_kernel( (void*) &table_req, nh_control, CONTROL_DATA) < 0)
    return -1;
  while(1)
    {
      counter ++;
      init_table(&st);
      if( (bytes_read = read_from_kern(nh_control, (unsigned char*) &st, 
				       sizeof(struct state_info) ) ) < 0)
      {
		libnetl_perror("state_table_request()");
      }
      if( st.direction == PRINT_FINISHED)
		break;
      else
		print_state_table_entry((struct state_info *) &st, counter);
    }
  if(counter == 1)
	  PGRAY, printf(TR("Kernel table empty.") ), PCL;
  printf(NL NL "\t   - - - - ");
  printf(TR("End of connection table")); printf(" - - - -" NL);
  return 0;
}

/* requests dnat  tables to kernel and prints responses */
int dnat_table_request(const struct netl_handle* nh_control)
{
  int counter = 0;
  struct dnat_info di;
  command table_req;
  int bytes_read;
  printf(NL  "\t- - - - " UNDERL ); 
  printf(TR("TABLE OF ACTIVE DNAT CONNECTIONS")); printf(CLR " - - - -" NL NL); 
  init_command(&table_req);
  table_req.cmd = PRINT_DNAT_TABLE;
  /* init info table */
  memset(&di, 0, sizeof(di) );
  if(send_to_kernel( (void*) &table_req, nh_control, CONTROL_DATA) < 0)
    return -1;
  while(1)
    {
      counter ++;
  	memset(&di, 0, sizeof(di) );
      if( (bytes_read = read_from_kern(nh_control, (unsigned char*) &di, 
				       sizeof(struct dnat_info) ) ) < 0)
		libnetl_perror("dnat_table_request()");
      if( di.direction == PRINT_FINISHED)
		break;
      else
		print_dnat_table_entry((struct dnat_info *) &di, counter);
    }
  if(counter == 1)
	  PGRAY, printf(TR("Kernel table empty.") ), PCL;
  printf(NL NL "\t   - - - - ");
  printf(TR("End of dnat connection table")); printf(" - - - -" NL);
  return 0;
}

/* requests dnat  tables to kernel and prints responses */
int snat_table_request(const struct netl_handle* nh_control)
{
  int counter = 0;
  struct snat_info si;
  command table_req;
  int bytes_read;
  printf(NL  "\t- - - - " UNDERL ); 
  printf(TR("TABLE OF ACTIVE SNAT CONNECTIONS")); printf(CLR " - - - -" NL NL); 
  init_command(&table_req);
  table_req.cmd = PRINT_SNAT_TABLE;
  /* init info table */
  memset(&si, 0, sizeof(si) );
  if(send_to_kernel( (void*) &table_req, nh_control, CONTROL_DATA) < 0)
    return -1;
  while(1)
    {
      counter ++;
  	memset(&si, 0, sizeof(si) );
      if( (bytes_read = read_from_kern(nh_control, (unsigned char*) &si, 
				       sizeof(struct snat_info) ) ) < 0)
		libnetl_perror("snat_table_request()");
      if( si.direction == PRINT_FINISHED)
		break;
      else
		print_snat_table_entry((struct snat_info *) &si, counter);
    }
  if(counter == 1)
	  PGRAY, printf(TR("Kernel table empty.") ), PCL;
  printf(NL NL "\t   - - - - ");
  printf(TR("End of snat connection table")); printf(" - - - -" NL);
  return 0;
}

int change_smart_log(int level)
{
	command cmdl;
	memset(&cmdl, 0, sizeof(cmdl));
	cmdl.is_rule = 0;
	if(level != SMART_SIMPLE && level != SMART_STATE)
	{
		PRED, printf(TR("Changing levels different from SMART_SIMPLE or SMART_STATE not allowed")), PNL, PNL;
		return -1;
		
	}
	else
	{
		cmdl.cmd = level; /* SMART_SIMPLE or SMART_STATE */
		return send_command_to_kernel(&cmdl);
	}
}

void print_state(int state)
{
  if(state == SYN_SENT)
      printf(BLUE "SETUP" CLR);
  else if(state == SYN_RECV)
     printf(BLUE "SETUP OK" CLR);
  else if(state == ESTABLISHED)
     printf( BLUE "EST" CLR);
  else if(state == LAST_ACK)
      printf(BLUE "LAST ACK" CLR);
  else if(state == CLOSE_WAIT)
     printf(BLUE "CLOSE WAIT" CLR);
  else if(state == INVALID_STATE)
    printf(RED "?" CLR);
  else if(state == FIN_WAIT)
     printf(BLUE "FIN WAIT" CLR);
  else if(state == IPFI_TIME_WAIT)
     printf(BLUE "TIME WAIT" CLR);
  else if(state == GUESS_ESTABLISHED)
     printf(MAROON "EST?" CLR);
  else if(state == CLOSED)
     printf(BLUE "CLOSED" CLR);
  else if(state == NOTCP)
     printf(YELLOW "S" CLR);
  else if(state == UDP_NEW)
     printf(YELLOW "NEW" CLR);
 else if(state == UDP_ESTAB)
     printf(YELLOW "STREAM" CLR);
  else if(state == ICMP_STATE)
     printf(DRED "ICMP" CLR);
  else if(state == IGMP_STATE)
	  printf(DVIOLET "IGMP" CLR);
 else if(state == GUESS_CLOSING)
     printf(MAROON "CLOSING?" CLR);
  else if(state == INVALID_FLAGS)
     printf(RED "INVALID FLAGS!" CLR);
  else if(state == NULL_FLAGS)
     printf(RED "NULL syn fin rst ack FLAGS!"CLR );
  else if(state == GUESS_SYN_RECV)
    printf(MAROON "SETUP OK?" CLR);
  else if(state != IPFI_NOSTATE)
    printf("STATE: %d", state);
}

void print_direction(int direction)
{
  if(direction == IPFI_INPUT)
    printf(GREEN "IN " CLR);
  else if(direction == IPFI_OUTPUT_POST)
    printf("POST ");
  else if(direction == IPFI_OUTPUT)
    printf(CYAN "OUT " CLR);
  else if(direction == IPFI_FWD)
    printf(YELLOW "FORW " CLR);
  else if(direction == IPFI_INPUT_PRE)
    printf("PRE ");

}

void print_protocol(int protocol)
{	
  if(protocol == IPPROTO_TCP)
	  printf(YELLOW "TCP " CLR);
  else if(protocol == IPPROTO_UDP)
	  printf(MAROON "UDP " CLR);
  else if(protocol == IPPROTO_ICMP)
	  printf(YELLOW "ICMP " CLR);
  else if(protocol == IPPROTO_IGMP)
	  printf(VIOLET "IGMP " CLR);
}

#define INET_ADDRSTRLEN 16 /*  in.h */

/* This one prints the timeout given in seconds as an
 * unsigned int in a form ndxhymzs 
 */
void print_timeout_dhms(unsigned int to)
{
	unsigned int d, h, m, s;
	s = to % 60;
	m = (to / 60) % 60;
	h = (to / 3600) % 24;
	d = (to / (3600 * 24) );
	if(d > 0)
		printf(YELLOW "%d" GRAY "d" CLR, d);
	if(h > 0)
		printf(YELLOW "%d" GRAY "h" CLR, h);
	if(m > 0)
		printf(YELLOW "%d" GRAY "m" CLR, m);
	if(s > 0)
		printf(YELLOW "%d" GRAY "s" CLR, s);
}

int print_state_table_entry(const struct state_info* tr, int counter)
{
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, (void*)  &tr->saddr, saddr, 
	    INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (void*)  &tr->daddr, daddr, 
	    INET_ADDRSTRLEN);
  printf("* %d.", counter);
  printf(TR("from rule %d "), tr->rule_id);
  print_direction(tr->direction);
   /* Protocol */
  print_protocol(tr->protocol);
  
  printf("|%s:", saddr);
  printf( "%d", ntohs(tr->sport) );
  printf(GRAY "->" CLR);
  printf("%s:", daddr );
  
  printf("%d| ", ntohs(tr->dport) );
  char in_devname[IFNAMSIZ] = "n.a.";
  char out_devname[IFNAMSIZ] = "n.a.";
  if (tr->in_ifindex > 0) if_indextoname(tr->in_ifindex, in_devname);
  if (tr->out_ifindex > 0) if_indextoname(tr->out_ifindex, out_devname);

  if(strncmp(in_devname, "n.a.", 4) )
  	printf(TR("IF IN:" CYAN "%s"), in_devname) ;
  if(strncmp(out_devname, "n.a.", 4) )
  	printf(TR("IF OUT:" GREEN "%s"), out_devname);

  
  printf("[");
  print_state( tr->state.state);
  printf(CLR "]");
  printf("["), PGRN;
  /* Print the timeout in Days Hours, Mins and Secs */
  print_timeout_dhms(tr->timeout);
  printf(CLR "]"), PNL;

  return 0;
}

int print_dnat_table_entry(const struct dnat_info* di, int counter)
{
  char newdaddr[INET_ADDRSTRLEN];
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, (void*)  &di->saddr, saddr, 
	    INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (void*)  &di->daddr, daddr, 
	    INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (void*)  &di->newdaddr, newdaddr, 
	    INET_ADDRSTRLEN);

  printf("* %d.", counter);
  printf(TR("ID:%d:"), di->id);	
  print_direction(di->direction);
   /* Protocol */
  print_protocol(di->protocol);
  
  printf("|%s:", saddr);
  printf( "%d", ntohs(di->sport) );
  printf(GRAY "->" CLR "[");
  printf(GRAY"%s:", daddr );
  /* New destination address and port */
  printf("%d]" CLR , ntohs(di->dport) );
  printf( "==>" GREEN "%s" CLR ":", newdaddr);
  printf(GREEN "%d" CLR "|" CLR, ntohs(di->newdport) );
  
  char in_devname[IFNAMSIZ] = "n.a.";
  char out_devname[IFNAMSIZ] = "n.a.";
  if (di->in_ifindex > 0) if_indextoname(di->in_ifindex, in_devname);
  if (di->out_ifindex > 0) if_indextoname(di->out_ifindex, out_devname);

  if(strncmp(in_devname, "n.a.", 4) )
  	printf(TR("INDEV: %s"), in_devname) ;
  if(strncmp(out_devname, "n.a.", 4) )
  	printf(TR("OUTDEV: %s"), out_devname);
  
  printf("|[");
  print_state( di->state.state);
  printf(CLR "]"), CLR;
  printf("["), PGRN;
  /* Print the timeout in Days Hours, Mins and Secs */
  print_timeout_dhms(di->timeout);
  printf(CLR "]"), PNL;
  return 0;
}

int print_snat_table_entry(const struct snat_info* di, int counter)
{
  char newsaddr[INET_ADDRSTRLEN];
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, (void*)  &di->saddr, saddr, 
	    INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (void*)  &di->daddr, daddr, 
	    INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (void*)  &di->newsaddr, newsaddr, 
	    INET_ADDRSTRLEN);

  printf("* %d.", counter);
  printf(TR("ID:%d:"), di->id);	
  print_direction(di->direction);
   /* Protocol */
  print_protocol(di->protocol);
  
  printf("|[" GRAY "%s" CLR ":", saddr);
  printf(GRAY "%d" CLR "]==>", ntohs(di->sport) );
  printf(GREEN "%s" CLR ":", newsaddr);
  printf(GREEN "%d" CLR "|" CLR, ntohs(di->newsport) );

  printf(GRAY "->" CLR);
  printf("%s:", daddr );
  /* New source address and port */
  printf("%d|", ntohs(di->dport) );
   
  char in_devname[IFNAMSIZ] = "n.a.";
  char out_devname[IFNAMSIZ] = "n.a.";
  if (di->in_ifindex > 0) if_indextoname(di->in_ifindex, in_devname);
  if (di->out_ifindex > 0) if_indextoname(di->out_ifindex, out_devname);

  if(strncmp(in_devname, "n.a.", 4) )
  	printf(TR("INDEV: %s"), in_devname) ;
  if(strncmp(out_devname, "n.a.", 4) )
  	printf(TR("OUTDEV: %s"), out_devname);
  
  printf("|[");
  print_state( di->state.state);
  printf(CLR "]"), CLR;
  printf("["), PGRN;
  /* Print the timeout in Days Hours, Mins and Secs */
  print_timeout_dhms(di->timeout);
  printf(CLR "]"), PNL;
  return 0;
}

#define MAXPORT 65535
#define MINPORT 0



/////////////////////// TRADUZIONE FINO QUI /////////////////////

/* prints some information about the meanings of
 * log user levels */
void print_loguser_meanings(int level)
{
  if(level >=6)
    printf(TR("  [All filtering and translation is monitored.]") ), PNL;
  else if(level >= 5)
    printf(TR("  [All filtering is monitored, except pre/post directions.]") ), PNL;
  else if(level >= 4)
    printf(TR("  [Implicit and explicit denial is monitored.]") ), PNL;
  else if(level >= 2)
    printf(TR("  [Only implicit denial is monitored.]") ), PNL;
}

void print_hello_error(const command* hello)
{
	command sizerequest;
	struct firesizes fsizes;
  printf(RED "Error: conflicting data structures: " CLR);
  switch(hello->cmd)
    {
    case H_INFOSIZE_MISMATCH:
      printf("size of information structure mismatch.\n");
      break;
    case H_RULESIZE_MISMATCH:
      printf("size of rule structure mismatch.\n");
      break;
    case H_CMDSIZE_MISMATCH:
      printf("size of command structure mismatch.\n");
      break;
    case H_UID_MISMATCH:
      printf("UID mismatch!\n");
      break;
    case IPFIRE_BUSY:
      printf(VIOLET "ipfire is busy!" NL VIOLET 
	     "Another instance of an userspace interface seems to be running, with pid %d!"
	     NL NL, hello->anumber);
      break;
    default:
      printf("Unknown error code %d!\n", hello->cmd);
      break;
    }
    sizerequest.cmd = KSTRUCT_SIZES;
    sizerequest.is_rule = 0;
    if(send_command_to_kernel(&sizerequest) < 0)
	    printf(RED "Error sending to the kernel the request for the structures sizes!" NL NL);
    if(read_command_from_kernel(&sizerequest) < 0 )
	    printf(RED "Error reading from the kernel the request for loguser enabled!" NL NL);
    memcpy(&fsizes, &sizerequest.content.fwsizes, sizeof(fsizes) );
  printf(NL);
  printf(VIOLET "Sizes" CLR ": "NL);
  printf("kernel info: %d\tuser info: %d\n", 
	 fsizes.infosize, sizeof(ipfire_info_t) );
  printf("kernel rule: %d\tuser rule: %d\n", 
	 fsizes.rulesize, sizeof(ipfire_rule) );
  printf("kernel command: %d\tuser command: %d\n",
	 fsizes.cmdsize, sizeof(command));
	
  printf(NL "Be sure to have compiled " UNDERL "both" 
	 CLR " userspace and kernelspace software\n"
	 "with the same options about rulenames.\n");
  printf("If you notice a difference of 20 (bytes), in sizes above,\n"
	 "it is likely you "
	 "have compiled stuff with opposite options!" NL NL);
}

/* Converts seconds into days hours mins secs and prints */
void print_seconds_to_dhms(unsigned int seconds)
{
	unsigned min = 60;
	unsigned hour = 60 * min;
	unsigned day = 24 * hour;
	
	unsigned days, hours, mins, secs;
	unsigned remainder;
	
	days = seconds / day;
	remainder = seconds % day;
	
	hours = remainder / hour;
	remainder = (seconds % day) % hour;
	
	mins = remainder / min;
	secs = ( (seconds % day) % hour %min);
	
	if(days > 0)
		printf(TR("%u days "), days);
	if(hours > 0)
		printf(TR("%u hours "), hours);
	if(mins > 0)
		printf(TR("%u mins "), mins);
	if(secs > 0)
		printf(TR("%u secs"), secs);
}

void print_cmd_options(const struct cmdopts* cmdo, 
		       const struct userspace_opts* uo, int verbose)
{
	if(verbose != 0)
	{
  		printf(TR("- log level of kernel messages: %d;"), cmdo->kloglevel); PNL;
  		printf(TR("- log level of user interface: %d."), cmdo->loguser); PNL;
  		print_loguser_meanings(cmdo->loguser);
  		printf(TR("- log level on file %s: %u."), uo->logfile_name, uo->loglevel); PNL;
	}
  if(cmdo->quiet)
    {
      printf(TR("- Quiet modality enabled.") ); PNL;
      if(cmdo->loguser> 2)
	printf(TR("  Decrease loguser to avoid message exchange between") ); PNL;
	printf(TR("  user and kernel space.") ); PNL;
    }
  if(cmdo->noflush_on_exit)
    printf("- "), PGRN, printf(TR("Rules will remain ") ), PUND, printf(TR("active")),
	   PCL, PGRN, printf(TR(" in firewall after you shut")), PNL, printf(TR("  down user interface.")), PNL;
  if(cmdo->daemonize)
    printf(NL "- Program will run as a " UNDERL GREEN "daemon" CLR ", although"
	   " redirecting\n  output to this console" NL);
  if(cmdo->quiet_daemonize)
    PNL, printf(TR("- Program will run as a ")), PUND, PGRN, printf(TR("daemon")), PCL,
		printf(TR(", redirecting") ), PNL, printf(TR("output to ")), PUND, PRED,
		printf(TR("null") ), PCL, printf(TR(" device.")), PNL;
  if(uo->clearlog)
    PNL, printf(TR("- Log file will be ")), PUND, PVIO, printf(TR("cleared")), PCL,
  			printf("." NL);
  if(! uo->rmmod )
  {
	  /* For a normal user it is normal that the module is not unloaded.
	   * If instead we are root, it is good to signal this case */
	  if(verbose != 0 || getuid() == 0) 
    		PNL, printf(TR("- Kernel module will ")), PUND, PVIO, printf(TR("not") ),
		  PCL, printf(TR(" be ")), PUND, PVIO, printf(TR("unloaded")), PCL,
			printf(TR(" at exit.")), PNL;
  }
  else
    printf(TR("- Kernel module will be ")), PVIO, printf(TR("unloaded")),
	  PCL, printf(TR(" at exit." )), PNL;
	  
	  
 if(verbose) /* Print file names only if verbose is not 0 */
  {	  
	  printf(NL);
	  printf(UNDERL); printf(TR("CONFIGURATION FILES:")); printf(NL);
	  printf(TR("Permission rules:") ); PTAB; 
	  printf("\"%s\".", uo->permission_filename); printf(NL);
	  printf(TR("Denial rules:")); PTAB, PTAB; 
	  printf("\"%s\".", uo->blacklist_filename);
	  printf(NL);
	  printf(TR("Translation rules:")); PTAB, PTAB;
	  printf("\"%s\".", uo->translation_filename);
	  printf(NL);
  }
  if(uo->dns_resolver)
  {
    printf(TR("- Blacklisted sites will be blocked. List will be refreshed every %d seconds."),
	   uo->dns_refresh), PNL;
    if(verbose)
    {
    	printf(TR("- Blocked sites rules:")), PTAB,
    	printf("\"%s\".", uo->blacksites_filename),
    	printf(NL NL);
    }
  }
  if(verbose) /* Print port resolution state only if in verbose state */
  {
	  if(uo->resolv_services)
		  printf(TR("- Ports will be translated into service names.")),  PNL;
	  else
		  printf(TR("- Ports will not be translated into service names.")), PNL;
  }
  
  if(uo->mail)
  {
	  printf(TR("- Mailer enabled. An email will be sent every ") );
	  print_seconds_to_dhms(uo->mail_time);
  }
  else
	  printf(TR("- Mailer disabled." ) ), PNL;
  
  printf(NL);
}


/* manages adding a new rule, asking user for position
 * and then invoking add_rule() */
int manage_adding_rule(const ipfire_rule* r)
{
  int scelta;
  int position = 1;
  int new_pos;
  extern int den_rules_num, acc_rules_num,
    transl_rules_num;
  char line[MAXLINELEN];
	
  /* get position of last rule in vector */
  if(r->nflags.policy == DENIAL)
    position = den_rules_num;
  else if(r->nflags.policy == ACCEPT)
    position = acc_rules_num;
  else if(r->nflags.policy == TRANSLATION)
    position = transl_rules_num;
	
 prompt:
  new_pos = position;
	
  printf(TR("Type 'p' if  you want to specify the position of the new rule")); PNL;
  printf(TR("in the list, another key to insert new rule at the tail of the")); PNL;
  printf(TR("list (default is at the tail [%d]): "), position + 1);
  scelta = char_translation( g_getchar() );
  switch(scelta)
    {
    case 'p':
      PNL; printf(TR("Position of the new rule: ") );
      if(get_line(line) > 0)
	{
	  new_pos = atoi(line);
	  if(new_pos == 0)
	    {
		    PNL, PRED, printf(TR("Position %d not valid! Minimum position value is 1."),
		      new_pos); PNL, PNL;
	      goto prompt;
	    }
	  else
	    {
	      if(add_rule_at_position(r, new_pos) < 0)
		{
		  PRED, printf(TR("Error inserting rule at position %d!"), new_pos); PNL;
		  return -1;
		}
	      else 
		return new_pos;
	    }
	}
      else
	goto prompt;
			
      break;
		
    default:
      PNL; printf(TR("Rule will be inserted at the end of the list...") );
      if( (new_pos = add_rule_at_position(r, 0) ) < 0)
	{
	  PRED, printf(TR("Error inserting rule at position %d!"), new_pos), PNL;
	  return -1;
	}
      else 
	return new_pos;
			
      break;
    }
}

/* this function manages deleting a rule, presenting to
 * the user an interface to choose the position of the 
 * rule to remove */
int manage_deleting_rule(ipfire_rule * r)
{
  int scelta, i, pos, scelta2;	
  extern ipfire_rule* denial_rules;
  extern ipfire_rule* accept_rules;
  extern ipfire_rule* translation_rules;
  extern int den_rules_num, acc_rules_num,
    transl_rules_num;
	
  if(getuid() == 0)
    PNL, PNL, printf(TR("TYPE 'p' TO DELETE A PERMISSION RULE")), PNL,
	   printf(TR("     'd' TO DELETE A DENIAL RULE") ), PNL,
	   printf(TR("     't' TO DELETE A TRANSLATION RULE.")), PNL,
	   printf("[p, d, t]");
  else
   PNL, PNL, printf(TR("TYPE 'p' TO DELETE A PERMISSION RULE")), PNL,
	   printf(TR("     'd' TO DELETE A DENIAL RULE") ), PNL,
	   printf("[p, d]");
	
  scelta = g_getchar();
	
  if( (scelta == 't' ) && (getuid() != 0) )
    return -1;
	
  PNL, printf(TR("ENTER THE POSITION OF THE RULE YOU WANT TO DELETE, 0 TO EXIT."));
  PNL;
  switch(scelta)
    {
    case 'p':
      printf("[");
      for(i = 1; i < acc_rules_num + 1; i++)
	printf("%d ", i);
      printf("]: ");
      scanf("%d", &pos);
      if(pos == 0)
	return -1;
      while(getchar() != '\n');
      if( (pos <= 0) | (pos > acc_rules_num) )
	{
	  PNL; PRED; printf(TR("Error: value %d out of range!"), pos);
	  return -1;
	}
			
      PNL, PRED, printf(TR("Rule %d:"), pos); PNL; PNL;
      print_rules(accept_rules + pos -1, 1, NULL);
      PNL, PRED, printf(TR("WILL BE DELETED, ARE YOU SURE [y | n]?")); PNL;
      scelta2 = char_translation(g_getchar() );
      if(scelta2 == 'y')
	{
	  if(delete_rule_at_position(pos, ACCEPT) < 0)
	    return -1;
	  else
	    PNL, PUND, printf(TR("PERMISSION")),  PCL, 
	  		printf(TR(" RULE AT POSITION %d SUCCESSFULLY DELETED."), pos), PNL;
	  /* set policy in rule: update_kernel_rules() needs to know */
	  r->nflags.policy = ACCEPT;
	}
      else 
	return -1;
			
      return 0;
			
    case 'd':
      printf("[");
      for(i = 1; i < den_rules_num + 1; i++)
	printf("%d ", i);
      printf("]: ");
      scanf("%d", &pos);
      while(getchar() != '\n');
      if(pos == 0)
	return -1;
      if( (pos <= 0) | (pos > den_rules_num) )
	{
	  PNL; PRED; printf(TR("Error: value %d out of range!"), pos);
	  return -1;
	}
			
      PNL, PRED, printf(TR("Rule %d:"), pos); PNL; PNL;
      print_rules(denial_rules + pos -1, 1, NULL);
      PNL, PRED, printf(TR("WILL BE DELETED, ARE YOU SURE [y | n]?")) ; PNL;
      scelta2 = char_translation( g_getchar() );
      if(scelta2 == 'y')
	{
	  if(delete_rule_at_position(pos, DENIAL) < 0)
	    return -1;
	  else
	    PNL, PUND, printf(TR("DENIAL")),  PCL, 
	  		printf(TR(" RULE AT POSITION %d SUCCESSFULLY DELETED."), pos), PNL;
	  r->nflags.policy = DENIAL; /* see above */
	}
      else 
	return -1;
			
      return 0;	
			
    case 't':
      printf("[");
      for(i = 1; i < transl_rules_num + 1; i++)
	printf("%d ", i);
      printf("]: ");
      scanf("%d", &pos);
      while(getchar() != '\n');
      if(pos == 0)
	return -1;
      if( (pos <= 0) | (pos > transl_rules_num) )
	{
	  PNL; PRED; printf(TR("Error: value %d out of range!"), pos);
	  return -1;
	}
			
      PNL, PRED, printf(TR("Rule %d:"), pos); PNL; PNL;
      print_rules(translation_rules + pos -1, 1, NULL);
      PNL, PRED, printf(TR("WILL BE DELETED, ARE YOU SURE [y | n]?")); PNL;
      scelta2 = char_translation( g_getchar() );
      if(scelta2 == 'y')
	{
	  if(delete_rule_at_position(pos, TRANSLATION) < 0)
	    return -1;
	  else
	    PNL, PUND, printf(TR("TRANSLATION")),  PCL, 
	  		printf(TR(" RULE AT POSITION %d SUCCESSFULLY DELETED."), pos), PNL;
	  r->nflags.policy = TRANSLATION; /* see above */
	}
      else 
	return -1;
			
      return 0;		
    }
  return 0;
	
}

void print_help(void)
{
  FILE* fphelp = NULL;
  char homedir[PWD_FIELDS_LEN];
  char namefile[MAXFILENAMELEN]="";
  get_user_info(HOMEDIR, homedir);
  if(strlen(homedir) + 20 < MAXFILENAMELEN)
    strcat(namefile, homedir);
  strcat(namefile, "/.IPFIRE/firehelp");
  fphelp = fopen(namefile, "r");
  char line[1024];
  unsigned count  = 1;
  if(fphelp == NULL)
    PRED, perror(TR("Error opening help file!")), PCL;
  else
    {
      while(fgets(line, 1024, fphelp) != NULL)
	{
	  if(strncmp(line, "_", 1) == 0)
	    {
	      printf(UNDERL);
	      line[0] = '\r';
	    }
	  if(strncmp(line, "#", 1) == 0)
	    goto next;
	  fprintf(stdout, "\r%s" CLR, line);
	  if(count %6 == 0)
	    {
	      PGRAY, printf(TR("- - - - - - - Press a key to read on... - - - - - - ")), PCL;
	      g_getchar();
	      printf("\r                                                                          \r");     
	    }	
	next:
	  count ++;			
	}
      fclose(fphelp);
    }
}

void print_configuration_options(void)
{
  extern command opts;
  extern struct userspace_opts uops;
  extern struct cmdopts prog_ops;
  /* 1 for verbose printing */
  print_cmd_options(&prog_ops, &uops, 1);
  print_command(&opts);
}

/* Returns 0 if filter is null (no filter to be applied,
 * >0 if the filter has success, < 0 otherwise
 */
int filter_rule(const ipfire_rule*  rule, const ipfire_rule_filter* filter)
{
	if(filter == NULL)
		return 0;
	/* 1. Direction */
	if( filter->direction) /* we have to filter by drection */
	{
		if( ! (/* if it does not happen one of these sets of conditions, we fail */
			(filter->out && rule->direction == IPFI_OUTPUT) ||
			(filter->in && rule->direction == IPFI_INPUT) ||
			(filter->fwd && rule->direction == IPFI_FWD) ||
			(filter->pre && rule->direction == IPFI_INPUT_PRE) ||
			(filter->post && rule->direction == IPFI_OUTPUT_POST)
		      )	
		)
			return -1;
	}
	/* 2. Policy: accept or denial only */
	if(filter->policy && (filter->rule->nflags.policy != rule->nflags.policy))
		return -1;
	/* 3. Position */
	if(filter->position && (filter->rule->position != rule->position))
		return -1;
	/* 4. Protocol */
	if(filter->protocol)
	{
		if( ! /* if it does not happen one of these sets of conditions, we fail */
		    (	(filter->tcp && rule->ip.protocol == IPPROTO_TCP) ||
			(filter->udp && rule->ip.protocol == IPPROTO_UDP) ||
			(filter->icmp && rule->ip.protocol == IPPROTO_ICMP) ||
			(filter->igmp && rule->ip.protocol == IPPROTO_IGMP)	    
		    )
		  )
			return -1;
	}
	/* 5. State */
	if(filter->state && !rule->state)
		return -1;
	/* 6. Device */
	if(filter->device )
	{
		if(!filter->indevice && !filter->outdevice)
		{
			if(strcmp(filter->rule->devpar.in_devname, rule->devpar.in_devname) &&
				strcmp(filter->rule->devpar.in_devname, rule->devpar.out_devname) )
				 return -1;
		}
		if(filter->indevice)
		{
			if(strcmp(filter->rule->devpar.in_devname, rule->devpar.in_devname) )
				return -1;
		}
		if(filter->outdevice)
		{
			if(strcmp(filter->rule->devpar.out_devname, rule->devpar.out_devname) )
				return -1;
		}
	}
	/* 7. IP */
	/* IP are stored using inet_pton and so are already in network byte order.
	 * The ports are instead saved in the rule by allocate_ruleset() with 
	 * htons(), and so they are in network byte order, while those read by
	 * the filter allocator are not converted in network byte order.
	 */
	if(filter->sip) /* a source IP is specified */
	{
		struct in_addr ia1, ia2;
		if(filter->rule->nflags.src_addr == MYADDR && rule->nflags.src_addr == MYADDR)
			goto ipdst;
		ia1.s_addr = filter->rule->ip.ipsrc[0];
		ia2.s_addr = rule->ip.ipsrc[0];

		if(rule->parmean.samean == INTERVAL)
		{
			if(filter->rule->ip.ipsrc[0] > rule->ip.ipsrc[1] ||
					filter->rule->ip.ipsrc[0] < rule->ip.ipsrc[0] )
				return -1;
		}
		else if(rule->parmean.samean == SINGLE)
		{
			if(filter->rule->ip.ipsrc[0] != rule->ip.ipsrc[0])
				return -1;
		}
		else
		{
			printf(TR("Other kinds of ip directives not supported!\n") );
			return -1;
		}
	}
ipdst:
	if(filter->dip) /* a destination IP is specified */
	{
		struct in_addr ia1, ia2;
		
		if(filter->rule->nflags.dst_addr == MYADDR && rule->nflags.dst_addr == MYADDR)
			goto sport;
		ia1.s_addr = filter->rule->ip.ipdst[0];
		ia2.s_addr = rule->ip.ipdst[0];
		if(rule->parmean.damean == INTERVAL)
		{
			if(filter->rule->ip.ipdst[0] > rule->ip.ipdst[1] ||
					filter->rule->ip.ipdst[0] < rule->ip.ipdst[0] )
				return -1;
		}
		else if(rule->parmean.damean == SINGLE)
		{
			if(filter->rule->ip.ipdst[0] != rule->ip.ipdst[0])
				return -1;
		}
		else
		{
			printf(TR("Other kinds of ip directives not supported!\n") );
			return -1;
		}
	}
sport:
	/* 7. PORT */
	if(filter->sport) /* a source port is specified */
	{
		if(rule->parmean.spmean == INTERVAL)
		{
			if(filter->rule->tp.sport[0] > ntohs(rule->tp.sport[1]) ||
					filter->rule->tp.sport[0] < ntohs(rule->tp.sport[0]) )
				return -1;
		}
		else if(rule->parmean.spmean == SINGLE)
		{
			if(filter->rule->tp.sport[0] != ntohs(rule->tp.sport[0]))
				return -1;
		}
		else
		{
			printf(TR("Other kinds of port directives not supported!\n") );
			return -1;
		}
	}
	if(filter->dport) /* a destination port is specified */
	{
		if(rule->parmean.dpmean == INTERVAL)
		{
			if(filter->rule->tp.dport[0] > ntohs(rule->tp.dport[1]) ||
					filter->rule->tp.dport[0] < ntohs(rule->tp.dport[0]) )
				return -1;
		}
		else if(rule->parmean.dpmean == SINGLE)
		{
			if(filter->rule->tp.dport[0] != ntohs(rule->tp.dport[0]))
				return -1;
		}
		else
		{
			printf(TR("Other kinds of port directives not supported!\n") );
			return -1;
		}
	}

	return 0;
	
}

int print_rules(const ipfire_rule* v_rules, int numrules, const ipfire_rule_filter* filter)
{
  int i = 0, j;
  char proto[12];
  struct in_addr addr;
  if(v_rules == NULL)
    return -1;
  for(i=0; i < numrules; i++)
    {

     	 if(filter == NULL || filter_rule(&v_rules[i], filter) >= 0)
	 {
      if(v_rules[i].nflags.policy == DENIAL)
	{
		PRED, printf("----------------------------------------------"); PNL;
		PUND, PRED, printf(TR("DENIAL RULE")), printf(CLR " N. %d\t", v_rules[i].position);
	}
      else if(v_rules[i].nflags.policy == ACCEPT)
	{
		PGRN, printf("----------------------------------------------"); PNL;
		PUND, PGRN, printf(TR("PERMISSION RULE")), printf(CLR " N. %d\t", v_rules[i].position);
      	}
	else if(v_rules[i].nflags.policy == BLACKSITE)
	{
		PRED, printf("----------------------------------------------"); PNL;
		PUND, PRED, printf(TR("BLACKLISTED SITE RULE")), printf(CLR " N. %d\t", v_rules[i].position);
	}
      else if(v_rules[i].nflags.policy == TRANSLATION)
	{
	  PCYAN, printf("----------------------------------------------"); PNL;
	  if(v_rules[i].masquerade)
	    printf(TR("MASQUERADE RULE N. %d"), v_rules[i].position), PTAB;
	  else if( (v_rules[i].nat) && (v_rules[i].direction == IPFI_INPUT_PRE ) )
	    printf(TR("PREROUTING DEST. ADDRESS TRANSL. RULE N. %d"),
		   v_rules[i].position), PTAB;
	  else if( (v_rules[i].nat) && (v_rules[i].direction == IPFI_OUTPUT ) )
	    printf(TR("OUTPUT DNAT. RULE N. %d"),
		   v_rules[i].position), PTAB;
	  else if( (v_rules[i].nat) && (v_rules[i].direction == IPFI_OUTPUT_POST ) )
	    printf(TR("OUTPUT POSTROUTING SNAT. RULE N. %d"),
		   v_rules[i].position), PTAB;
	  else if( (v_rules[i].masquerade) && (v_rules[i].direction == IPFI_OUTPUT_POST ) )
	    printf(TR("OUTPUT POSTROUTING MASQ. RULE N. %d"),
		   v_rules[i].position), PTAB;
	}
	/* rulename, if enabled */
#ifdef ENABLE_RULENAME
      if(strlen(v_rules[i].rulename)	> 0)
		printf(GRAY "\"" VIOLET "%s" GRAY "\"", v_rules[i].rulename);
#endif	
	printf(NL);
      /* print direction */
      if(v_rules[i].direction == IPFI_INPUT)
		PGRN, printf(TR(" INPUT")), PTAB, PTAB, PCL;
      else if(v_rules[i].direction == IPFI_OUTPUT)
		printf(CYAN), printf(TR(" OUTPUT")), PTAB, PTAB, PCL;
      else if(v_rules[i].direction == IPFI_FWD)
		PYEL, printf(TR(" FORWARD") ), PTAB, PTAB, PCL;	
      printf(TR("OWNER: %d"), v_rules[i].owner), PTAB, PTAB;
      /* protocol */
      if(v_rules[i].nflags.proto)
      {
	      get_proto_name(proto, v_rules[i].ip.protocol);
	      printf(TR("PROTO: ")), printf(YELLOW "%s" CLR, proto );
      }	
     
      if( (v_rules[i].nflags.src_addr) | (v_rules[i].nflags.dst_addr) )
		printf(NL);
      if(v_rules[i].nflags.src_addr)
	{
	  addr.s_addr = v_rules[i].ip.ipsrc[0];
	  if( (v_rules[i].parmean.samean == SINGLE) &
	      (v_rules[i].nflags.src_addr == ONEADDR) )
	    printf(TR("IPSRC: %s | "), inet_ntoa(addr) );
			
	  else if( (v_rules[i].parmean.samean == DIFFERENT_FROM) &
		   (v_rules[i].nflags.src_addr == ONEADDR) )
	    printf(TR("IPSRC NOT: %s | "), inet_ntoa(addr) );
			
	  else if( (v_rules[i].parmean.samean == DIFFERENT_FROM) &
		   (v_rules[i].nflags.src_addr == MYADDR) )
	    PUND, printf(TR("IPSRC: NOT MY ADDRESS")), printf(CLR " ");
			
	  else if( (v_rules[i].parmean.samean == SINGLE) &
		   (v_rules[i].nflags.src_addr == MYADDR) )
	    PUND, printf(TR("IPSRC: MY ADDRESS")), printf(CLR " ");
			
	  else if(v_rules[i].parmean.samean == INTERVAL)
	    {
	      printf(TR("IPSRC: %s "), inet_ntoa(addr) );
	      addr.s_addr = v_rules[i].ip.ipsrc[1];
	      printf("- %s | ", inet_ntoa(addr) );
	    }
	  else if(v_rules[i].parmean.samean == INTERVAL_DIFFERENT_FROM)
	    {
	      printf(TR("IPSRC NOT IN INTERVAL: %s "), inet_ntoa(addr) );
	      addr.s_addr = v_rules[i].ip.ipsrc[1];
	      printf("- %s | ", inet_ntoa(addr) );
	    }
	  else if(v_rules[i].parmean.samean == MULTI)
	  {
	    addr.s_addr = v_rules[i].ip.ipsrc[0];
	    printf(TR("IPSRC: \e[4m%s\e[0m,"), inet_ntoa(addr));
	    for(j = 1; j < MAXMULTILEN && v_rules[i].ip.ipsrc[i] != 0; i++)
	    {
	       addr.s_addr = v_rules[i].ip.ipsrc[j];
		printf(" \e[4m%s\e[0m, ", inet_ntoa(addr));
	    }
	    printf("\b\b | "); /* remove last space and comma */
	  }
	  else if(v_rules[i].parmean.samean == MULTI_DIFFERENT)
	  {
	    addr.s_addr = v_rules[i].ip.ipsrc[0];
	    printf(TR("IPSRC NOT: %s,"), inet_ntoa(addr));
	    for(j = 1; j < MAXMULTILEN && v_rules[i].ip.ipsrc[i] != 0; i++)
	    {
	       addr.s_addr = v_rules[i].ip.ipsrc[j];
		printf(" \e[4m%s\e[0m, ", inet_ntoa(addr));
	    }
	    printf("\b\b | "); /* remove last space and comma */
	  }
	}
      if(v_rules[i].nflags.dst_addr)
	{
	  addr.s_addr = v_rules[i].ip.ipdst[0];
	  if( (v_rules[i].parmean.damean == SINGLE) &
	      (v_rules[i].nflags.dst_addr == ONEADDR) )
	    printf(TR("IPDST: %s | "), inet_ntoa(addr) );
	  else if( (v_rules[i].parmean.damean == DIFFERENT_FROM) &
		   (v_rules[i].nflags.dst_addr == ONEADDR) )
	    printf(TR("IPDST NOT: %s | "), inet_ntoa(addr) );
	  else if(v_rules[i].parmean.damean == INTERVAL)
	    {
	      printf(TR("IPDST: %s "), inet_ntoa(addr) );
	      addr.s_addr = v_rules[i].ip.ipdst[1];
	      printf("- %s | ", inet_ntoa(addr) );
	    }
	  else if(v_rules[i].parmean.damean == INTERVAL_DIFFERENT_FROM)
	    {
	      printf(TR("IPDST NOT IN INTERVAL: %s "), inet_ntoa(addr) );
	      addr.s_addr = v_rules[i].ip.ipdst[1];
	      printf("- %s | ", inet_ntoa(addr) );
	    }
	  else if( (v_rules[i].parmean.damean == DIFFERENT_FROM) && (v_rules[i].nflags.dst_addr == MYADDR) )
	    PUND, printf(TR("IPDST: NOT MY ADDR")), printf(CLR " ");
	  else if((v_rules[i].parmean.damean == SINGLE) && (v_rules[i].nflags.dst_addr == MYADDR) )
	    PUND, printf(TR("IPDST: MY ADDRESS")), printf(CLR " ");
	  else if((v_rules[i].parmean.damean == MULTI))
	  {
	    addr.s_addr = v_rules[i].ip.ipdst[0];
	    printf(TR("IPDST: \e[4m%s\e[0m,"), inet_ntoa(addr));
	    for(j = 1; j < MAXMULTILEN && v_rules[i].ip.ipdst[j] != 0; j++)
	    {
	       addr.s_addr = v_rules[i].ip.ipdst[j];
		printf(" \e[4m%s\e[0m, ", inet_ntoa(addr));
	    }
	    printf("\b\b | "); /* remove last space and comma */
	  }
	  else if(v_rules[i].parmean.damean == MULTI_DIFFERENT)
	  {
	    addr.s_addr = v_rules[i].ip.ipdst[0];
	    printf(TR("IPDST NOT: \e[4m%s\e[0m,"), inet_ntoa(addr));
	    for(j = 1; j < MAXMULTILEN && v_rules[i].ip.ipdst[j] != 0; j++)
	    {
	       addr.s_addr = v_rules[i].ip.ipdst[j];
		printf(" \e[4m%s\e[0m, ", inet_ntoa(addr));
	    }
	    printf("\b\b | "); /* remove last space and comma */
	  }
	}
     /* TOT LEN AND TOS NOT TRANSLATED */
      if(v_rules[i].nflags.tot_len)
		printf(TR("TOT. LEN: %d | "), v_rules[i].ip.total_length);
      if(v_rules[i].nflags.tos)
		printf(TR("TOS: %d | "), v_rules[i].ip.tos);
      /* done with IP fields */
      printf("\n");
      if(v_rules[i].nflags.src_port)
	{
	  if(v_rules[i].parmean.spmean == SINGLE)
	    printf(TR("SPORT: %d | "), ntohs(v_rules[i].tp.sport[0]) );
	  else if(v_rules[i].parmean.spmean == DIFFERENT_FROM)
	    printf(TR("SPORT NOT: %d | "), ntohs(v_rules[i].tp.sport[0]) );
	  else if(v_rules[i].parmean.spmean == INTERVAL)
	    printf(TR("SPORT: %d - %d | "), ntohs(v_rules[i].tp.sport[0]),
		   ntohs(v_rules[i].tp.sport[1]) );	
	  else if(v_rules[i].parmean.spmean == INTERVAL_DIFFERENT_FROM)
	    printf(TR("SPORT NOT IN: %d - %d | "), ntohs(v_rules[i].tp.sport[0]),
		   ntohs(v_rules[i].tp.sport[1]) );
	  else if(v_rules[i].parmean.spmean == MULTI)
	  {
	     printf(TR("SPORT: \e[4m%d\e[0m, "), ntohs(v_rules[i].tp.sport[0]));
	     for(j = 1; j < MAXMULTILEN && v_rules[i].tp.sport[j] != 0; j++)
	       printf("\e[4m%d\e[0m, ", ntohs(v_rules[i].tp.sport[j]));
	  }
	  else if(v_rules[i].parmean.spmean == MULTI_DIFFERENT)
	  {
	     printf(TR("SPORT NOT: \e[4m%d\e[0m, "), ntohs(v_rules[i].tp.sport[0]));
	     for(j = 1; j < MAXMULTILEN && v_rules[i].tp.sport[j] != 0; j++)
	       printf("\e[4m%d\e[0m, ", ntohs(v_rules[i].tp.sport[j]));
	  }
	}
      if(v_rules[i].nflags.dst_port)
	{
	  if(v_rules[i].parmean.dpmean == SINGLE)
	    printf(TR("DPORT: %d | "), ntohs(v_rules[i].tp.dport[0]) );
	  else if(v_rules[i].parmean.dpmean == DIFFERENT_FROM)
	    printf(TR("DPORT NOT: %d | "), ntohs(v_rules[i].tp.dport[0]) );
	  else if(v_rules[i].parmean.dpmean == INTERVAL)
	    printf(TR("DPORT: %d - %d | "), ntohs(v_rules[i].tp.dport[0]),
		   ntohs(v_rules[i].tp.dport[1]) );	
	  else if(v_rules[i].parmean.dpmean == INTERVAL_DIFFERENT_FROM)
	    printf(TR("DPORT NOT IN: %d - %d | "), ntohs(v_rules[i].tp.dport[0]),
		   ntohs(v_rules[i].tp.dport[1]) );
	
	  else if(v_rules[i].parmean.dpmean == MULTI)
	  {
	     printf(TR("DPORT: \e[4m%d\e[0m, "), ntohs(v_rules[i].tp.dport[0]));
	     for(j = 1; j < MAXMULTILEN && v_rules[i].tp.dport[j] != 0; j++)
	       printf("\e[4m%d\e[0m, ", ntohs(v_rules[i].tp.dport[j]));
	    printf("\b\b | "); /* remove last space and comma */
	  }
	  else if(v_rules[i].parmean.dpmean == MULTI_DIFFERENT)
	  {
	     printf(TR("DPORT NOT: \e[4m%d\e[0m, "), ntohs(v_rules[i].tp.dport[0]));
	     for(j = 1; j < MAXMULTILEN && v_rules[i].tp.dport[j] != 0; j++)
	       printf("\e[4m%d\e[0m, ", ntohs(v_rules[i].tp.dport[j]));
	    printf("\b\b | "); /* remove last space and comma */
	  }
	}
      if(v_rules[i].nflags.syn)
	printf("SYN: %d | ", v_rules[i].tp.syn);
      if(v_rules[i].nflags.fin)
	printf("FIN: %d | ", v_rules[i].tp.fin);
      if(v_rules[i].nflags.ack)
	printf("ACK: %d | ", v_rules[i].tp.ack);
      if(v_rules[i].nflags.psh)
	printf("PSH: %d | ", v_rules[i].tp.psh);
      if(v_rules[i].nflags.urg)
	printf("URG: %d | ", v_rules[i].tp.urg);
      if(v_rules[i].nflags.rst)
	printf("RST: %d | ", v_rules[i].tp.rst);
      if(v_rules[i].nflags.icmp_type)
	printf("ICMP TYPE: %d | ", v_rules[i].icmp_p.type);
      if(v_rules[i].nflags.icmp_code)
	printf("ICMP CODE: %d | ", v_rules[i].icmp_p.code);
      if(v_rules[i].nflags.icmp_echo_id)
	printf("ICMP ECHO ID: %d | ", v_rules[i].icmp_p.echo_id);
      if(v_rules[i].nflags.icmp_echo_seq)
	printf("ICMP ECHO SEQ: %d | ", v_rules[i].icmp_p.echo_seq);
      if(v_rules[i].nflags.ftp)
		PVIO, printf(TR("PASSIVE FTP SUPPORT ")), printf(CLR "| ");
      /* state */
      if(v_rules[i].state)
	printf("[" BLUE ), printf(TR("STATE")), printf(CLR "] ");
		
   if(v_rules[i].nat)
	{
	  printf(NL YELLOW "NAT" CLR ": " CLR );
	  if(v_rules[i].nflags.newaddr)
	    {
	      addr.s_addr = v_rules[i].newaddr;
	      if( (v_rules[i].direction == IPFI_INPUT_PRE) ||
		  (v_rules[i].direction == IPFI_OUTPUT)  )
			printf(TR("IP DNAT TO: %s | "), inet_ntoa(addr) );
	      else if(v_rules[i].direction == IPFI_OUTPUT_POST)
			printf(TR("IP SNAT TO: %s | "), inet_ntoa(addr) );
	    }
	  if(v_rules[i].nflags.newport)
	    {
	      if( (v_rules[i].direction == IPFI_INPUT_PRE) ||
		  (v_rules[i].direction == IPFI_OUTPUT)  )
			printf(TR("PORT DNAT TO: %d | "), htons(v_rules[i].newport) );
	      else if(v_rules[i].direction == IPFI_OUTPUT_POST)
		printf(TR("PORT SNAT TO: %d | "), htons(v_rules[i].newport) );
	    }		
	}
      if(v_rules[i].masquerade)
		printf("[" MAROON), printf(TR("MASQ")), printf( CLR "] ");
      if(v_rules[i].nflags.indev)
		printf("[" GREEN ), printf(TR("in device: %s"), v_rules[i].devpar.in_devname),
		 	printf(CLR "] ");
      if(v_rules[i].nflags.outdev)
		printf("[" GREEN), printf(TR("out device: %s"), v_rules[i].devpar.out_devname), 
	  		printf(CLR "] ");
	if(v_rules[i].pkmangle.mss.enabled)
	{
	   PNL;
	   if(v_rules[i].pkmangle.mss.option == MSS_VALUE)
	     printf("-- " GREEN), printf(TR("tcp mss: %d"), v_rules[i].pkmangle.mss.mss), printf(CLR " --");
	   else if(v_rules[i].pkmangle.mss.option == ADJUST_MSS_TO_PMTU)
	     printf("-- " GREEN), printf(TR("tcp MSS_VALUE adjust to path mtu")), printf(CLR " --");
	}
		
		PNL, PGRAY, printf("----------------------------------------------"); PNL;
	 } 
    }
  return 1;
}


void print_menu(short filter_enabled, short resolv_services)
{
  extern command opts;
  extern struct userspace_opts uops;
  command askforloguser;
  extern char upper_username[PWD_FIELDS_LEN];
  extern int den_rules_num;
  extern int acc_rules_num; 
  extern int transl_rules_num;
	
  /* NOTE: for translation: do not change menu keys! */
  printf(NL GRAY " F1: HELP " DRED "*" GRAY
	 " ?: INFO\t  " CLR  " * " RED UNDERL "IPFIRE" CLR " *");
	
  if(getuid() == 0)
    printf(DRED "\t\t\tROOT" NL);
  else
    printf(GREEN "\t\t\t%s" NL, upper_username);
	
  build_loguser_enabled_command(&askforloguser, IS_LOGUSER_ENABLED);

  if(send_command_to_kernel(&askforloguser) < 0)
  	printf(RED "Error sending to kernel the request for loguser enabled!" NL NL);
  if(read_command_from_kernel(&askforloguser) < 0 )
  	printf(RED "Error reading from kernel the request for loguser enabled!" NL NL);

  printf("*---------------------------------------------------------------*\n");
  printf("| "GRAY"P."CLR); printf(TR("  PRINT YOUR RULES.   ")); printf("\t| "
	 GRAY"F/Z."CLR); printf(TR("SETUP/CLEAR A VIEW FILTER.|")); PNL;
  printf("| "GRAY"F3."CLR); printf(TR(" PRINT RULES IN FIREWALL.  ")); printf("| ");
  if(filter_enabled)
  {
	  printf( GRAY"K."CLR); printf(TR("      PRINT THE FILTER. \t")); printf("|");
  	  printf(" ["), PVIO, printf(TR("FILTER ON")),  PCL, printf("]" ), PNL;
  }
  else
  {
	printf(GRAY"CTRL+R."CLR); printf(TR(" RELOAD RULES.    ")); printf("\t|\n");
  }
  	
  printf("| "GRAY"I."CLR); printf(TR("  INSERT A RULE.         ")); printf("\t| "
	 GRAY"CANC."CLR); printf(TR("   DELETE A RULE.        ")); printf("|");

  if(askforloguser.anumber == 0)
  	printf(" ["),  PBOLD,  PRED, printf(TR("SILENT")),  PCL, printf("]" ), PNL;
  else
  	PNL;

  printf("| "GRAY"F5."CLR); printf(TR(" PRINT STATE TABLE.        ")); printf("| "
	 GRAY"CTRL+B"CLR); 
  
  if(!uops.dns_resolver)
	  PGRAY;

  printf(TR("  EDIT BLOCKED SITES. \t| ")); PCL;
	
  if(getuid() == 0)
    printf("[" GREEN "%d" CLR "|" RED "%d" CLR "|" YELLOW "%d" 
	   CLR "]\n", acc_rules_num, den_rules_num, transl_rules_num);
  else
    printf("[" GREEN "%d" CLR "|" RED "%d" CLR "|" GRAY "*" 
	   CLR "]\n", acc_rules_num, den_rules_num);

  if(askforloguser.anumber == 0)
  	printf("| "GRAY"V."CLR), printf(TR("  PRINT PACKETS FLOWING.    ")), printf("| ");
  else
  	printf("| "GRAY"S."CLR), printf(TR("  SILENT MODALITY.          ")), printf("| ");

  if(resolv_services)
  	printf(GRAY"B."CLR), printf(TR("      PORT RESOLUTION OFF.  ")), printf("| ");
  else
  	printf(GRAY"U."CLR), printf(TR("      ENABLE PORT RESOLUT.  ")), printf("| ");
  
  if(opts.nat)
    printf("[" GREEN "NAT" CLR "]\n");
  else
    printf("[" RED "NAT" CLR "]\n");
  printf("| " GRAY "F7." CLR    ); printf(TR(" KERNEL STATISTICS      ")); printf("\t| " 
	 GRAY "L." CLR); printf(TR("      LOCAL STATISTICS.")); printf("\t| " );
  if( (opts.stateful) & (!opts.all_stateful) )
    printf("[" GREEN "STATE" CLR "]\n");
  else if( ( opts.stateful) & (opts.all_stateful) )
    printf("[" GREEN "ALLSTATE" CLR "]\n");
  else
    printf("[" RED), printf(TR( "STATE")), printf(CLR "]\n");
	
  printf("| "GRAY"C."CLR); printf(TR("  PRINT CONFIGURATION INFO.")); printf("\t| "
	 GRAY "ESC" CLR "/" GRAY "Q." CLR); printf(TR("  QUIT.")); printf("\t\t\t| ");
  if(opts.masquerade)
    printf("[" GREEN), printf(TR("MASQ")), printf(CLR "]\n");
  else
    printf("[" RED ), printf(TR("MASQ")), printf( CLR "]\n");
  printf("*---------------------------------------------------------------*\n");
}

/* main interaction menu */
int interaction(const struct netl_handle* nh_control)
{
  int scelta;
  int counter;
  int ret;
  int rules_updated = -1;
  ipfire_rule r;
  char username[PWD_FIELDS_LEN];
  struct kernel_stats firestats;
  extern pid_t resolver_pid;
  struct mailer_options mailopts;
  extern struct userspace_opts uops;
  char *str_filter = NULL;
  short filter_enabled = 0;
  short resolve_services = uops.resolv_services;
  /* The following is used to enable/disable the communication between
   * the kernel and the user son process which prints the packets with
   * the verdicts on the console.
   */
  command cmd_toggle_loguser;
	
  do{
    print_menu(filter_enabled, resolve_services);
    /* This does not call char_translation: keys are not 
     * translated in main menu, because of the presence of
     * special function keys and 'CANC' and CTRL keys..
     */
    scelta = g_getchar();
    switch(scelta)
      {
	/* Function keys involve kernel requests, except F1,
	 * which is for help */
      case F3:
      case '3':
	send_command_to_listener("quiet");
	print_request(nh_control);
	prompt_return_to_menu();
	break;
				
      case F11:
      case CTRL_F:
	if( (counter = flush_request(nh_control, FLUSH_RULES) ) < 0)
	  PRED, printf(TR("print_request(): ERROR SENDING FLUSH COMMAND TO KERNEL!")),
		PNL;
	else
	  PGRN, printf(TR("Flushed %d rules!"), counter), PNL;
	prompt_return_to_menu();
	break;
					
      case F5: /* request the table of connection established */
      case '5':
	send_command_to_listener("quiet");
	state_table_request(nh_control);
	prompt_return_to_menu();				
	break;	

      case F4: /* request the table of snat connections established */
      case '4':
	send_command_to_listener("quiet");
	snat_table_request(nh_control);
	prompt_return_to_menu();				
	break;	
		
      case F6: /* request the table of dnat connection established */
      case '6':
	send_command_to_listener("quiet");
	dnat_table_request(nh_control);
	prompt_return_to_menu();				
	break;	
			
      case 'i': case 'I':
	stop_printing(); /* stop printing messages on console */
	PNL; PNL;
	PGRAY; printf(TR("Type \"x\" to exit this menu without modifying rules."));
	PNL;
	if(get_new_rule(&r) < 0)
	  {
	    printf(TR("No rule added...")); PNL;
	    goto _break;
	  }
	PNL; PNL; PVIO;
	printf(TR("New rule to be added:")); PNL; PNL;
	print_rules(&r, 1, NULL); PNL, PVIO;
	printf(TR("Do you want to add the new rule [y | n]? " )); PNL;
	scelta = char_translation( g_getchar() );
	if( (scelta != 'y') & (scelta != 's') )
	  {
		PNL, PVIO;
	    printf(TR("New rule has not been added.")); PNL; PNL;
	    break;
	  }
	/* manage_adding_rule adds rule to local vector */
	if( (ret = manage_adding_rule(&r) ) < 0)
	  PNL, PRED, printf(TR("Rule not added." )), PNL;
	else
	  PNL, PNL, PGRN, printf(TR("Rule %d successfully added!"), ret), PNL;
	/* now we have to update kernel rules. See ipfire_userspace.c */
	if( (rules_updated = update_kernel_rules(r.nflags.policy,
						 RELOAD_VECTOR) ) < 0)
	  PRED, printf(TR("ERROR UPDATING KERNEL RULES!" )), PNL;
	else
	  PGRN, printf(TR("FIREWALL RULES UPDATED [%d RULES] :)" ), rules_updated);
	printf(TR("Saving rules on file...") );
	if(save_rules() < 0)
	  PRED, printf(TR("Error saving rules!")), PNL, PNL;
	else
	  printf("\tOK" NL);
      _break:
	prompt_return_to_menu();
	break;	
					
      case 'd': case 'D': case CANC:
	stop_printing();
	if(manage_deleting_rule(&r) < 0)
	  PVIO, PNL, printf(TR("RULE NOT DELETED." )), PNL;
	else
	  {
	    /* update rules in kernel firewall */
	    if( ( rules_updated = update_kernel_rules(r.nflags.policy, RELOAD_VECTOR) ) < 0)
	      PRED, printf(TR("ERROR UPDATING KERNEL RULES!")), PNL;
	    else
	      PGRN, printf(TR("%d FIREWALL RULES UPDATED :)"), rules_updated), PNL;
	    printf(TR("Saving rules on file..."));
	    if(save_rules() < 0)
	      PRED, printf(TR("Error saving rules!")), PNL;
	    else
	      printf("\tOK" NL);
	  }
	prompt_return_to_menu();
	break;				
      case 'p': /* print user defined rules */
      case 'P':
	print_my_rules();
	prompt_return_to_menu();
	break;
				
    case CTRL_B:
    	stop_printing();

	if(uops.dns_resolver)
	{
		if(blocked_sites_management(uops.blacksites_filename) > 0)
		{
			if(kill(resolver_pid, SIGUSR1) < 0)
			          PRED, perror(TR("Error notifying refresher" )), PNL;
		}
	}
	else
	{
		PNL, PRED, printf(TR("The refresher is not active! Start IPFIREwall with the -dns N option,"));  
		printf("\n"), printf(TR("where N is the refresh interval, in seconds.") ), PNL,  PNL;
	}
	prompt_return_to_menu();

    break;
	      case CTRL_N:
		      printf(TR("Enabling state smart log")), PNL;
		      change_smart_log(SMART_STATE);
		      
		      
		      break;
	      case CTRL_L:
		      printf(TR("Disabling state smart log")), PNL;
		      change_smart_log(SMART_SIMPLE);
		      break;
    case CTRL_T:
		PNL; printf(TR("Saving rules...")); PTAB;
	if(( ret = save_rules() ) < 0)
	  PRED, printf(TR("FAILED")), PNL;
	else
	  printf(TR("done")), PCL,
		 printf(TR(". Saved %d rules."), ret), PNL;
	break;
					
      case 'w':
	if(uops.dns_resolver)
	{
		if(kill(resolver_pid, SIGUSR1) < 0)
	  		PRED, perror(TR("Error notifying refresher" )), PNL;
	}
	else
	{
		stop_printing();
		PNL, PRED, printf("The refresher is not active! Start IPFIREwall with the -dns N option."); PNL, PNL;
		prompt_return_to_menu();
	}
	break;					
      case CTRL_R:
	/* reload rules */
	if(update_all_rules() < 0)
	  printf(TR("ERROR UPDATING RULES!")), PNL;
	break;
					
      case 'L':
      case 'l':
	if(send_command_to_listener("netlink_stats") < 0)
	  PRED, printf(TR("Error sending netlink stats request!" )), PNL;
	usleep(50000); /* wait while listener prints stats */
	prompt_return_to_menu();
	break;
					
      case 'v':
      case 'V':
		PGRN, printf(TR("Verbose modality enabled. ")); PNL;
	       printf(TR("Press ")); printf(UNDERL GREEN "S" CLR); 
	       printf(TR(" to switch to silent modality." )), PNL;
	       build_loguser_enabled_command(&cmd_toggle_loguser, START_LOGUSER);
	       send_command_to_kernel(&cmd_toggle_loguser);
	
	break;
				
      case 's':
      case 'S':
	PNL, PGRN, printf(TR("Silent modality enabled.")); PCL;
	       printf(TR("Press ")); printf(UNDERL GREEN "v" CLR);
      	   printf(TR(" to switch to verbose modality again.")), PNL;
	   build_loguser_enabled_command(&cmd_toggle_loguser, STOP_LOGUSER);
	   send_command_to_kernel(&cmd_toggle_loguser);

	break;
				
	case '-':
		PNL, PGRN;
		printf(TR("Silent modality with kernel/user communication still enabled.")), PNL;
		printf(TR("Press '+' to restore the verbose modality.") ), PNL; 
		send_command_to_listener("quiet");
		break;
	case '+':
		PNL, PGRN;
		printf(TR("Press '-' to restore the silent modality.") ), PNL; 
		printf(TR("Use 's' and 'v' to toggle between silent and verbose modality")), PNL;
		printf(TR("by stopping and re-enabling kernel/user communication (more efficient!)")), PNL;
		send_command_to_listener("verb");
		break;
      case F1:
      case 'h':
      case 'H':
      case '1':
	send_command_to_listener("quiet");
	print_help();
	prompt_return_to_menu();
	break;
				
      case '?':
	send_command_to_listener("quiet");
	print_sysinfo();
	prompt_return_to_menu();
	break;
				
      case 'C':
      case 'c':
	send_command_to_listener("quiet");
	get_user_info( USERNAME, username);
	printf(NL BLUE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
	printf(TR("User ")); printf(GREEN UNDERL "%s" CLR "." NL NL,username);				
	print_configuration_options();
	printf(NL BLUE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
	prompt_return_to_menu();
	printf(NL BLUE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
	break;
				
      case 'b':
	PNL; printf(TR("- Disabling port resolution.")); PNL;
	send_command_to_listener("noservcs");
	printf(TR("- Print 'u' to enable port resolution.")), PNL;
	resolve_services = 0;
	break;
				
      case 'u':
	PNL; printf(TR("- Enabling port resolution.")); PNL;
	send_command_to_listener("servcs");
	resolve_services = 1;
	printf(TR("- Print 'b' to disable port resolution.")), PNL;
	break;
				
      case F7:
      case '7':
	send_command_to_listener("quiet");
	printf(NL BLUE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
	PNL, printf(TR("- Requesting ")); printf(UNDERL "kernel" CLR); 
	       printf(TR(" firewall statistics...")), PNL;
	memset(&firestats, 0, sizeof(firestats) );
	if(request_kstats() < 0)
	  PRED, printf(TR("Failed to send statistics request to kernel firewall!")), PNL, PNL;
	if(receive_kstats(&firestats) < 0)
	  PRED, printf(TR("Failed to read statistics from kernel firewall!" )), PNL, PNL;
	print_kstats(&firestats);
	prompt_return_to_menu();
	printf(NL BLUE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
	break;
				
	case 'm':
	case 'M':
		send_command_to_listener("quiet");
		PNL; PUND, PYEL, PTAB, PTAB, PTAB;
		printf(TR("MAILER OPTIONS" )), PNL, PNL;
		init_mailopts(&mailopts);
		if(get_mail_options(uops.mailer_options_filename, &mailopts) 
				 < 0)
			PRED, printf(TR("Error getting mailer options from file \"%s\"!"),
					 uops.mailer_options_filename);
		print_mail_options(&mailopts, &uops);
		printf(NL NL);
		prompt_return_to_menu();
	break;

	/* The filter, since v 0.98.6 */
	case 'f':
	case 'F':
	
		stop_printing();
		if(str_filter != NULL) /* A filter was already defined and not cleared */
			free(str_filter);
		/* Allocate a new string for the filter */	
		str_filter = setup_filter_pattern();
		if(str_filter == NULL)
		{
			PRED, printf(TR("Error setting up the filter string!" ) ), PNL;
			break;
		}
		char cmd[MAXFILTERLINELEN + 10];
		sprintf(cmd, "filter:%s", str_filter);
		send_command_to_listener(cmd); /* send the whole string over the pipe */
		/* The son will build the structure from this string */
		filter_enabled = 1;
		break;

	case 'z':
	case 'Z':
		send_command_to_listener("remove_filter");
		prompt_return_to_menu();
		filter_enabled = 0;
		if(str_filter != NULL)
		{
			free(str_filter);
			str_filter = NULL;
		}
	break;
	case 'k':
	case 'K':
		send_command_to_listener("print_filter");
		prompt_return_to_menu();
	break;
      default:
				
	break;
      }
			
  }while( (scelta != 'q') & (scelta != ESC) );
  return 0;
}

int get_new_rule(ipfire_rule* r)
{
  char addr[MAXLINELEN];
  char port[MAXLINELEN];
  int scelta;
  int mss;
  init_rule(r);
  /* set owner */
  r->owner = getuid();
	
 get_kindarule:
  /* depending on owner, there are two possibilities */
  if(r->owner != 0)
    printf(TR("IS THIS A PERMISSION [p] OR DENIAL RULE [d] ?")), PNL;
  else /* root can add translation rules */
    printf(TR("IS THIS A PERMISSION RULE")), printf("\t[p]\n"),
	printf(TR("        A DENIALE RULE")), printf("\t\t[d]\n"),
	printf(TR("        A SOURCE NAT RULE")), printf("\t[s]\n"),
	printf(TR("        A DESTINATION NAT RULE")), printf("\t[t]\n"),
	printf(TR("        A MASQUERADE RULE")), printf("\t[m] ?");
  if(r->owner != 0)
    printf(NL GRAY "[p, d] " CLR);
  else
    printf(NL GRAY "[p, d, s, t, m] " CLR);
	
  scelta =  g_getchar();
	
  if(set_kinda_rule(scelta, r) < 0)
    goto get_kindarule;
	
 get_direction:
  if(getuid() == 0)
    PNL, printf(TR("INSERT THE ")), PUND, PGRN, printf(TR("DIRECTION")), PCL, 
	   printf(TR(" THE RULE AFFECTS") ), printf("\n[in | out | fwd | pre | post]: ");
  else
    PNL, printf(TR("INSERT THE ")), PUND, PGRN, printf(TR("DIRECTION")), PCL, 
	   printf(TR(" THE RULE AFFECTS") ), printf("\n[in | out | fwd]: ");
	
  if(get_direction(r) < 0)
    goto get_direction;
	
 get_protocol:
  PNL; printf(TR("CHOOSE ")); PGRN, PUND,printf(TR("PROTOCOL")); printf( CLR ": "  
	 "[tcp | udp | icmp | igmp]" NL);
  if(get_in_protocol(r) < 0)
    goto get_protocol;
	
 get_in_device:  /* device */
  if( (r->direction == IPFI_INPUT) ||
      (r->direction == IPFI_INPUT_PRE) ||
      (r->direction == IPFI_FWD) ) 
    {
      printf(TR("SPECIFY THE ")); PGRN, PUND; printf(TR("INPUT DEVICE")); printf(CLR); 
	     printf(TR(" RELATED TO THE RULE: "));
      if(get_device(r, INDEV) < 0 )
	goto get_in_device;
    }
	
 get_out_device:
  if( (r->direction == IPFI_OUTPUT) ||
      (r->direction == IPFI_OUTPUT_POST) ||
      (r->direction == IPFI_FWD) ) 
    {
      printf(TR("SPECIFY THE ")); PGRN, PUND; printf(TR("OUTPUT DEVICE")); printf(CLR); 
	     printf(TR(" RELATED TO THE RULE: "));
      if(get_device(r, OUTDEV) < 0 )
	goto get_out_device;
    }
	
 get_sip:   /* ip parameters */
  PNL, PGRN, printf(TR("- IP PARAMETERS: ")), PNL;
  printf(TR("SOURCE ADDRESS: "));
  if( get_in_address(addr, r, SOURCE, r->direction) < 0)
    goto get_sip;
  struct in_addr ia;
  ia.s_addr = r->ip.ipsrc[0];
//   printf("%s e' %x\n", inet_ntoa(ia), ntohl(r->ip.ipsrc[0] ));
	
 get_dip:
  printf(TR("DESTINATION ADDRESS: "));
  if(get_in_address(addr, r, DEST, r->direction) < 0)
    goto get_dip;
	
 ip_layer:
  PNL; printf(TR("ARE YOU INTERESTED IN SPECIFYING OTHER "));
   PUND; printf("IP LAYER"); PNL;
	 printf(TR("SPECIFIC PARAMETERS (TOS, TOTAL LENGTH) [y | n]? [n] "));
  scelta = char_translation( g_getchar() );
  if( (scelta == 's') | (scelta == 'y') )
    {
      if(get_ip_specific_parameters(r) < 0)
	goto ip_layer;
    }
	
  if( (r->ip.protocol == IPPROTO_TCP) || 
      (r->ip.protocol == IPPROTO_UDP) ||
       (r->nflags.proto == 0 ) )
    {
	  PNL, PNL, PGRN;
      printf(TR("- TRANSPORT LEVEL PARAMETERS: ")), PNL;
		
    get_sport:
      PNL, printf(TR("SOURCE PORT: ") );
      if(get_in_port(port, r, SOURCE) < 0)
	goto get_sport;
		
    get_dport:
      PNL, printf(TR("DESTINATION PORT: ") );
      if(get_in_port(port, r, DEST) < 0)
	goto get_dport;
      if(ntohs(r->tp.dport[0]) == 21)
	ask_if_ftp_support(r);
    }
 get_xxx_params: /* tcp specific parameters */
  if(r->ip.protocol == IPPROTO_TCP)
    {
      PNL, printf(TR("ARE YOU INTERESTED IN SPECIFYING OTHER ")), PUND, 
	     printf(TR("TRANSPORT LAYER")), PNL,
	     printf(TR("SPECIFIC PARAMETERS (FLAGS: SYN, ACK, RST ... ) [y | n]? [n]"));
      scelta = char_translation( g_getchar() );
      if( (scelta == 's') || (scelta == 'y') )
	{
	  if(get_tcp_specific_parameters(r) < 0)
	    goto get_xxx_params;
	}
	
      PNL, printf(TR("ARE YOU INTERESTED IN CHANGING MSS_VALUE OF TCP CONNECTIONS [y | n]? [n]"));
      scelta = char_translation( g_getchar() );
      if( (scelta == 's') || (scelta == 'y') )
      {
	if(get_mss_parameters(r) < 0)
	  goto get_xxx_params;
      }
    }
  else if(r->ip.protocol == IPPROTO_ICMP)
    {
	  PNL, printf(TR("ARE YOU INTERESTED IN SPECIFYING OTHER ")), PUND, 
	     printf(TR("ICMP")), PNL,
	     printf(TR("SPECIFIC PARAMETERS (TYPE, CODE..) [y | n]? "));
      scelta = char_translation( g_getchar() );
      if( (scelta == 's') | (scelta == 'y') )
	{
	  if(get_icmp_specific_parameters(r) < 0)
	    goto get_xxx_params;
	}
    }
    /* no options supported for protocol IGMP */
  /* source nat */
 get_nat:
  if( (r->nflags.policy == TRANSLATION) &&
      (r->snat) && (r->nat) )
    {
      if(get_nat_parameters(r, SOURCE_NAT) < 0)
	goto get_nat;
    }	
  /* destination nat */
  else if( (r->nflags.policy == TRANSLATION) &&
	   (r->nat) )
    {
      if(get_nat_parameters(r, DEST_NAT) < 0)
	goto get_nat;
    }		
  /* masquerade */
  else if((r->nflags.policy == TRANSLATION) &&
	  (r->masquerade) )
    {
      if(get_masquerade_parameters(r) < 0)
	goto get_nat;
    }
  if(r->nflags.policy == ACCEPT) /* stateful rules only for permission ones. */
    {
      printf(NL), 
      	printf(TR("DO YOU WANT THIS RULE TO BE STATEFUL [y|n]? ") );
      if(char_translation( g_getchar() ) == 'y' )
      {
	r->state = 1;
	printf(TR(" yes.")), PNL;
      }
      else 
      {
	r->state = 0;
	printf(TR(" no.")), PNL;
      }
    }
#ifdef ENABLE_RULENAME
 get_name:		
  PNL; printf(TR("GIVE RULE A SIMPLE NAME [MAX 20 CHARS]: "));
  if(get_in_rule_name(r) < 0)
    {
      PNL, PRED, printf(TR("Bad rule name: too long!" )), PNL, PNL;
      goto get_name;
    }		
#endif
  return 0;
}

void ask_if_ftp_support(ipfire_rule* r)
{
  printf(TR("Do you want to enable ftp passive support?[y|n] "));
  if(char_translation( g_getchar() ) == 'y')
  {
	  PGRN, printf(TR(" yes")); printf(CLR "." NL);
    	r->nflags.ftp = 1;
  }
}

/* sets kind of rule to be inserted */
int set_kinda_rule(const int scelta, ipfire_rule *r)
{
  printf(NL);
  switch(scelta)
    {
    case 'p':
      PGRN, printf(TR("PERMISSION RULE:"));  PNL;
      r->nflags.policy = ACCEPT;
      break;
		
    case 'd':
      PRED, printf(TR("DENIAL RULE:")), PNL;
      r->nflags.policy = DENIAL;
      break;
		
    case 's':
      printf(TR("SOURCE NETWORK ADDRESS TRANSLATION:")), PNL;
      r->nflags.policy = TRANSLATION;
      r->snat = 1;
      r->nat = 1;
      break;
		
    case 't':
      printf(TR("DESTINATION NETWORK ADDRESS TRANSLATION RULE:")), PNL;
      r->nflags.policy = TRANSLATION;
      r->nat = 1;
      break;
		
    case 'm':
      printf(TR("MASQUERADE RULE (a sort of SNAT):")), PNL;
      r->nflags.policy = TRANSLATION;
      r->masquerade = 1;
      break;
		
    default:
      return -1;
    }
  return 0;
}

int get_direction(ipfire_rule* r)
{
  char direction[MAXLINELEN];
  int ret;
	
  if( (ret = get_line(direction)) < 0)
    {
      PRED, printf(TR("Bad direction \"%s\"."), direction), PNL;
      return -1;
    }
  else if( (ret == 0) & (r->nflags.policy == TRANSLATION) )
    {
      PRED, printf(TR("Direction is mandatory in translation rules!" )), PNL;
      return -1;
    }
	
  if( (r->nflags.policy == ACCEPT) | (r->nflags.policy == DENIAL) )
    {
      if(! strncmp(direction, "in", 2) )
	r->direction = IPFI_INPUT;
      else if(! strncmp(direction, "out", 3) )
	r->direction = IPFI_OUTPUT;
      else if(! strncmp(direction, "fwd", 3) )
	r->direction = IPFI_FWD;
      else
	  {
		PRED, printf(TR("Error: direction is mandatory!")), PNL;
		  return -1;
	  }
    }
  else if( (r->nflags.policy == TRANSLATION) && (r->nat) &&
	   (!r->snat) )
    {	
      if(! strncmp(direction, "pre", 3) )	
	r->direction = IPFI_INPUT_PRE;
      else if(! strncmp(direction, "out", 3) )
	r->direction = IPFI_OUTPUT;
      else
	{
	  PRED, printf(TR("Bad direction \"%s\"."), direction), printf("\n" DRED);
		 printf(TR("Destination nat can be applied to ")); 
		 printf(UNDERL "pre-routing" CLR DRED); printf(TR(" and"));  
		 printf(UNDERL "output" CLR DRED ); 
		 printf(TR(" directions only.")); PNL;
	  return -1;
	}		
    }
  else if( (r->nflags.policy == TRANSLATION) &&  ( ( (r->nat) && 
	   (r->snat) ) || (r->masquerade) ) )
    {
	  PNL;
      printf(TR("Source network address translation is applied to "));
	  printf(UNDERL GREEN "post routing" CLR );
	  printf(TR(" direction automatically."));
	  PNL;
      r->direction = IPFI_OUTPUT_POST;
    }
  return 0;
}

int get_device(ipfire_rule* r, int direction)
{
  char device[IFNAMSIZ];
  int len;
	
  fgets(device, IFNAMSIZ, stdin);
  if( (len = strlen(device) ) == 1) /* only newline */
    return 0;
  else if(len > 1) /* we delete endline */
    device[strlen(device) - 1] = '\0';
  /* null terminate string anyway */
  device[IFNAMSIZ - 1] = '\0';
  if(direction == INDEV)
    {
      strncpy(r->devpar.in_devname, device, IFNAMSIZ);
      r->nflags.indev = 1;
    }
  if(direction == OUTDEV)
    {
      strncpy(r->devpar.out_devname, device, IFNAMSIZ);
      r->nflags.outdev = 1;
    }
  return 0;
}

/* asks user which protocol regards new rule */
int get_in_protocol(ipfire_rule *r)
{
  int ret = -1;
  char proto[MAXLINELEN];
  if((ret = get_line(proto) ) < 0)
    return -1;
  else if(ret == 0)
  {
	  r->nflags.proto = 0;
	  PVIO, printf(TR("Warning: protocol not specified.")), PNL;
	  printf(TR("Rule will apply to all protocols."));
	  PNL;
	  return 0;
  }
  if((strncmp(proto, "tcp", 3) == 0) || ((strncmp(proto, "TCP", 3) == 0)))
   	r->ip.protocol = IPPROTO_TCP;
  else if((strncmp(proto, "udp", 3) == 0) || ((strncmp(proto, "UDP", 3) == 0)))
	r->ip.protocol = IPPROTO_UDP;
  else if((strncmp(proto, "icmp", 4) == 0) ||((strncmp(proto, "ICMP", 4) == 0)))
	r->ip.protocol = IPPROTO_ICMP;
  else if((strncmp(proto, "igmp", 4) == 0) ||((strncmp(proto, "IGMP", 4) == 0)))
	r->ip.protocol = IPPROTO_IGMP;
  else
    {
      PRED, printf(TR("Protocol \"%s\" not valid!"), 
	     proto), PNL;
      return -1;
    }
  r->nflags.proto = 1;
  return 0;
}

/* fills in rule ipsrc or ipdst fields, depending on the  direction
 * specified. Returns -1 on error, 0 if address does not have 
 * to be specified, 1 in case of success. Direction in this case
 * is SOURCE or DEST, hook is IPFI_INPUT, IPFI_OUTPUT... */
int get_in_address(char* addr, ipfire_rule* r, int direction, int hook)
{
  int ret;
  struct in_addr ina, ina2;
	
  if( (ret = get_line(addr) ) < 0)
    return -1;
  else if(ret == 0)
    return 0;
	
  if(strcmp(addr, "any") == 0)
    return 0;
	
  if(strlen(addr) == 0)
    return -1;
	
  if(addr[0] == '!') /* address different from */
    {
      remove_exclmark(addr);
      printf(TR("selected not addr: \"%s\""), addr), PNL;
      if(strcmp(addr, "me") == 0)
	{
	  if(set_myaddr_flags(r, direction, DIFFERENT_FROM, hook) < 0)
	    return -1;
	  return 1;
	}
		
      /* is_cidr, in ipfire_userspace.c, finds if
       * addr is expressed in the form 
       * x.y.z.w/a.b.c.d or x.y.z.w/n. cidr_to_interval(),
       * transforms cidr notation in interval notation */
      if( is_cidr(addr) == 1 )
	{
	  if(cidr_to_interval(addr) < 0)
	    return -1;
	}
		
      if(is_interval(addr) )
	{
	  if(fill_not_ip_interval(addr, r, direction) < 0)
	    return -1;
			
	  if( (r->nflags.src_addr) & (r->parmean.samean ==
				      INTERVAL_DIFFERENT_FROM) & (direction == SOURCE ))
	    {
	      ina.s_addr = r->ip.ipsrc[0];
	      ina2.s_addr = r->ip.ipsrc[1];
	      printf(TR("IP SRC NOT IN INTERVAL %s"),
		    inet_ntoa(ina));
	      printf(" - %s\n", inet_ntoa( ina2) );
	    }
	  else if( (r->nflags.dst_addr) & (r->parmean.damean ==
					   INTERVAL_DIFFERENT_FROM) & (direction == DEST) )
	    {
	      ina.s_addr = r->ip.ipdst[0];
	      ina2.s_addr = r->ip.ipdst[1];
	      printf(TR("IP DST NOT IN INTERVAL %s"),
		     inet_ntoa(ina));
	      printf(" - %s\n", inet_ntoa( ina2) );
	    }
	}
      else
	{
	  if(fill_not_ip(addr, r, direction) < 0)
	    return -1;
	}
      return 1;
    }
	
  if(strcmp(addr, "me") == 0)
    {
      if(set_myaddr_flags(r, direction, SINGLE, hook) < 0)
	return -1;
      return 1;
    }
	
  if(is_cidr(addr) )
    if(cidr_to_interval(addr) < 0)
      return -1;
	
  if(is_interval(addr) )
    {
      if(fill_ip_interval(addr, r, direction) < 0)
	return -1;
      return 1;
    }
  else 
    {
      if(fill_plain_address(addr, r, direction) < 0)
	return -1;
    }
  return 1;
}

int get_ip_specific_parameters(ipfire_rule* r)
{
  u8 tos = 0;
  u16 totlen;
  char line[MAXLINELEN];
  PNL, printf(TR("INSERT AN INTEGER REPRESENTING TYPE OF SERVICE: "));
  if(get_line(line) < 0)
    return -1;
  totlen = (u8) atoi (line);
  if( check_tos(tos) < 0)
    return -1;
  r->ip.tos = tos;
	
  PNL, printf(TR("INSERT AN INTEGER REPRESENTING THE TOTAL LENGTH: "));
  if(get_line(line) < 0)
    return -1;
  totlen = (u16) atoi (line);
  if(check_totlen(totlen) < 0)
    return -1;
  r->ip.total_length = totlen;
  return 0;
}

/* checks if tos value is permitted. Returns 0 on success,
 * -1 otherwise */
int check_tos(u8 tos)
{
  return 0;
}

/* checks if total length value is permitted. Returns 0 on success,
 * -1 otherwise */
int check_totlen(u16 total_length)
{
  return 0;
}

/* fills in rule source port or destination port fields,
 * depending on the  direction specified. 
 * Returns -1 in case of error, 0 if no port is specified,
 * 1 if port is specified and correct */
int get_in_port(char* port, ipfire_rule* r, int direction)
{
	int ret;
	
	if( (ret = get_line(port) ) < 0)
		return -1;
	else if(ret == 0)
		return 0;
	
	if(strcmp(port, "any") == 0)
		return 0;

	if(strlen(port) == 0)
		return -1;
	
	if(port[0] == '!') /* address different from */
	{
		remove_exclmark(port);
		
		if(is_interval(port) )
		{
			if(fill_not_port_interval(port, r, direction) < 0)
				return -1;
		}
		else
		{
			if(fill_not_port(port, r, direction) < 0)
				return -1;
		}
		return 1;
	}
	else if(is_interval(port) )
	{
		if(fill_port_interval(port, r, direction) < 0)
			return -1;
		return 1;
	}
	else 
	{
		if(fill_plain_port(port, r, direction) < 0)
			return -1;
	}
	return 1;
}


int get_tcp_specific_parameters(ipfire_rule* r)
{
  int scelta;
  printf(NL);
  /* SYN */
  PNL, PGRN, printf(TR("SYN FLAG MUST BE: ACTIVE [a or 1],  OFF [o or 0],")), PNL,
	 printf(TR("DON'T CARE [other]: ") );
  scelta = char_translation( g_getchar() );
  switch(scelta)
    {
    case 'a':
    case '1':
      r->nflags.syn = 1;
      r->tp.syn = 1;
      PGRN, printf(TR("SYN ACTIVE")), PNL;
      break;
		
    case 'o':
    case '0':
      r->nflags.syn = 1;
      r->tp.syn = 0;
      PRED, printf(TR("SYN OFF")); PNL;
      break;
		
    case 'e':
      return 0;
		
    default:
      r->nflags.syn = 0;
      PGRAY, printf(TR("DON'T CARE ABOUT SYN.")), PNL;
      break;
    }
  /* ACK */
  PNL, PGRN, printf(TR("ACK FLAG MUST BE: ACTIVE [a or 1],  OFF [o or 0],")); PNL;
  printf(TR("DON'T CARE [other], DONE, EXIT [e]: "));
  scelta = char_translation( g_getchar() );
  switch(scelta)
    {
    case 'a':
    case '1':
      r->nflags.ack = 1;
      r->tp.ack = 1;
      PGRN, printf(TR("ACK ACTIVE")), PNL;
      break;
		
    case 'o':
    case '0':
      r->nflags.ack = 1;
      r->tp.ack = 0;
      PRED, printf(TR("ACK OFF")); PNL;
      break;
		
    case 'e':
      return 0;
		
    default:
      r->nflags.ack = 0;
      PGRAY, printf(TR("DON'T CARE ABOUT ACK.")), PNL;
      break;
    }
  /* URG */
  PNL, PGRN, printf(TR("URG FLAG MUST BE: ACTIVE [a or 1],  OFF [o or 0],")); PNL;
  printf(TR("DON'T CARE [other], DONE, EXIT [e]: "));
  scelta = char_translation( g_getchar() );
  switch(scelta)
    {
    case 'a':
    case '1':
      r->nflags.urg = 1;
      r->tp.urg = 1;
      PGRN, printf(TR("URG ACTIVE")), PNL;
      break;
		
    case 'o':
    case '0':
      r->nflags.urg = 1;
      r->tp.urg = 0;
      PRED, printf(TR("URG OFF")); PNL;
      break;
		
    case 'e':
      return 0;
		
    default:
      r->nflags.urg = 0;
      PGRAY, printf(TR("DON'T CARE ABOUT URG.")), PNL;
      break;
    }
  /* PSH */
  PNL, PGRN, printf(TR("PUSH FLAG MUST BE: ACTIVE [a or 1],  OFF [o or 0],")); PNL;
  printf(TR("DON'T CARE [other], DONE, EXIT [e]: "));
  scelta = char_translation( g_getchar() );
  switch(scelta)
    {
    case 'a':
    case '1':
      r->nflags.psh = 1;
      r->tp.psh = 1;
      PGRN, printf(TR("PSH ACTIVE")), PNL;
      break;
		
    case 'o':
    case '0':
      r->nflags.psh = 1;
      r->tp.psh = 0;
      PRED, printf(TR("PSH OFF")); PNL;
      break;
		
    case 'e':
      return 0;
		
    default:
      r->nflags.psh = 0;
      PGRAY, printf(TR("DON'T CARE ABOUT PSH.")), PNL;
      break;
    }
  /* RST */
  PNL, PGRN, printf(TR("RESET FLAG MUST BE: ACTIVE [a or 1],  OFF [o or 0],")); PNL;
  printf(TR("DON'T CARE [other], DONE, EXIT [e]: "));
  scelta = char_translation( g_getchar() );
  switch(scelta)
    {
    case 'a':
    case '1':
      r->nflags.rst = 1;
      r->tp.rst = 1;
      PGRN, printf(TR("RST ACTIVE")), PNL;
      break;
		
    case 'o':
    case '0':
      r->nflags.rst = 1;
      r->tp.rst = 0;
      PRED, printf(TR("RST OFF")); PNL;
      break;
		
    case 'e':
      return 0;
		
    default:
      r->nflags.rst = 0;
      PGRAY, printf(TR("DON'T CARE ABOUT RST.")), PNL;
      break;
    }
  /* FIN */
  PNL, PGRN, printf(TR("FIN FLAG MUST BE: ACTIVE [a or 1],  OFF [o or 0],")); PNL;
  printf(TR("DON'T CARE [other], DONE, EXIT [e]: "));
  scelta = char_translation( g_getchar() );
  switch(scelta)
    {
    case 'a':
    case '1':
      r->nflags.fin = 1;
      r->tp.fin = 1;
      PGRN, printf(TR("FIN ACTIVE")), PNL;
      break;
		
    case 'o':
    case '0':
      r->nflags.fin = 1;
      r->tp.fin = 0;
      PRED, printf(TR("FIN OFF")); PNL;
      break;
		
    case 'e':
      return 0;
		
    default:
      r->nflags.fin = 0;
      PGRAY, printf(TR("DON'T CARE ABOUT FIN.")), PNL;
      break;
    }
  return 0;
}

/* gets MSS_VALUE */
int get_mss_parameters(ipfire_rule *r)
{
    int scelta;
    int mss;
    int ret;
    PNL, printf(TR("DO YOU WANT TO SPECIFY A VALUE [v] OR LET THE FIREWALL AUTOMATICALLY ADJUST IT TO PMTU [a] ? [a]"));
    scelta = char_translation( g_getchar() );
    if(scelta == 'v')
    {
      printf(TR("TYPE AN INTEGER VALUE FOR THE Maximum Segment Size (max 1500 - 40 = 1460): "));
      ret = scanf("%d", &mss);
      while(getchar() != '\n');
      if(ret <= 0)
      {
	printf(TR("INVALID INTEGER")); PNL;
	return -1;
      }
      if(mss > 1460 || mss <= 0)
      {
	printf(TR("MSS_VALUE MUST BE GREATER THAN 0 AND LESS THAN OR EQUAL TO 1460"));
	return -1;
      }
      else
      {
	r->pkmangle.mss.mss = mss;
	r->pkmangle.mss.enabled = 1;
	r->pkmangle.mss.option = MSS_VALUE;
      }
      
    }
    else /* scelta != v : automatic mss */
    {
      r->pkmangle.mss.enabled = 1;
      r->pkmangle.mss.option = ADJUST_MSS_TO_PMTU;
    }
    return 0;
}

int get_icmp_specific_parameters(ipfire_rule *r)
{
  int ret;
  char line[MAXLINELEN];
  PNL, PNL, printf(TR("SPECIFY ICMP TYPE: "));
  if( (ret = get_line(line) ) < 0)
    return -1;
  else if(ret > 0)
    {
      r->icmp_p.type = (u8) atoi(line);
      r->nflags.icmp_type = 1;
    }
  printf(TR("ICMP CODE: "));
  if( (ret = get_line(line) ) < 0)
    return -1;
  else if(ret > 0)
    {
      r->icmp_p.code = (u8) atoi(line);
      r->nflags.icmp_code = 1;
    }
  return 0;
}

/* writes a command on pipe shared between main
 * interface and listener (son) and then signals listener
 * that there is a message for it */
int send_command_to_listener(const char* com)
{
  extern int pipefd[2];
  extern pid_t listener_pid;

  if(write(pipefd[1], com, strlen(com)+1 ) < 0)
    PRED, perror(TR("send_command_to_listener(): error writing to pipe")), PCL;
  else
    kill(listener_pid, SIGUSR1);
  return 0;
}

/* invoked by listener when packet loss happens.
 * It disables verbose printing, re-enabling it
 * if 'v' key is pressed */
void quiet_modality(int quiet)
{
  if(! quiet)
    {
      printf(VIOLET UNDERL); printf(TR("WARNING")); PCL;
	  printf(TR(": printing packets has been disabled for now:")); PNL;
	  printf(TR("         high network traffic/low resources on machine"));  PNL;
	  printf(TR("         caused packet loss from kernel/user communication.")); PNL;
	  printf(TR("         Press "));  printf(GREEN "'v'" CLR);
	  printf(TR("key to re-enable verbose printing.")); PNL;
      quiet = 1;
    }
}

/* enables quiet modality */
void stop_printing(void)
{
  if(send_command_to_listener("quiet") < 0)
    PRED, printf(TR("stop_printing(): error sending command ") ), PNL;
}

/* prints rules in user vector, not all those
 * loaded in firewall. Those printed are personal
 * rules */
int print_my_rules(void)
{
  extern ipfire_rule* denial_rules;
  extern ipfire_rule* accept_rules;
  extern ipfire_rule* translation_rules;	
  extern int den_rules_num;
  extern int acc_rules_num; 
  extern int transl_rules_num;
  ipfire_rule_filter *filter = NULL;;
  char *str_filter = NULL;
	
  stop_printing();

  /* Ask the user to setup a visualization filter */
  str_filter = setup_filter_pattern();
  if(str_filter == NULL)
	  printf(TR("Errore allocating the string for the filter!\n"));
  else
  {
  	filter = setup_filter(str_filter);
	if(filter == NULL)
		PVIO, PUND,  printf(TR("No filter will be applied.") ); PNL;
  	free(str_filter); /* we do not need the string any more: we now have "filter" */
  }
  print_rules(denial_rules, den_rules_num, filter);
  print_rules(accept_rules, acc_rules_num, filter);
  if(getuid() == 0)
    {
      print_rules(translation_rules, transl_rules_num, filter);
   }
  if( (getuid() != 0) && (!opts.user_allowed) )
    PVIO, printf(TR(" ! RULES SHOULD NOT BE LOADED:")),
	printf(TR("   USER DOES NOT SEEM TO BE ALLOWED TO INSERT HIS OWN RULES.")),
	PNL, printf(TR("   CHECK WITH F3 AND CONTACT ADMINISTRATOR.")),
	PNL;

  if(filter != NULL)
	  free_filter_rule(filter);
  return 0;
}

/* parent prints kernel statistics after a stats 
 * request. */
void print_kstats(const struct kernel_stats* ks)
{
  float lost_percent = 0;
  float perc_in_drop = 0;
  float perc_in_drop_impl = 0;
  float perc_out_drop = 0;
  float perc_out_drop_impl = 0;
  float perc_fwd_drop = 0;
  float perc_fwd_drop_impl = 0;
  float perc_in_acc_impl = 0;
  float perc_out_acc_impl = 0;
  float perc_fwd_acc_impl = 0;
  
  /* hours, minutes, seconds and days */
  double hours, mins, days;
  time_t current_time;
  double secs_difftime;
	
  unsigned long long total = 0;
	
  total = ks->in_rcv + ks->out_rcv + ks->fwd_rcv +
    ks->pre_rcv + ks->post_rcv;
	
  /* update percentage */
  if( total != 0)
    lost_percent = (float) 
      ( ( ( (float) ks->total_lost / (float) total) ) * 100);
  else
    lost_percent = 0;
	
  PNL, PRED, PTAB, PTAB;
  printf(TR("* STATISTICS FROM ")); printf(UNDERL "KERNEL" CLR RED);
  printf(TR(" POINT OF VIEW *")), PNL, PNL;
	
  printf(TR("Kernel module has been loaded since %s"), ctime(&ks->kmod_load_time) );
  
  /* Calculate current time and the number of seconds elapsed between kernel module
   * loading time and now. Then calculate corresponding hours, minutes and seconds.
   */
  time(&current_time);
  secs_difftime = difftime(current_time, ks->kmod_load_time);
  
  hours = secs_difftime/(3600);
  mins = secs_difftime/60;
  days = secs_difftime/(3600 * 24);
  
  printf(TR("Policy being applied to packets not matching any rule: "));
  if(ks->policy == 0)
	  PRED, printf(TR("drop")), printf( CLR "." NL);
  else
	  PGRN, printf(TR("accept")), printf( CLR "." NL);
  PNL, PGRN;
  printf(TR("SUMMARY ON PACKETS ")); PUND; printf(TR("PROCESSED"));
	 printf(CLR GREEN); printf(TR(" BY ")); printf(UNDERL "KERNEL" CLR);
	 PGRN; printf(":" NL NL);
	 
	 printf("- INPUT: \t%llu\t", ks->in_rcv); 
	 printf(TR("[%.2f/day %.2f/h %.2f/min %.2f/s]"), ks->in_rcv/days, ks->in_rcv/hours, 
		ks->in_rcv/mins, ks->in_rcv/secs_difftime );   PNL;
	 
	 printf("- OUTPUT: \t%llu\t", ks->out_rcv); 
	 printf(TR("[%.2f/day %.2f/h %.2f/min %.2f/s]"), ks->out_rcv/days, ks->out_rcv/hours, 
		ks->out_rcv/mins, ks->out_rcv/secs_difftime );   PNL;
	 
	 printf("- FORWARD: \t%llu\t", ks->fwd_rcv); 
	 printf(TR("[%.2f/day %.2f/h %.2f/min %.2f/s]"), ks->fwd_rcv/days, ks->fwd_rcv/hours, 
		ks->fwd_rcv/mins, ks->fwd_rcv/secs_difftime );   PNL;
	 
	 printf( "- PRE ROUTING: \t%llu\t", ks->pre_rcv);
	 printf(TR("[%.2f/day %.2f/h %.2f/min %.2f/s]"), ks->pre_rcv/days, ks->pre_rcv/hours, 
		ks->pre_rcv/mins, ks->pre_rcv/secs_difftime );   PNL; 
	 
	 printf( "- POST ROUTING: %llu\t" , ks->post_rcv); 
	 printf(TR("[%.2f/day %.2f/h %.2f/min %.2f/s]"), ks->post_rcv/days, ks->post_rcv/hours, 
		ks->post_rcv/mins, ks->post_rcv/secs_difftime );   PNL; 
	 
  printf("                ----\n");
  printf(TR("- TOTAL:")); PTAB; printf("%llu\t", total); 
  printf(TR("[%.2f/day %.2f/h %.2f/min %.2f/s]"), total/days, total/hours, 
	 total/mins, total/secs_difftime );
  PNL; PNL;
	
  /* INPUT */
  if(ks->in_rcv != 0)
    {
      perc_in_drop = (float) ks->in_drop / (float) ks->in_rcv * 100;
      perc_in_drop_impl = (float) ks->in_drop_impl / (float) ks->in_rcv * 100;
      perc_in_acc_impl = (float) ks->in_acc_impl / (float) ks->in_rcv * 100;
		
      PCL; printf(TR("INPUT PACKETS")); 
      PRED, printf(TR(" DROPPED")); PCL;
	  printf(": %llu [%.1f%%]." NL,
		ks->in_drop, perc_in_drop);
	
	  PCL; printf(TR("INPUT PACKETS")); 
	  PGRN, printf(TR(" ACCEPTED")); PCL;
	  printf(": %llu [%.1f%%]." NL, 
	     ks->in_rcv - ks->in_drop, (float) 100 - perc_in_drop);
      
      if(ks->in_drop_impl > 0)
	      printf(TR("INPUT PACKETS DROPPED ")),
	    	PVIO, printf(TR("IMPLICITLY")), PNL, 
				printf(TR("[WITH DEFAULT POLICY]: %llu [%.1f%%]."), ks->in_drop_impl,
      				perc_in_drop_impl), PNL, PNL;  
	  
      if(ks->in_acc_impl > 0)
	      printf(TR("INPUT PACKETS ACCEPTED ")),
	    	PVIO, printf(TR("IMPLICITLY")), PNL, 
				printf(TR("[WITH DEFAULT POLICY]: %llu [%.1f%%]."), ks->in_acc_impl,
      			perc_in_acc_impl);  
    }
	
  /* OUTPUT */
  if(ks->out_rcv != 0)
    {
      perc_out_drop = (float) ks->out_drop / (float) ks->out_rcv * 100;
      perc_out_drop_impl = (float) ks->out_drop_impl / (float) ks->out_rcv * 100;
      perc_out_acc_impl = (float) ks->out_acc_impl / (float) ks->out_rcv * 100;
		
      PCL; printf(TR("OUTPUT PACKETS")); 
	  PRED, printf(TR(" DROPPED"));  PCL;
	  printf(": %llu [%.1f%%]." NL, ks->out_drop, perc_out_drop);
	
      PCL; printf(TR("OUTPUT PACKETS")); 
	  PGRN, printf(TR(" ACCEPTED")); PCL;
	  printf(": %llu [%.1f%%]." NL, 
	     ks->out_rcv - ks->out_drop, (float) 100 - perc_out_drop);	
      
      if(ks->out_drop_impl > 0)
	      printf(TR("OUTPUT PACKETS DROPPED ")),
	    	PVIO, printf(TR("IMPLICITLY")), PNL, 
				printf(TR("[WITH DEFAULT POLICY]: %llu [%.1f%%]."), ks->out_drop_impl,
      			perc_out_drop_impl), PNL, PNL; 
	  
      if(ks->out_acc_impl > 0)
	      printf(TR("OUTPUT PACKETS ACCEPTED ")),
	    	PVIO, printf(TR("IMPLICITLY")), PNL, 
				printf(TR("[WITH DEFAULT POLICY]: %llu [%.1f%%]."), ks->out_acc_impl,
      			perc_out_acc_impl), PNL, PNL;  
    }
	
  /* FORWARD */
  if(ks->fwd_rcv != 0)
    {
      perc_fwd_drop = (float) ks->fwd_drop / (float) ks->fwd_rcv * 100;
      perc_fwd_drop_impl = (float) ks->fwd_drop_impl / (float) ks->fwd_rcv * 100;
      perc_fwd_acc_impl = (float) ks->fwd_acc_impl / (float) ks->fwd_rcv * 100;
		
      PCL; printf(TR("FORWARD PACKETS")); 
	  PRED, printf(TR(" DROPPED"));  PCL;
	  printf(": %llu [%.1f%%]." NL,
		ks->fwd_drop, perc_fwd_drop);
	
      PCL; printf(TR("FORWARD PACKETS")); 
	  PGRN, printf(TR(" ACCEPTED") ); PCL;
	  printf(": %llu [%.1f%%]." NL, 
	     ks->fwd_rcv - ks->fwd_drop, (float) 100 - perc_fwd_drop);	
      
      if(ks->fwd_drop_impl > 0)
	      printf(TR("FORWARD PACKETS DROPPED ")),
	    	PVIO, printf(TR("IMPLICITLY")), PNL, 
				printf(TR("[WITH DEFAULT POLICY]: %llu [%.1f%%]."), ks->fwd_drop_impl,
      			perc_fwd_drop_impl), PNL, PNL; 
      
      if(ks->fwd_acc_impl > 0)
	      printf(TR("FORWARD PACKETS ACCEPTED ")),
	    	PVIO, printf(TR("IMPLICITLY")), PNL, 
				printf(TR("[WITH DEFAULT POLICY]: %llu [%.1f%%]."), ks->fwd_acc_impl,
      			perc_fwd_acc_impl), PNL, PNL; 
    }
		
  PNL, printf(TR("- Packets ")), PUND, PGRN,printf(TR("sent")), PCL, 
  printf(TR(" to user firewall: %llu."), ks->sent_tou), PNL;
  
  printf(TR("- Packets ")), PUND, PVIO, printf(TR("not sent")), PCL, 
  printf(TR(" to user firewall: %llu."), total - ks->sent_tou), PNL;	

  printf(TR("- Packets ")), printf(DVIOLET UNDERL), printf(TR("not sent")),
  PCL, printf(TR(" to user firewall due to kernel/user log level: %llu."), ks->not_sent);
  PNL;
  
  printf(TR("- Packets ")), PUND, PRED, printf(TR("lost")), PCL,
  printf(TR(" while sending towards userspace: %llu"), 
	 ks->total_lost), PNL;
	
  printf(TR("- Packets ")), PUND, PRED, printf(TR("lost")), PCL,
  printf(TR(" towards userspace over total packets sent: %llu/%llu [%.2f %%]"),
	 ks->total_lost, ks->sent_tou, lost_percent);
  PNL;
  if(ks->pre_rcv != 0)
	  PNL, printf(TR("- Pre routing nat checks found %d packets with errors"),
		      ks->bad_checksum_in); PNL;
	  printf(TR("  over %llu arrived (bad checksum). [%.2f %%]"), ks->pre_rcv,
	   (float) ks->bad_checksum_in / (float) ks->pre_rcv * (float) 100), PNL;
	
  printf(GRAY "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
	
}

/* listener prints statistics regarding netlink communication */
void print_stats(struct netlink_stats* ns)
{
  /* update percentage */
  if( ns->sum_now != 0)
    ns->percentage = (float) 
      ( ( ( (float) ns->total_lost / (float) ns->sum_now) ) * 100);
  else
    ns->percentage = 0;
	
  printf(GRAY "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
  PTAB, PRED, printf(TR("STATISTICS FROM "));
  PUND; printf(TR("USERSPACE FIREWALL")); PCL; PRED; 
	 printf(TR(" POINT OF VIEW")); PCL; PNL; PNL;
	
  PGRN, printf(TR("SUMMARY ON PACKETS ")), PUND; printf(TR("PROCESSED"));
  PCL, PGRN, printf(TR(" BY ")); printf(UNDERL "KERNEL" CLR GREEN ":" NL);
  printf("- INPUT: \t%llu\n"
	 "- OUTPUT: \t%llu\n"
	 "- FORWARD: \t%llu\n"
	 "- PRE ROUTING: \t%llu\n"
	 "- POST ROUTING: %llu\n",
	 ns->in_rcv, ns->out_rcv, ns->fwd_rcv, ns->pre_rcv, ns->post_rcv);
	
  PNL, PUND, PTAB, PTAB, printf(TR("IN THIS SESSION:")), PNL;
  PNL, printf(TR("- Packets ")), PUND, PGRN, printf(TR("received")); PCL;
  printf(TR(" from kernel firewall: %lu."), ns->last_pre_rcv+
	 ns->last_in_rcv + ns->last_out_rcv + ns->last_fwd_rcv+
	 ns->last_post_rcv), PNL;
  printf(TR("- Packets ")), PUND, PVIO, printf(TR("not sent"));
  PCL, printf(TR(" by kernel firewall due to loglevel: %d."), 
	 ns->not_sent_nor_lost), PNL;
  printf(TR("- Packets ")); PUND; PRED, printf(TR("lost")), PCL,
  printf(TR(" in kernel/user communication: %lu"), ns->total_lost); 
  PGRAY, printf(TR(" (not lost by firewall ;)"));
  PNL, printf(TR("- Packets ")); PUND, PRED, printf(TR("lost")), PCL,
  printf(TR(" over total packets received: %lu/%lu [%.2f %%]"),
	 ns->total_lost, ns->sum_now, ns->percentage), PNL;
	
  printf(GRAY "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" NL);
}

/* asks user to press a key, then sends to listener
 * a command to enable printing */
int prompt_return_to_menu(void)
{
  extern struct cmdopts prog_ops;
  PNL, printf(TR("Press any key to return to main menu...")), PNL;
  g_getchar();
  /* restore verbose modality only if options were not quiet */
  if(prog_ops.quiet == 0)
    {
      if(send_command_to_listener("verb") < 0)
	{
	  PRED, printf(TR("prompt_return_to_menu(): error sending enable printing command"));
	  PNL;
	  return -1;
	}
    }
  return 0;
}

int check_port(int p)
{
  return 
    ( (p < 65536) && (p > 0) );
}


/* fills in new address and port for translation. Returns -1 in
 * case of errors, 0 otherwise */
int get_nat_parameters(ipfire_rule* r, int nat_kind)
{
  char addr[INET_ADDRSTRLEN];
  struct in_addr ina;
  int ret;
  int port;
	
  if(nat_kind == SOURCE_NAT)
    {		
      PNL, PGRN, printf(TR("SOURCE NETWORK ADDRESS TRANSLATION: ")), PNL, PNL;
      printf(TR("NEW SOURCE IP ADDRESS: "));
    }
  else if(nat_kind == DEST_NAT)
    {		
      PNL, PGRN, printf(TR("DESTINATION NETWORK ADDRESS TRANSLATION: ")), PNL, PNL;
      printf(TR("NEW DESTINATION IP ADDRESS: "));
    }	
	
  if( (ret = get_line(addr) ) < 0)
    return -1;
  else if(ret == 0)
    goto getport;
	
  if(inet_pton(AF_INET, addr, &ina) <= 0)
    {
      PRED, perror(TR("get_snat_parameters(): error in address")), PCL;
      return -1;
    }
  /* fill in new value */
  r->newaddr = ina.s_addr;
  r->nflags.newaddr = 1;
	
 getport:
  if(nat_kind == SOURCE_NAT)
    PNL, printf(TR("NEW SOURCE PORT: "));
  else if(nat_kind == DEST_NAT)
    PNL, printf(TR("NEW DESTINATION PORT: "));
	
  if( (ret = get_line(addr) ) < 0)
    return -1;
  else if(ret == 0)
    return 0;
	
  port = atoi(addr);
	
  if(check_port(port) < 0)
    {
      PRED, printf(TR("Value not permitted for port. Ports must be"));
	  PNL, printf(TR("between %d and %d.") , MINPORT, MAXPORT), PNL;
      return -1;
    }
	
  r->newport = (__u16) htons(port);
  r->nflags.newport = 1;
	
  return 0;
	
}

int get_masquerade_parameters(ipfire_rule* r)
{
	
  if(!r->nflags.outdev)
    {
      PVIO, printf(TR("MASQUERADE:")), PNL;
	  printf(TR("YOU SHOULD SPECIFY THE OUTPUT DEVICE TO MASQUERADE: ")), PNL;
      if(get_device(r, OUTDEV) < 0)
	{
	  PNL, PNL, PRED, printf(TR("get_masquerade_parameters(): error getting device name!")),
		PNL;
	  return -1;
	}
    }
  /* if we have not device name now, we disable masquerade */
  if(!r->nflags.outdev)
    {
      PRED, printf(TR("I CAN'T MASQUERADE AN UNSPECIFIED OUTPUT INTERFACE!")); PNL;
      return -1;
    }
  return 0;
}

void print_sysinfo(void)
{
  struct utsname sysinfo;
  if (uname(&sysinfo) < 0)
    perror(RED "uname() error" CLR);
  printf
    ("\n\e[0;35m- - - - - - - - - - - - TABELLA INFORMAZIONI - - - - - - - - - - - - \e[0;37m\n");
  printf("Sistema operativo:\t\t%s.\n", sysinfo.sysname);
  printf("Nome del dominio:\t\t%s.\n", sysinfo.nodename);
  printf("Versione del kernel:\t\t%s.\n", sysinfo.release);
  printf("Tipo di macchina:\t\t%s.\n", sysinfo.machine);
  printf(NL GRAY "Versione di IPFIRE userspace:   %s \"" UNDERL "%s"
	 GRAY "\".\n", VERSION, CODENAME);
  printf(GRAY "Descrizione: %s" NL, DESCRIPTION);
  printf(GRAY "Build %s on %s" NL, USPACE_BUILD_DATE, USPACE_BUILD_SYS);
  printf(GRAY "Latest kernel version supported: \"%s\"" NL NL, LATEST_KERNEL_SUPPORTED);
  printf(GRAY "(C) " " %s " GRAY "%s\n" , AUTHOR, AUTHOR_MAIL );
  printf(CLR GRAY "%s\n", FIREDATE);
  printf(GRAY "Free software! :)" NL NL);
}

#ifdef ENABLE_RULENAME
int get_in_rule_name(ipfire_rule* r)
{
  char name[MAXLINELEN];
  int ret;
	
  if( (ret = get_line(name) ) < 0)
    return -1;
	
  else if(ret == 0)
    return ret;
	
  if(strlen(name) >= RULENAMELEN)
    return -1;
	
  strncpy(r->rulename, name, RULENAMELEN);
	
  return 1;
}


int blocked_sites_management(const char* filename)
{
	FILE *fp;
	int i = 0, nlines = 0, ret;
	short modified = 0, saved = 0;
	int scelta = '0', xline, scelta2;
	char input[MAXLINELEN]; /* MAXLINELEN because we use get_line */
	char **names = NULL, **list_updated, **tmpnames;
	char tmpname[1024];

	fp = fopen(filename, "r");
	if(fp == NULL)
	{
		PRED, printf(TR("Error opening file \"%s\" for reading "));
		perror(""), PNL, PNL;
		return -1;
	}

	while(fgets(tmpname, 1024, fp) != NULL)
	{
		if(strlen(tmpname) > 1 && tmpname[0] != '#' && tmpname[0] != '\n')
			nlines++;
	}
	/* Allocate the necessary number of lines */
	names = (char **) malloc(sizeof(char *) * nlines);
	if(names == NULL )
	{
		PRED, printf(TR("Error allocating memory for the blocked sites list "));
		perror(""), PNL;
		return -1;
	}
	
	rewind(fp);

	while(fgets(tmpname, 1024, fp) != NULL && i < nlines)
	{
		if(strlen(tmpname) > 1 && tmpname[0] != '#' && tmpname[0] != '\n')
		{
			names[i] = (char*) malloc(sizeof(char) * (strlen(tmpname) + 1) );
			if(names[i] == NULL)
			{
				PRED, printf(TR("Error allocating memory for the blocked site entry no %d "), i + 1);
				perror(""), PNL;
				free(names);
				return -1;
			}
			strncpy(names[i], tmpname, strlen(tmpname) + 1);
			i++;
		}
	}
	fclose(fp);

	i = 0;
	
	do{
		PNL;
		PRED, printf(TR("*** BLOCKED SITES ***")), PNL, printf(TR("choose:")), PNL;
		printf("- - - - - - - - - - - - - - -\n");
		if(nlines > 0)
		{
			printf(TR("L. List blocked sites.")), PNL;
			printf(TR("D. Remove a blocked site.")), PNL;
		}
		printf(TR("A. Add a new blocked site.")), PNL;
		if(modified)
		{
			printf(TR("X. Exit without saving.")), PNL;
			printf(TR("S. Save.") ), PNL;
		}
		else
			printf(TR("X. Exit.") ), PNL;
		printf("- - - - - - - - - - - - - - -\n");

		scelta = g_getchar();
		switch(scelta)
		{
			case 'l':
			case 'L':
				if(nlines == 0 )
				{
					PNL, PVIO, printf(TR("The list is empty!") ), PNL, PNL;
					break;
				}
				PNL, PRED, printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~"), PNL;
				for(i = 0; i < nlines; i++)
					printf("[%d] %s", i + 1, names[i] );
				PRED, printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~"), PNL;
				break;
			case 'D':
			case 'd':
				if(nlines > 0)
				{
					printf(TR("Insert the number corresponding to the line you want to remove [%d-%d] [+return], "),
							1, nlines);
					PNL, printf(TR("or simply press `return` to cancel operation: "));

					if( (ret = get_line(input) ) < 0)
					{
						PRED, printf(TR("Error in the input value!")), PNL;
						break;
					}
					else if(ret == 0)
					{
						printf(YELLOW), printf(TR("Operation canceled!")), PNL;
						break;
					}
					else
					 	xline = atoi(input);

					if(xline < 1 || xline > nlines)
					{
						PRED, printf(TR("Number %d out of the range %d-%d!"), xline, 1, nlines);
						break;
					}
					else
					{
						PNL, printf(TR("Going to remove the line:  "));
						PRED , printf("%s", names[xline - 1] ), PCL, printf("... ");
						printf(TR("are you sure [y,n]? "));
						scelta2 = char_translation(g_getchar() );
						if(scelta2 == 'y')
						{
							list_updated = remove_line(names, nlines, xline);
							if(list_updated == NULL)
								PRED, printf(TR("An error occurred while removing an entry, so it won't be removed!") ),
									PNL;
							else
							{
								/* Update the copy */

								/* 1 Free the original  list */
								for(i = 0; i < nlines; i++)
									free(names[i] );
								free(names);

								PGRN, printf(TR("Ok, the site will be blocked.") ), PNL;
								printf(TR("Confirm by pressing the 's' key when finished") ), PNL, PNL;
								/* Operation successful: update the new number of lines */
								nlines--;
								names = list_updated;
								modified = 1;
							}
								
						}
						else
							PNL, printf(TR("Operation canceled!") ), PNL, PNL;
					}
				}
				else
					PNL, PRED, printf(TR("The list is empty!") ), PNL, PNL;

				break;

			case 's':
			case 'S':
				fp = fopen(filename, "w");
				if(fp == NULL)
				{
					PRED, printf(TR("Error opening the file %s for writing "), filename);
					perror(""), PNL;
					return -1;
				}
				
				i = 0;
				fprintf(fp, "# Put here Internet addresses you want to be blocked.\n"
						"# Comments are allowed: first character of the line must be '#'.\n"
						"#\n"
						"# Example:\n"
						"# www.badsite.com\n"
						"#\n"
						"#\n"
						"# File is read by IPFIREWALL 'resolver' if ipfire is started with option '-dns N',\n"
						"# where N is the interval in seconds after which names are refreshed.\n"
						"#\n"
						"# (C) Giacomo S.\n"
						"# june 2005 - march 2007 delleceste@gmail.com\n"
						"#\n" 
						"# Since version 0.98.4 this file can be managed by the main menu interface.\n"
						"# This is a recommended usage unless you have to paste a long list in this\n"
						"# file.\n"
						"# Have a nice time :)\n"
						"#\n");

				for(i = 0; i < nlines; i++)
					fprintf(fp, "%s", names[i]);

				fprintf(fp, "#\n# End of list.\n#\n");
				
				fclose(fp);
				/* file has been saved */
				modified = 0;
				saved = 1;
				break;
			
			case 'a':
			case 'A':
				PNL, printf(TR("Insert the name of the site you want to block"));
				PNL, PGRAY, printf(TR("for instance: www.example.com") ), PNL;
				PRED;
				if(fgets(tmpname, 1024, stdin) != NULL)
				{
					PNL; printf(TR("The web site"));
					PNL, PRED, printf("%s", tmpname);
					PCL, printf(TR("will be blocked. Are you sure [y|n]? ") );
					scelta2 = char_translation(g_getchar() );
					if(scelta2 == 'y')
					{
						tmpnames = (char **) malloc(sizeof(char *) * (nlines+1) );
						if(tmpnames == NULL)
						{
							PRED, printf(TR("Error allocating memory for a new block rule ") );
							perror("");
							PNL;
							return -1;
						}
						/* Copy the pointers of the dynamically allocated names */
						for(i = 0; i < nlines; i++)
							tmpnames[i] = names[i]; 
						/* Add the new rule */
						tmpnames[nlines] = (char *) malloc(sizeof(char) *( strlen(tmpname) + 1) );
						if(tmpnames[nlines] == NULL)
						{
							PRED, printf(TR("Error allocating memory for a new block rule ") );
							perror("");PNL;
							return -1;
						}
						strncpy(tmpnames[nlines], tmpname, strlen(tmpname) + 1);
						/* free old names vector... */
						free(names);
						/* ...and assign to it the new list... */
						names = tmpnames;
						PNL,PGRN, printf(TR("OK")); PNL;
						nlines++; /* ...which has one more element! */
						modified = 1;
					}
					else
						PNL, printf(TR("Operation canceled!") ); PNL;
				}
			}


	}while(scelta != 'x' && scelta != 'X' );

	for(i = 0; i < nlines; i++)
		free(names[i]);
	free(names);
	return saved;

}

char** remove_line(char **list, int nlines, int cancline)
{
	char **copy;
	int i = 0, j = 0, deleted = 0;
	copy = (char **) malloc(sizeof(char *) * nlines );
	if(copy == NULL)
	{
		PRED, printf(TR("Error allocating memory for the copy of the blocked list ") );
		perror(""), PNL;
		return NULL;
	}

	for(i = 0; i < nlines; i++)
	{
		copy[j] = (char *) malloc(sizeof(char) * strlen(list[i]) + 1);
		if(copy[j] == NULL)
		{
			PRED, printf(TR("Error allocating memory for the copy of the blocked list ") );
			perror(""), PNL;
			return NULL;
		}
		if(cancline < 1 || cancline > nlines)
		{
			PRED, printf(TR("remove_line(): Index out of range!") );
			free(copy);
			return NULL;
		}
		if(i != cancline -1 )
		{
			strncpy(copy[j], list[i], strlen(list[i]) + 1);
			j++;
		}
		else
			deleted++;
	}
	
	return copy;
}


#endif
