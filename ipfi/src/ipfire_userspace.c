/* Userspace functions, used by the interface to the kernel 
 * packet filter/translator. */
 
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



#include "includes/ipfire_userspace.h"
#include "includes/languages.h"
/* for constants SOURCE, DEST: */
#include "includes/interface.h" 
#include "includes/semafori.h"

unsigned int get_number_of_rules(FILE* fp)
{
  unsigned counter = 0;
  char line[MAXLINELEN];
  while(fgets(line, MAXLINELEN, fp) != NULL)
    {
      if( (strncmp(line, "RULE", 4) == 0) ||
	  (strncmp(line, "BSRULE", 4) == 0) )
	counter ++;
    }
  return counter;
}


/* sends a command structure to kernel netlink socket.
 * Returns -1 on failure, the number of bytes sent in case
 * of success.
 */
int send_command_to_kernel(const command * cmd)
{
  extern struct netl_handle *nh_control;
  int bytes_sent = 0;
  if( (bytes_sent = send_to_kernel((void *) cmd, nh_control, CONTROL_DATA) ) < 0)
    {
      libnetl_perror("send_command_to_kernel()" );
      return -1;
    } 
  /* each object to be sent is freed after being sent by send_to_kernel() */	
		
  return bytes_sent;
}

/* receives a command structure from kernel space, putting it 
 * in memory pointed by cmdrec. Returns -1 on failure, the
 * number of bytes read in case of success.
 */
int read_command_from_kernel(command* cmdrec)
{
  extern struct netl_handle *nh_control;
  int bytes_read = 0;
	
  if( (bytes_read = read_from_kern(nh_control, (unsigned char*) cmdrec, 
				   sizeof(command) ) ) < 0)
    {
      libnetl_perror(RED "read_command_from_kernel()");
      return -1; /* abort further reading */
    }
		
  return bytes_read;		
}

/* this one is called every time a command is sent to kernel.
 * Kernel verifies credentials and then sends an acknowledgement
 * before committing a command */
int wait_acknowledgement(void)
{
  command cmdack;
  if(read_command_from_kernel(&cmdack) < 0)
    {
      PRED, printf(TR("wait_acknowledgement(): error receiving ack from kernel!"));
      PNL;
	  return -1;
    }
  if(cmdack.cmd == ACKNOWLEDGEMENT)
    {
      return 1;
    }
  else
    {
		PRED, printf(TR("Bad ACKNOWLEDGEMENT value (%d) (Should be 50)!"),
	      cmdack.cmd);
	  PNL;PNL;
      return -1;
    }
}


int send_rules_to_kernel(ipfire_rule* rules,  int nrules)
{
  int i, bytes_read;
  ///// RIMOSSO extern struct cmdopts prog_ops;
  command cmd, cmd_ack;
	
		
  for(i=0; i < nrules; i++)
    {
      init_command(&cmd);
      build_rule_command(&cmd);
      /* now copy the rule at position i in the appropriate field of cmd */
      memcpy(&cmd.content.rule, &rules[i], sizeof(ipfire_rule) );
		
      /* send rule to kernel */
      if(send_command_to_kernel(&cmd) < 0)
	{
	  printf(RED "send_rules_to_kernel(): error sending rule %d to kernel!" 
		 NL, i+1);
	  return -1;
	}

      /* after sending the rule in kernel space, we wait for an acknowledgment */
      if( (bytes_read = read_command_from_kernel( &cmd_ack ) ) < 0)
	{
	  libnetl_perror(RED "Error getting acknowledgment from kernel!\n");
	  return -1; /* abort further reading */
	}
      else
	{
	  if(cmd_ack.cmd == RULE_ALREADY_PRESENT)
	  {
	    printf(RED "- - - - - - - - RULE %d ALREADY LOADED! - - - - - - - - - -" NL,
		   cmd_ack.content.rule.position);
	    print_rules(&rules[i], 1, NULL);
	  }
	  else if(cmd_ack.cmd == RULE_NOT_ADDED_NO_PERM)
	    printf(RED "RULE NOT ADDED: YOU DON'T HAVE THE PERMISSION\n"
		   "TO ADD RULES TO FIREWALL. CONTACT ADMINISTRATOR.\n" NL);
			
	  // RIMOSSO con iqfire!
	  /////////////prog_ops.user_allowed = cmd.user_allowed;
	}
    }
  return 0;
}


/* depending on direction, this function sets flags on rule
 * so that src/dst addresses will be chosen by kernel.
 * Note that only in input or output direction this option
 * is correct. */
int set_myaddr_flags(ipfire_rule* r, int direction, int meaning, int hook)
{
  switch(hook)
    {
    case IPFI_INPUT:
    case IPFI_OUTPUT:
      if(direction == SOURCE)
	{
	  r->nflags.src_addr = MYADDR;
	  r->parmean.samean = meaning;
	}
      else if(direction == DEST)
	{
	  r->nflags.dst_addr = MYADDR;
	  r->parmean.damean = meaning;
	}
      return 0;
		
    default:
      printf(RED "\"me\" can be set only in INPUT or OUTPUT directions!"
	     NL);
      return -1;
    }
}


int parse_rulefile_and_fill(FILE* fp, ipfire_rule* ipfr, int whichfile)
{
  unsigned ruleno = 0;
  unsigned linenum = 0;
  int i = 0;
  char line[MAXLINELEN];
  char key[MAXLINELEN];
  short next_policy_is_blacksite = 0;
	
#ifdef ENABLE_RULENAME
  char rulename[RULENAMELEN];
#endif
  struct in_addr address;
  ipfire_rule arule;
  short protocol;
  short tyos;
  u16 total_len;
  u16 sport;
  u16 dport;
  char devicename[IFNAMSIZ];
  init_rule(&arule);
  while(fgets(line, MAXLINELEN, fp) != NULL)
    {
      linenum++;
      /* delete endline */
      if(strlen(line) > 0 && line[strlen(line)-1] == '\n')
	line[strlen(line)-1]='\0';
      /* start reading file */
      if(strncmp(line, "#", 1) == 0)
	;
      else if(strncmp(line, "INDEVICE=", 9) == 0)
	{
	  get_string(devicename, line);
	  strncpy(arule.devpar.in_devname, devicename, IFNAMSIZ);
	  arule.nflags.indev = 1;
	}
      else if(strncmp(line, "OUTDEVICE=", 10) == 0)
	{
	  get_string(devicename, line);
	  strncpy(arule.devpar.out_devname, devicename, IFNAMSIZ);
	  arule.nflags.outdev = 1;
	}
	 else if(strncmp(line, "_END_SRCADDR=", 13) == 0)
	{
	  if( arule.nflags.src_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.samean = INTERVAL;
	      arule.ip.ipsrc[1] = address.s_addr;
	    }
	  else
	    perror("Error getting source address from line");
	}
      else if(strncmp(line, "_END_SRCADDR_NOT=", 17) == 0)
	{
	  if( arule.nflags.src_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.samean = INTERVAL_DIFFERENT_FROM;
	      arule.ip.ipsrc[1] = address.s_addr;
	    }
	  else
	    perror("Error getting source address from line");
	}
      else if(strncmp(line, "MYSRCADDR", 9) == 0)
	{
	  if(arule.nflags.src_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.src_addr = MYADDR;	
	      arule.parmean.samean = SINGLE;
	    }					
	}
      else if(strncmp(line, "MYSRCADDR_NOT", 13) == 0)
	{
	  if(arule.nflags.src_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.src_addr = MYADDR;	
	      arule.parmean.samean = DIFFERENT_FROM;					
	    }					
	}
      else if(strncmp(line, "_END_DSTADDR=", 13) == 0)
	{
	  if(arule.nflags.dst_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.damean = INTERVAL;
	      arule.ip.ipdst[1] = address.s_addr;
	    }
	  else
	    perror("Error getting destination address from line");
	}
      else if(strncmp(line, "_END_DSTADDR_NOT=", 17) == 0)
	{
	  if(arule.nflags.dst_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.damean = INTERVAL_DIFFERENT_FROM;
	      arule.ip.ipdst[1] = address.s_addr;
	    }
	  else
	    perror("Error getting destination address from line");
	}
      /* let kernel select our interface address depending on
       * direction of packet */
      else if(strncmp(line, "MYDSTADDR", 9) == 0)
	{
	  if(arule.nflags.dst_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.dst_addr = MYADDR;
	      arule.parmean.damean = SINGLE;
	    }					
	}
      else if(strncmp(line, "MYDSTADDR_NOT", 13) == 0)
	{
	  if(arule.nflags.dst_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.dst_addr = MYADDR;
	      arule.parmean.damean = DIFFERENT_FROM;
	    }
	}
      else if(strncmp(line, "PROTOCOL=", 9) == 0)
	{
	  protocol = (short) get_integer(line);
	  /* [...] do some checkin' before assignment! */
	  arule.ip.protocol = protocol;
	  arule.nflags.proto = 1;
	}
      else if(strncmp(line, "TOTAL_LENGTH=", 13) == 0)
	{
	  total_len = (u16) get_integer(line);
	  /* [...] do some checkin' before assignment! */
	  arule.ip.total_length = total_len;
	  arule.nflags.tot_len = 1;
	}
      else if(strncmp(line, "TOS=", 4) == 0)
	{
	  tyos = (u8) get_integer(line);
	  /* [...] do some checkin' before assignment! */
	  arule.ip.tos = tyos;
	  arule.nflags.tos = 1;
	}
        else if(strncmp(line, "_END_SRCPORT=", 13) == 0)
	{
	  if(! arule.nflags.src_port)
	    goto error_nofirst_interval;
	  sport= htons( (u16) get_integer(line) );
	  arule.tp.sport[1] = sport;
	  /* [...] checks! */
	  arule.parmean.spmean=INTERVAL;
	}
      else if(strncmp(line, "_END_DSTPORT=", 13) == 0)
	{
	  if(! arule.nflags.dst_port)
	    goto error_nofirst_interval;
				
	  arule.tp.dport[1] = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.parmean.dpmean=INTERVAL;
	}
      else if(strncmp(line, "SYN=TRUE", 8) == 0)
	{
	  arule.nflags.syn=1;
	  arule.tp.syn = 1;
	}
      else if(strncmp(line, "FIN=TRUE", 8) == 0)
	{
	  arule.nflags.fin=1;
	  arule.tp.fin = 1;
	}
      else if(strncmp(line, "PSH=TRUE", 8) == 0)
	{
	  arule.nflags.psh=1;
	  arule.tp.psh = 1;
	}
      else if(strncmp(line, "ACK=TRUE", 8) == 0)
	{
	  arule.nflags.ack=1;
	  arule.tp.ack = 1;
	}
      else if(strncmp(line, "RST=TRUE", 8) == 0)
	{
	  arule.nflags.rst=1;
	  arule.tp.rst = 1;
	}
      else if(strncmp(line, "URG=TRUE", 8) == 0)
	{
	  arule.nflags.urg=1;
	  arule.tp.urg= 1;
	}
      /* false versions */
      else if(strncmp(line, "SYN=FALSE", 9) == 0)
	{
	  arule.nflags.syn=1;
	  arule.tp.syn = 0;
	}
      else if(strncmp(line, "FIN=FALSE", 9) == 0)
	{
	  arule.nflags.fin=1;
	  arule.tp.fin = 0;
	}
      else if(strncmp(line, "PSH=FALSE", 9) == 0)
	{
	  arule.nflags.psh=1;
	  arule.tp.psh = 0;
	}
      else if(strncmp(line, "ACK=FALSE", 9) == 0)
	{
	  arule.nflags.ack=1;
	  arule.tp.ack = 0;
	}
      else if(strncmp(line, "RST=FALSE", 9) == 0)
	{
	  arule.nflags.rst=1;
	  arule.tp.rst = 0;
	}
      else if(strncmp(line, "URG=FALSE", 9) == 0)
	{
	  arule.nflags.urg=1;
	  arule.tp.urg= 0;
	}	
      /* icmp related */
      else if(strncmp(line, "ICMP_TYPE=", 10) == 0)
	{
	  arule.nflags.icmp_type = 1;
	  arule.icmp_p.type = (u8) get_integer(line);
	}
      else if(strncmp(line, "ICMP_CODE=", 10) == 0)
	{
	  arule.nflags.icmp_code = 1;
	  arule.icmp_p.code = (u8) get_integer(line);
	}
      else if(strncmp(line, "ICMP_ECHO_ID=", 12) == 0)
	{
	  arule.nflags.icmp_echo_id = 1;
	  arule.icmp_p.echo_id = (u16) get_integer(line);
	}
      else if(strncmp(line, "ICMP_ECHO_SEQ=", 13) == 0)
	{
	  arule.nflags.icmp_echo_seq= 1;
	  arule.icmp_p.echo_seq = (u16) get_integer(line);
	}
      /* frag mtu removed */
      /* direction of the packet */
      else if(strncmp(line, "DIRECTION=INPUT", 15) == 0)
	arule.direction = IPFI_INPUT;
      else if(strncmp(line, "DIRECTION=OUTPUT", 16) == 0)
	arule.direction = IPFI_OUTPUT;
      else if(strncmp(line, "DIRECTION=FORWARD", 17) == 0)
	arule.direction = IPFI_FWD;
      else if(strncmp(line, "DIRECTION=POST", 14) == 0)
	arule.direction = IPFI_OUTPUT_POST;
      else if(strncmp(line, "DIRECTION=PRE", 13) == 0)
	arule.direction = IPFI_INPUT_PRE;
      /* state connection tracking / nat / masquerading options */
      else if(strncmp(line, "KEEP_STATE=YES", 14) == 0)
	 arule.state = arule.nflags.state  = 1;
      else if(strncmp(line, "FTP_SUPPORT=YES", 14) == 0)
	arule.nflags.ftp = 1;
      else if(strncmp(line, "NOTIFY=YES", 14) == 0)
	      arule.notify = 1;
      else if(strncmp(line, "NAT=YES", 7) == 0)
	arule.nat = 1;
      else if(strncmp(line, "SNAT=YES", 8) == 0)
	{
	  arule.nat = 1;
	  arule.snat = 1;
	}
      else if(strncmp(line, "MASQUERADE=YES", 14) == 0 )
	{
	  arule.masquerade = 1;
	}
      else if(strncmp(line, "NOTIFY=YES", 10) == 0)
		arule.notify = 1;
      else if(strncmp(line, "NATURAL_LANGUAGE=YES", 20) == 0)
		arule.natural = 1;
      else if(strncmp(line, "NEWADDR=", 8) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.newaddr = 1;
	      arule.newaddr = address.s_addr;
	    }
	  else
	    perror("Error getting source address from line");
	}
      else if(strncmp(line, "NEWPORT=", 8) == 0)
	{
	  arule.newport = htons( (u16) get_integer(line) );
	  arule.nflags.newport = 1;
	}
      /*
       * packet mangling options 
       */
      else if(strncmp(line, "MSS_VALUE=TO_PMTU", 8) == 0)
      {
	arule.pkmangle.mss.enabled = 1;
	arule.pkmangle.mss.option = ADJUST_MSS_TO_PMTU;
      }
      else if(strncmp(line, "MSS_VALUE=", 4) == 0)
      {
	if(arule.ip.protocol == IPPROTO_TCP)
	{
	  arule.pkmangle.mss.enabled = 1;
	  arule.pkmangle.mss.option = MSS_VALUE;
	  arule.pkmangle.mss.mss = (u16) get_integer(line);
	}
	else
	  printf(TR("MSS_VALUE mangle option is only available for TCP protocol"));
      }
      else if(strncmp(line, "NAME=", 5) == 0)
	{
#ifdef ENABLE_RULENAME
	  get_rule_name(line, rulename);
	  strncpy(arule.rulename, rulename, RULENAMELEN);
#else  /* warn user */
	  printf(VIOLET "WARNING" CLR ": option \"NAME\" is disabled.\n"
		 "If you want to enable it, you must compile IPFIRE with\n"
		 "option \"ENABLE_RULENAME\", " UNDERL RED "both" NL
		 "in userspace program and in kernel modules. See manual\n"
		 "for further explanation." NL );
#endif
	}
     /* Start parsing lines which might indicate multiple values */
     /* ============================================== */
     /* source address(es) */
     i = 0;
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "SRCADDR%d=" : "SRCADDR="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.src_addr = ONEADDR;
	      arule.ip.ipsrc[i] = address.s_addr;
	     if(i > 0)
	      {
		arule.parmean.samean = MULTI;
		struct in_addr ina;
		ina.s_addr = arule.ip.ipsrc[i];
// 		printf("multiple source address: element %d: %s\n", i, inet_ntoa(ina));
	      }
	    }
	  else
	    perror("Error getting source address from line");
	}
	i++;
     }
     i = 0;
     /* destination address(es) */ 
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "DSTADDR%d=" : "DSTADDR="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.dst_addr = ONEADDR;
	      arule.ip.ipdst[i] = address.s_addr;
	      if(i > 0)
	      {
		arule.parmean.damean = MULTI;
// 		struct in_addr ina;
// 		ina.s_addr = arule.ip.ipdst[i];
// 		printf("multiple destination address: element %d: %s\n", i, inet_ntoa(ina));
	      }
	    }
	  else
	    perror("Error getting destination address from line");
	}	
	i++;
     }
     i = 0;
     /* destination address(es), "different from" */ 
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "SRCADDR%d_NOT=" : "SRCADDR_NOT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  /* rimosso dalla versione MULTI */
// 	  if(arule.nflags.src_addr)
// 	    goto conflicting_parameters;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.src_addr = ONEADDR;
	      arule.ip.ipsrc[i] = address.s_addr;
	      if(i == 0)
		arule.parmean.samean = DIFFERENT_FROM;
	      else
	      {
		arule.parmean.samean = MULTI_DIFFERENT;
		struct in_addr ina;
		ina.s_addr = arule.ip.ipsrc[i];
// 		printf("multiple source addresses DIFFERENT FROM: element %d: %s\n", i, inet_ntoa(ina));
	      }
	    }
	  else
	    perror("Error getting source address from line");
	}
	i++;
     }
     i = 0;
     /* multiple destination addresses different from */
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "DSTADDR%d_NOT=" : "DSTADDR_NOT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.dst_addr = ONEADDR;
	      arule.ip.ipdst[i] = address.s_addr;
	      if(i == 0)
		arule.parmean.damean = DIFFERENT_FROM;
	      else
	      {
		arule.parmean.damean = MULTI_DIFFERENT;
// 		struct in_addr ina;
// 		ina.s_addr = arule.ip.ipdst[i];
// 		printf("multiple destination addresses DIFFERENT FROM: element %d: %s\n", i, inet_ntoa(ina));
	      }
	    }
	  else
	    perror("Error getting source address from line");
	}
	i++;
     }
     
     /* PORTS */
      i = 0;
     /* multiple source ports */
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "SRCPORT%d=" : "SRCPORT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  sport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.sport[i]=sport;
	  arule.nflags.src_port=1;
	  if(i > 0)
	  {
	    arule.parmean.spmean = MULTI;
// 	    printf("multiple source ports: element %d: %d\n", i, ntohs(sport));
	  }
	}
	i++;
     }
 
     i = 0;
     /* multiple destination ports */
     while(i < MAXMULTILEN)
     {
        snprintf(key, MAXLINELEN, (i > 0 ? "DSTPORT%d=" : "DSTPORT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  dport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.dport[i]=dport;
	  arule.nflags.dst_port=1;
	  if(i > 0)
	  {
	    arule.parmean.dpmean = MULTI;
// 	    printf("multiple destination ports: element %d: %d\n", i, ntohs(dport));
	  }
	}
	i++;
     }
     
     i = 0;
     /* multiple source ports different from */
     while(i < MAXMULTILEN)
     {
        snprintf(key, MAXLINELEN, (i > 0 ? "SRCPORT%d_NOT=" : "SRCPORT_NOT="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  sport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.sport[i]=sport;
	  arule.nflags.src_port=1;
	  if(i ==0)
	    arule.parmean.spmean = DIFFERENT_FROM;
	  else
	  {
	    arule.parmean.spmean = MULTI_DIFFERENT;
// 	    printf("multiple source ports different from: element %d: %d\n", i, ntohs(sport));
	  }
	}
	i++;
     }
     
     i = 0;
     /* multiple destination ports different from */
     while(i < MAXMULTILEN)
     {
        snprintf(key, MAXLINELEN, (i > 0 ? "DSTPORT%d_NOT=" : "DSTPORT_NOT="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  dport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.dport[i]=dport;
	  arule.nflags.dst_port=1;
	  if(i ==0)
	    arule.parmean.dpmean = DIFFERENT_FROM;
	  else
	  {
	    arule.parmean.dpmean = MULTI_DIFFERENT;
// 	    printf("multiple destination ports different from: element %d: %d\n", i, ntohs(dport));
	  }
	}
	i++;
     }
     /* Finished parsing multiple elements :P */
     /* ===================================== */
     
      /* Go on with last lines to look for */
      if(  ( (strncmp(line, "RULE", 4) == 0)  && ( ruleno > 0) ) ||
		( (strncmp(line, "BSRULE", 6) == 0)  && ( ruleno > 0) ) |
		( (strncmp(line, "END", 3) == 0)   && ( ruleno > 0) )   )   
	{
	  /* set the right policy, depending on the file we are parsing */			
	  /* if previously next_policy_is_blacksite was set */
	  if(next_policy_is_blacksite)
	    arule.nflags.policy = BLACKSITE;
	  else /* policy depends on file we are reading */
	    arule.nflags.policy = whichfile;
				
	  if(arule.direction != NODIRECTION)
	    arule.nflags.direction = 1;
	  else
	    arule.nflags.direction = 0;
	  /* is this a blacksite rule? If yes, modify policy */
	  if( (strncmp(line, "BSRULE", 6) == 0) &&
	      (whichfile == DENIAL) )
	    next_policy_is_blacksite = 1;
	  else
	    next_policy_is_blacksite = 0;
	  /* set the owner of the rule */
	  arule.owner = getuid();
	  if(arule.direction == NODIRECTION)
	    {
	      printf(RED "Error: parameter \"DIRECTION=OUTPUT|PRE|POST|INPUT|FORWARD\""
		     "\nnot specified and the rule is a nat/masquerading one!\n"
		     "I won't add any rule from this configuraton file!" NL);
	      printf(RED "RULE N. %d" NL, ruleno);
	      goto error;
					
	    }
	  //~ if(arule.ip.protocol != IPPROTO_TCP && 
	  //~ arule.ip.protocol != IPPROTO_UDP &&
	  //~ arule.ip.protocol != IPPROTO_ICMP) /* dummy protocol */
	  //~ {
	  //~ printf(RED "Error: parameter PROTOCOL not specified or not correct!" NL);
	  //~ printf(RED "RULE N. %d" NL, ruleno);
	  //~ goto error;
	  //~ }
	  /* put ruleno in vector, at position ruleno -1 */
	  arule.position = ruleno;  /* set the rule position, will start from 1 */
	  ipfr[ruleno - 1] = arule;
	  if(strncmp(line, "END", 3) == 0) /* found last rule */
	    return ruleno;  
	  init_rule(&arule);			/* reinitialize rule */
	  /* arule.position = ruleno;  aaaaaaaaaaaaaaaaahhhh */
	  arule.direction = 0;
	  arule.ip.protocol = IPPROTO_IP; /* dummy protocol */
	  ruleno++;
	}
      else if( (strncmp(line, "RULE", 4) == 0) && (ruleno == 0) ) 
	{
	  /* 1st rule declaration */
	  ruleno ++;
	  next_policy_is_blacksite = 0; /* 1st rule not a blacksite one */
	}
      else if( (strncmp(line, "BSRULE", 6) == 0) && (ruleno == 0) )
	{
	  ruleno ++;
	  next_policy_is_blacksite = 1; /* 1st rule blacksite */
	}				
      else if(strncmp(line, "POSITION", 8) == 0) /* no more used, but do not signal as an error... */
	printf(RED "Keyword \"%s\" at line %d not valid!" NL, line, linenum);
    }
  return 0; /* number of rules read if file is empty */
 error:
  return -1;
 error_nofirst_interval:
  printf(RED "You can't specify an end interval without first specifying\n"
	 "the first value of the interval itself! (line %d)" CLRNL,
	 linenum);
  return -1;
 conflicting_parameters:
  printf(RED "You specified a value for a parameter and now you mean\n"
	 "the opposite: bad! Check line %d." NL, linenum);
  return -1;
}

ipfire_rule * allocate_ruleset(int whichfile, int *number_of_rules)
{
  unsigned numrules=0;
  extern struct userspace_opts uops;
  extern int semid_lockfile;
	
  FILE* fprules;
  ipfire_rule* ipfire_rules;	/* vector of rules */
  char namefile[MAXFILENAMELEN];
  if(whichfile == DENIAL)
    strncpy(namefile, uops.blacklist_filename, MAXFILENAMELEN);
  else if(whichfile == ACCEPT)
    strncpy(namefile, uops.permission_filename, MAXFILENAMELEN);
  else if(whichfile == TRANSLATION)
    strncpy(namefile, uops.translation_filename, MAXFILENAMELEN);
  if(uops.dns_resolver)
    {
      while(sem_locked(semid_lockfile) )
	{
	  printf(VIOLET "Waiting for unlock on file...\n");
	  usleep(50000);
	}
      if(lock_sem(semid_lockfile) < 0)
	{
	  printf(RED "Error locking semaphore!" NL);
	  kill(getpid(), SIGINT);
	  return NULL;
	}
    }
  if( (fprules = fopen(namefile, "r") ) == NULL)
    {
      PRED, printf(TR("allocate_ruleset(): error opening ruleset file \"%s\"."),
		namefile);
      perror("");
      unlock_sem(semid_lockfile);
      return NULL;
    }
  /* we read a file one time to count the number of rules */
  numrules = get_number_of_rules(fprules);
  rewind(fprules);
  /* allocate necessary space to contain all rules */
  ipfire_rules = (ipfire_rule*) malloc(sizeof(ipfire_rule) * numrules);
  *number_of_rules = parse_rulefile_and_fill(fprules, ipfire_rules, whichfile);
  if(fclose(fprules) < 0)
    perror(TR("Error closing ruleset file.")), PNL;
  if(uops.dns_resolver)
    {
      if(unlock_sem(semid_lockfile) < 0)
		PRED, printf(TR("Error unlocking semaphore!")); PNL;
    }
  if(*number_of_rules == -1)  /* parse_ ... returned an error code */
    {
      printf(TR("Error, freeing memory.")), PNL;
      free(ipfire_rules);
      exit(EXIT_FAILURE);
    }
  if( (*number_of_rules != numrules) && (numrules > 0) )
    {
      printf(TR("Error! Number of rules mismatch [%d vs %d]! Strange!"),
		numrules, *number_of_rules);
	  PNL;
	  printf(TR("Freeing memory..."));
      free(ipfire_rules);
      exit(EXIT_FAILURE);
    }
  return ipfire_rules;
}

void get_proto_name(char* name, int pro)
{
  switch(pro)
    {
    case IPPROTO_ICMP:
      strncpy(name, "ICMP", 5);
      break;
   case IPPROTO_IGMP:
      strncpy(name, "IGMP", 5);
	break;
    case IPPROTO_TCP:
      strncpy(name, "TCP", 5);
      break;
    case IPPROTO_UDP:
      strncpy(name, "UDP", 5);
      break;
    default:
      strncpy(name, TR("UNSUPPORTED"), 12);
      break;
    }
}

/* Builds a command to stop or start the netlink communication 
 * between the kernel and the packet printing process in 
 * userspace. With this (version 0.98), there is no need to tell
 * the son process to stop printing: it will simply stop receiving
 * packets from the kernel space.
 */
int build_loguser_enabled_command(command *cmd, int enabled)
{
	memset(cmd, 0, sizeof(command) );
	cmd->is_rule = 0;
	/* not a rule, an option */
	cmd->options = 1;
	/* The passed value of enabled must be START_LOGUSER or
	 * STOP_LOGUSER, defined in ipfire_userspace.h
	 */
	cmd->cmd = enabled;
	return 0;
}

/* sends hello message to kernel space. Returns code
 * filed in by kernel in field command of coming back 
 * command */
int hello_handshake(command* cmdh)
{
  if(send_command_to_kernel(cmdh) < 0)
    {
      PNL, PRED, printf(TR("hello_handshake(): error sending hello."));
	  PNL;
      return -1;
    }
  if(read_command_from_kernel(cmdh) < 0)
    {
      printf(NL RED "hello_handshake(): error receiving hello ack." NL);
      return -1;
    }
  return cmdh->cmd;	
}






int send_goodbye(struct netl_handle* nh_control)
{
  command exit_cmd;
  init_command(&exit_cmd);
  exit_cmd.cmd = EXITING;
  if(nh_control == NULL)
    return -1;
  if(send_to_kernel( (void*) &exit_cmd, nh_control, CONTROL_DATA) < 0)
    {
      printf(RED "print_request(): ERROR SENDING GOODBYE TO KERNEL!" NL);
      return -1;
    }
  return 0;
}

/* sends a simple goodbye to kernel after a start 
 * failure */
int send_simple_goodbye(void)
{
  command simple_bye;
  init_command(&simple_bye);
  simple_bye.cmd = SIMPLE_GOODBYE;
  if(send_command_to_kernel(&simple_bye) < 0)
    return -1;
  return 0;
}

int firewall_busy(command* com)
{
  if(com->cmd == IPFIRE_BUSY)
    return -com->anumber;
  return 0;
}

/* when userspace program exits, it tells kernel and kernel sends
 * back a message reporting the number of rules flushed */
void print_kernel_userspace_exit_status(const command *exc, int rc_enabled)
{
  if(exc->cmd == ROOT_NOFLUSHED)
    ;
//     printf(TR("%d rules flushed: \"-noflush\" or \"-load\" or \"-rc\" option?"),
// 	   exc->anumber), PNL;
  else
    printf(TR("%d rules have been removed from firewall."),
	   exc->anumber), PNL;
}


/* manages saving all rules (3 vectors)
 * calls write_header() and write_rule()
 * to write each rule on each file */
int save_rules()
{
  extern ipfire_rule* denial_rules;
  extern ipfire_rule* accept_rules;
  extern ipfire_rule* translation_rules;
  extern int den_rules_num;
  extern int acc_rules_num;
  extern int transl_rules_num;
  extern struct userspace_opts uops;
  extern int semid_lockfile;
	
  ipfire_rule* rules = NULL;
  int rnum = 0;
	
  FILE* fp;
  int i = 0;
  int rulecount = 0;
  short whichfile = 0;
  char filename[MAXFILENAMELEN];
  if(uops.dns_resolver)
    {
      while(sem_locked(semid_lockfile) )
	{
	  printf(VIOLET "Waiting for unlock on file...\n");
	  usleep(50000);
	}
      if(lock_sem(semid_lockfile) < 0)
	{
	  PRED, printf(TR("Error locking semaphore!")); PNL;
	  return -1;
	}
    }
  /* DENIAL is 0 ... TRANSLATION is 2 */
  while(whichfile < 3)
    {
      if(whichfile == DENIAL) 
	{
	  strncpy(filename, uops.blacklist_filename, 
		  MAXFILENAMELEN);
	  rules = denial_rules;
	  rnum = den_rules_num;
	} 
      else if(whichfile ==  ACCEPT) 
	{  
	  strncpy(filename, uops.permission_filename, 
		  MAXFILENAMELEN);
	  rules = accept_rules;
	  rnum = acc_rules_num;
	}
      else if(whichfile == TRANSLATION)
	{
	  strncpy(filename, uops.translation_filename,
		  MAXFILENAMELEN);
	  rules = translation_rules;
	  rnum = transl_rules_num;
	}
		
      fp = fopen(filename, "w");
      if(fp == NULL)
	{
	  PRED, printf(TR("Error opening file: \"%s\""), filename);
	  perror("");
	  return -1;
	}
      /* write something on top of files to describe them */
      write_header(fp, whichfile);
		
      while(i < rnum)
	{
	  write_rule(fp, rules[i], i);
	  i++;
	}
      rulecount += i; 
      /* write the keyword "END" at end of rules */
      if(rnum > 0)
     	 fprintf(fp, "END");
      fclose(fp);
      fp = NULL;
      i = 0;
      whichfile ++;
	  /* We have saved allowed and blacklist: if we are not
	   * root we have finished */
	  if(whichfile == TRANSLATION && getuid() != 0)
		  break;
    } /* while */
  if(uops.dns_resolver)
    {
      if(unlock_sem(semid_lockfile) < 0)
		PRED, printf(TR("Error unlocking semaphore!")); PNL;
    }
  return rulecount;
}

/* function sends flush request. Requires flush command 
 * to be specified, since it allows flushing all rules 
 * (FLUSH_RULES), or only permission (FLUSH_PERMISSION_RULES)
 * or only denial (FLUSH_DENIAL_RULES) or only translation
 * rules (FLUSH_TRANSLATION_RULES). */
int flush_request(const struct netl_handle* nh_control, 
		  int flush_com)
{
  command flush_cmd; 
  init_command(&flush_cmd);
  flush_cmd.cmd = flush_com;	/* flush specified ruleset */
  if(send_to_kernel( (void*) &flush_cmd, nh_control, CONTROL_DATA) < 0)
    return -1;
  init_command(&flush_cmd);
  if(read_from_kern(nh_control, (unsigned char*) &flush_cmd, 
		    sizeof(command) ) < 0)
    {
      libnetl_perror("flush_request():");
      return -1;
    }
		
  if(flush_cmd.cmd == FLUSH_RULES) /* cmd must be of this type... */
    return flush_cmd.anumber;
  else 					/* ...otherwise we have received something wrong */
    return -1;
}


/* This function updates kernel rules. Depending on policy,
 * interested rules are first flushed, then a new vector
 * is reloaded. */
int update_kernel_rules(int policy, int flag)
{
  int flush_command = FLUSH_RULES;
  ipfire_rule* newrules=NULL;
  int numrules=0;
	
  extern ipfire_rule* denial_rules;
  extern ipfire_rule* accept_rules;
  extern ipfire_rule* translation_rules;
  extern int den_rules_num;
  extern int acc_rules_num;
  extern int transl_rules_num;
	
  extern struct netl_handle* nh_control;
	
  switch(policy)
    {
    case ACCEPT:
      flush_command = FLUSH_PERMISSION_RULES;
      newrules = accept_rules;
      numrules = acc_rules_num;
      break;
    case DENIAL:
      flush_command = FLUSH_DENIAL_RULES;
      newrules = denial_rules;
      numrules = den_rules_num;
      break;
    case TRANSLATION:
      if(getuid() != 0)
	{
	  PRED, printf(TR("Only root can modify translation ruiles!")), PNL;
	  return -1;
	}
      flush_command = FLUSH_TRANSLATION_RULES;
      newrules = translation_rules;
      numrules = transl_rules_num;
      break;	
    }
  /* flush ruleset */
  if(flush_request(nh_control, flush_command) < 0)
    {
      PRED, printf(TR("update_kernel_rules(): error in flush request!")), PNL;
      return -1;
    }
	
  if(flag == RELOAD_FILE)
    {
      printf(TR("Reloading rules from file and freeing old vector...") );
      newrules = allocate_ruleset(policy, &numrules);
      switch(policy)
	{
	case ACCEPT:
	  /* free old vector */
	  free(accept_rules);
	  accept_rules = newrules;
	  acc_rules_num = numrules;
	  break;
	case DENIAL:
	  free(denial_rules);
	  denial_rules = newrules;
	  den_rules_num = numrules;
	  break;
	case TRANSLATION:
	  if(getuid() == 0)
	    {
	      free(translation_rules);
	      translation_rules = newrules;
	      transl_rules_num = numrules;
	    }
	  else
	    PRED, printf(TR("You are not root: not freeing old translation rules.")), PNL;
	  break;
	}
		
    }
  printf("\tdone." NL);	
	
  /* send new rules */

  if(send_rules_to_kernel(newrules, numrules) < 0)
    {
      PRED, printf(TR("Error sending new rules to kernel space!")), PNL;
      exit(EXIT_FAILURE);
    }
  return numrules;
}

/* calls update_kernel_rules() 3 times if root, 2 if not root,
 * each time flushing and then reloading accept, denial 
 * and translation rules */
int update_all_rules(void)
{

  PNL, PYEL, printf(TR("RELOADING RULES")), PNL;

  if(update_kernel_rules(ACCEPT, RELOAD_FILE) < 0)
    {		
      PRED, printf(TR("ERROR UPDATING KERNEL RULES!")), PNL;
      return -1;
    }
  else
    PGRN, printf(TR("FIREWALL PERMISSION RULES UPDATED :)")), PNL;	
	
  if(update_kernel_rules(DENIAL, RELOAD_FILE) < 0)
    {
      PRED, printf(TR("ERROR UPDATING KERNEL RULES!")), PNL;
      return -1;
    }
  else
    PGRN, printf(TR("FIREWALL DENIAL RULES UPDATED :)")), PNL;	
	
  if(getuid() == 0)
    {
      if(update_kernel_rules(TRANSLATION, RELOAD_FILE) < 0)
	{
	  PRED, printf(TR("ERROR UPDATING KERNEL RULES!")), PNL;
	  return -1;
	}
      else
		PGRN, printf(TR("FIREWALL TRANSLATION RULES UPDATED :)")), PNL;	
    }
  return 0;
}

int openlog(const struct userspace_opts* uo)
{
  extern FILE* fplog;
  if(uo->clearlog)
    fplog = fopen(uo->logfile_name, "w");
  else
    fplog = fopen(uo->logfile_name, "a");
	
  if(fplog == NULL)
    {
      PRED, perror(TR("openlog(): error opening log file")), PNL;
      return -1;
    }
  return 0;
}

int closelog()
{
  extern FILE* fplog;
  if(fplog != NULL)
    {
      if(fclose(fplog) < 0)
	return -1;
      return 0;
    }
  return 1;
}

int flog(const char* line)
{
  extern FILE* fplog;
  extern struct userspace_opts uops;
  if( (fplog != NULL) && (uops.loglevel > NOLOG) )
    return do_log(line);
  else 
    return -1;
}

int do_log(const char* line)
{
  extern FILE* fplog;
  /* fprintf returns the number of characters written,
   * '\0' excluded */
  return fprintf(fplog, "%s", line);
}

/* given a log code, prints it separating each
 * entry with a '|' character. Used for printing
 * a packet received by kernelspace. Codes 
 * are stored in "log_codes.h" */
int flogpack(int code)
{
  char string[LOGLINELEN];
  snprintf(string, LOGLINELEN, "|%d", code);
  return flog(string);
}



	
/* put all fields to 0 when listener starts */
void init_netlink_stats(struct netlink_stats* nls)
{
  memset(nls, 0, sizeof(struct netlink_stats) );
}

/* invokes send_to_kernel specifying that the 
 * desired structure is a kernel_stats one */
int request_kstats(void)
{
  command stats_req;
  extern struct netl_handle* nh_control;
	
  init_command(&stats_req);
	
  stats_req.cmd = KSTATS_REQUEST;
	
  if(send_to_kernel( (void*) &stats_req, nh_control, CONTROL_DATA) < 0)
    {
      libnetl_perror("request_kstats(): error sending "
		     "statistics request command to firewall");
      return -1;
    }
  return 0;
}

/* receives from netlink socket a kernel_stats 
 * structure. Requires a struct netl_handle
 * externally allocated.
 */
int receive_kstats(struct kernel_stats* ks)
{
  extern struct netl_handle* nh_control;
  if(read_from_kern(nh_control, (unsigned char*) ks, 
		    sizeof(struct kernel_stats) ) < 0)
    {
      libnetl_perror("receive_kstats():");
      return -1;
    }
  return 0;	
}



/* Functions that manage adding/removing rules from firewall */
/* given two ipfire_rules mallocated pointers, a new rule, a
 * new position, the old dimension of old pointer, this function
 * inserts at position 'position' the new rule. */
int push_rule_at_pos(ipfire_rule *oldv, ipfire_rule *newv, 
		     int position, const int nmax, 
		     const ipfire_rule* newr)
{
  int i, k;
  int index;
  if(position <= 0)
    {
      printf(RED "push_rule_at_pos(): position must be >= 0!"
	     NL NL);
      return -1;
    }
  /* position starts from 1 */
  if(position > nmax + 1)
    position = nmax + 1;
  /* index starts from 0 */
  index = position - 1;
  /* copy first position-2 rules to new vector (numnering 
   * starts from 0..) */
  for(i = 0; i < index && i < nmax; i ++)
    {
      newv[i] = oldv[i];
      newv[i].position = i+1;
    }
  /* insert new rule */
  newv[index] = *newr;
  newv[index].position = position;
  /* last rules */
  for(k = index+1; i < nmax && k < nmax + 1;
      i++, k++)
    {
      newv[k] = oldv[i];
      newv[k].position = k+1;
    }
  return k;
}

/* deletes a rule at position 'position' */
int pop_rule_from_pos(ipfire_rule *oldv, ipfire_rule *newv, 
		      int position, const int nmax)
{
  int index, i;
	
  /* position starts from 1, index from 0 */
  index = position - 1;
	
  /* copy elements to new vector, except index-th */
  for(i = 0; i < index; i ++)
    {
      newv[i] = oldv[i];
      newv[i].position = i+1;
    }

  for(i = index +1; i < nmax; i++)
    {
      newv[i-1] = oldv[i];
      newv[i].position = i+1;
    }
	
  return 0;
}

/* adds rule at the position specified. Position starts from 1.
 * If position is 0, then rule is added at the tail of the vector.
 * The function reads the policy field of the rule, and then 
 * decides which vector is to be added to. */
int add_rule_at_position(const ipfire_rule *r, int position)
{
  extern ipfire_rule* denial_rules;
  extern ipfire_rule* accept_rules;
  extern ipfire_rule* translation_rules;
  extern int den_rules_num, acc_rules_num,
    transl_rules_num;
	
  ipfire_rule* tmp_v_rules;
	
  switch(r->nflags.policy)
    {
      /* permission rules vector */
    case ACCEPT:
      if(position == 0)
	position = acc_rules_num + 1; /* position starts from 0 */
		
      tmp_v_rules = 
	(ipfire_rule*) malloc(sizeof(ipfire_rule) * (acc_rules_num + 1) );
		
      /* add the permission rule at requested position */
      if(push_rule_at_pos(accept_rules, tmp_v_rules, position, 
			  acc_rules_num, r) < 0)
	return -1;
      acc_rules_num ++;	
      /* free old vector */
      free(accept_rules);
      accept_rules = tmp_v_rules;
      return position;
		
      /* drop rules vector */
    case DENIAL:
      if(position == 0)
	position = den_rules_num + 1; /* position starts from 0 */
		
      tmp_v_rules = 
	(ipfire_rule*) malloc(sizeof(ipfire_rule) * (den_rules_num + 1) );
		
      /* add the denial rule at requested position */
      if(push_rule_at_pos(denial_rules, tmp_v_rules, position, 
			  den_rules_num, r) < 0)
	return -1;
      den_rules_num ++;	
      /* free old vector */
      free(denial_rules);
      denial_rules = tmp_v_rules;
      return position;
		
      /* translation rules vector */
    case TRANSLATION:
      if(getuid() != 0)
	{
	  PNL, PRED, 
	  printf(TR("You have not the rights to insert a translation rule!"));
	  PNL;		
	  return -1;
	}
      if(position == 0)
	position = transl_rules_num + 1; /* position starts from 0 */
		
      tmp_v_rules = 
	(ipfire_rule*) malloc(sizeof(ipfire_rule) * (transl_rules_num + 1) );
		
      /* add the denial rule at requested position */
      if(push_rule_at_pos(translation_rules, tmp_v_rules, position, 
			  transl_rules_num, r) < 0)
	return -1;
      transl_rules_num ++;	
      /* free old vector */
      free(translation_rules);
      translation_rules = tmp_v_rules;
      return position;
		
    default:
      return -1;
    }
	
  /* return the position of added rule */
  return position;
}

/* deletes a rule at the position specified in vector indicated
 * by which_vector. Code in this function could be not necessary
 * if pop_rules_from_pos() was directly invoked. Anyway, it makes
 * manage_deleting_rule() a bit lighter */
int delete_rule_at_position(int position, int which_vector)
{
  extern ipfire_rule* denial_rules;
  extern ipfire_rule* accept_rules;
  extern ipfire_rule* translation_rules;
  extern int den_rules_num, acc_rules_num,
    transl_rules_num;
  ipfire_rule *v_tmp = NULL;
	
  if ( (which_vector == TRANSLATION) && (getuid() != 0) )
    {
      PRED, printf(TR("You must be root to delete a translation rule!"));
	  PNL;
      return -1;
    }		
  switch(which_vector)
    {
    case ACCEPT:
      if(position > acc_rules_num)
	{
	  PRED, printf(TR("Position %d out of range!"), position);
	  PNL;
	  return -1;
	}
      /* allocate space for temporary work */
      v_tmp = (ipfire_rule *)
	malloc(sizeof(ipfire_rule) * (acc_rules_num - 1) );

      if(pop_rule_from_pos(accept_rules, v_tmp, position, 
			   acc_rules_num ) < 0)	
	return -1;	
			
      /* free old vector */
      free(accept_rules);
      /* copy new allocated pointer into accept_rules */
      accept_rules = v_tmp;
      /* decrease rule counter */
      acc_rules_num --;			
      return 0;		
	
    case DENIAL:
      if(position > den_rules_num)
	{
	  PRED, printf(TR("Position %d out of range!"), position);
	  PNL;
	  return -1;
	}
      /* allocate space for temporary work */
      v_tmp = (ipfire_rule *)
	malloc(sizeof(ipfire_rule) * (den_rules_num - 1) );

      if(pop_rule_from_pos(denial_rules, v_tmp, position, 
			   den_rules_num ) < 0)	
	return -1;			
			
      /* free old vector */
      free(denial_rules);
      /* copy new allocated pointer into accept_rules */
      denial_rules = v_tmp;
      /* decrease rule counter */
      den_rules_num --;			
      return 0;	
			
    case TRANSLATION:
      if(position > transl_rules_num)
	{
	  PRED, printf(TR("Position %d out of range!"), position);
	  PNL;
	  return -1;
	}
      /* allocate space for temporary work */
      v_tmp = (ipfire_rule *)
	malloc(sizeof(ipfire_rule) * (transl_rules_num - 1) );

      if(pop_rule_from_pos(translation_rules, v_tmp, position, 
			   transl_rules_num ) < 0)	
	return -1;			
			
      /* free old vector */
      free(translation_rules);
      /* copy new allocated pointer into accept_rules */
      translation_rules = v_tmp;
      /* decrease rule counter */
      transl_rules_num --;			
      return 0;		
			
    default:
      return -1;			
    }
  return 0;
}

int log_initialization(const struct tm* tm, const char* user)
{
  char initlog[LOGLINELEN];
  snprintf(initlog, LOGLINELEN, "+%d-%d-%d-%d/%d:%d:%d#%s\n",
	   tm->tm_wday, tm->tm_mday, tm->tm_mon, tm->tm_year+1900, 
	   tm->tm_hour, tm->tm_min, tm->tm_sec, user);	
  return flog(initlog);
}

int log_exiting(const struct tm* tm, const char* user,
		const struct netlink_stats* nls)
{
  char initlog[LOGLINELEN];
  snprintf(initlog, LOGLINELEN, "-%d-%d-%d-%d/%d:%d:%d#TOT:%llu#LOST:%llu#%s\n",
	   tm->tm_wday, tm->tm_mday, tm->tm_mon, tm->tm_year+1900, 
	   tm->tm_hour, tm->tm_min, tm->tm_sec, nls->sum_now, nls->total_lost,
	   user);	
  return flog(initlog);
}



