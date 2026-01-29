/* ip firewall Giacomo S. 
 * Passive ftp support module */

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
/* see ipfi.c for details */

#include <linux/module.h>
#include <linux/list.h>
#include "includes/ipfi.h"
#include "includes/ipfi_netl.h"
#include "includes/ipfi_machine.h"
#include "includes/ipfi_ftp.h"

#define FTPBUF 256
#define CLEANEDBUF 128

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giacomo S. <jacum@libero.it>");
MODULE_DESCRIPTION("Passive FTP support module");

/* Removed thread-unsafe global: char ftp_buffer[FTPBUF]; */

/* returns 1 if a new entry is added, 0 if the skb data do not
 * contain ftp 227 information about ip and port, 
 * -1 if an error occurs 
 * Comes from:
 * -iph_in_get_response();
 * - ipfire_filter();
 * - check_state();
 * skb already checked in ipfi_response() against `NULL' value
 */
struct state_table* ftp_support(struct state_table* tentry, 
		const struct sk_buff* skb, 
		ipfire_info_t* packet_info)
{	
	char ftp_buffer[FTPBUF];
	return packet_contains_ftp_params(skb, tentry, ftp_buffer);
}

/* if skb data contain ftp address and port, allocate and return the new entry
 * to be added to the dynamic tables list */
struct state_table* packet_contains_ftp_params(const struct sk_buff* skb,
		const struct state_table* orig_entry, char *ftp_buffer)
{
	struct state_table* newt = NULL;
	if(data_start_with_227(skb, ftp_buffer) > 0)
		newt = get_params_and_alloc_newentry(orig_entry, ftp_buffer);
	return newt;		
}

/* just inspect if skb contains 227 command  ("Entering passive mode") */
int data_start_with_227(const struct sk_buff* skb, char *ftp_buffer)
{
	unsigned int dataoff, datalen;
	char* data_ptr;
	struct tcphdr *th;
	struct iphdr* iph;
	struct tcphdr _tcph;
	
	iph = ip_hdr(skb);
	if(iph == NULL)
		return network_header_null("data_start_with_227() (ipfi_ftp.c)",
				"IP header NULL");

	/* a packet arrives here if protocol is TCP, see check_state() */
	th = skb_header_pointer(skb, iph->ihl*4, sizeof(_tcph), &_tcph);

	if (check_tcp_header_from_skb(skb, th) < 0)
		return network_header_null("data_start_with_227() (ipfi_ftp.c)", "TCP header NULL");

	dataoff = iph->ihl*4 + th->doff*4;
	/* If there is no data in the buffer, return -1 */
	if (dataoff >= skb->len) 
		return -1;
	datalen = skb->len - dataoff;

	if (datalen > FTPBUF - 1)
		datalen = FTPBUF - 1;

	data_ptr = skb_header_pointer(skb, dataoff,
			datalen, ftp_buffer);

	if(data_ptr == NULL)
	{
		IPFI_PRINTK("IPFIRE: fb_ptr NULL! (ipfi_ftp.c)\n");
		return -1;
	}

	if (data_ptr != ftp_buffer)
		memcpy(ftp_buffer, data_ptr, datalen);

	ftp_buffer[datalen] = '\0';

	/* 227 ( ) A,B,C,D,p,q -> minimal string representing a 227 command*/
	if(datalen < 16) 
		return 0;

	if(strncmp(ftp_buffer, "227", 3) == 0)
		return 1;
	return 0;
}

/* returns a new kmallocated struct state_table. It is the copy of the 
 * original ftp table, with the new address and port. 
 * _Remember_ to initialize a new timer and to add the rule at the tail
 * of the list in the calling function. */
	struct state_table* 
get_params_and_alloc_newentry(const struct state_table* orig, char *ftp_buffer)
{
	ftp_info ftpi;
	struct state_table *newt = NULL;
#ifdef ENABLE_RULENAME
	char rname[RULENAMELEN];
#endif
	ftpi = get_ftpaddr_and_port(ftp_buffer);

	if(ftpi.valid)
	{
		newt = (struct state_table*) 
			kmalloc(sizeof(struct state_table), GFP_ATOMIC);
		if(!newt)
		{
		  IPFI_PRINTK("failed to allocate space for the ftp state table!\n");
		  return NULL;
		}
		/* to start, copy old table into new one */
		memset(newt, 0, sizeof(struct state_table));
		memcpy(newt, orig, sizeof(struct state_table) );
		newt->daddr = ftpi.ftp_addr;
		newt->dport = ftpi.ftp_port;
		newt->ftp = FTP_DEFINED;
		newt->originating_rule = orig->originating_rule;
#ifdef ENABLE_RULENAME
		snprintf(rname, RULENAMELEN, "FTP<->RULE %u [%u-%u]", orig->originating_rule,
			  ntohs(orig->sport), ntohs(orig->dport));
		rname[RULENAMELEN-1] = '\0';
		strncpy(newt->rulename, rname, RULENAMELEN-1);
#endif	
	}
	/* return the new allocated state table or NULL */
	return newt;
}

/* checks a bit of syntax in buffer related to 227 command */
inline int check_buf(const char* ftpcmd)
{
	int len = strlen(ftpcmd);
	unsigned i = 0;
	unsigned commas = 0, parenthesis =0;
	if(len - 3 < 0 || len > FTPBUF)
	  return -1;
	if(ftpcmd[len-1] != '\n')
		return -1;
	if(ftpcmd[len-2] != '\r')
		return -1;
	if(ftpcmd[len-3] != ')')
		return -1;
	for(i=0; i < len && i < FTPBUF; i++)
	{
		if(ftpcmd[i] == ',')
			commas++;
		else if(ftpcmd[i] == '(')
			parenthesis ++;
	}
	if( (commas != 5 ) || (parenthesis != 1) )
		return -1;

	return 1;
}

/* takes ftp string and fills in integers representing ip and port */
int clean_ftp_command(char* cleaned, char *ftp_buffer)
{
	unsigned i = 0, j = 0;

	if(check_buf(ftp_buffer) < 0)
	{
		IPFI_PRINTK("IPFIRE: bad format for 227 ftp command: \"%s\"\n", ftp_buffer);
		return -1;
	}

	while(( i < FTPBUF) && (ftp_buffer[i] != '\0') && (ftp_buffer[i] != '(')  )
		i++;
	/* reached '(', ftp_buffer[i] points to '(' */
	i++; /* pass '(' */
	while((i < FTPBUF) && (j < CLEANEDBUF - 1) && (ftp_buffer[i] != '\0') && (ftp_buffer[i] != ')' ))
	{
		cleaned[j] = ftp_buffer[i];
		i++;
		j++;
	}
	cleaned[j] = '\0'; /* Terminate string */

	return 1;
}

/* inspects skb data and retrieves ftp address and port.
 * returns a structure of type ftp_info, which has the flag valid 
 * set to 1 if it is valid, 0 if something failed. The caller must
 * check against the valid flag.
 */
ftp_info get_ftpaddr_and_port(char *ftp_buffer) 
{
	ftp_info ftpi, invalid_ftpinfo;
	char cleaned[CLEANEDBUF];
	__u8 a1, a2, a3, a4, p1, p2;
	__u32 n=0, m=0, o=0;
	
	memset(&ftpi, 0, sizeof(ftp_info));
	memset(&invalid_ftpinfo, 0, sizeof(invalid_ftpinfo));

	/* validate the ftp_info aimed at containing a valid result */
	ftpi.valid = 1; 
	
	if(clean_ftp_command(cleaned, ftp_buffer) < 0)
	{
		IPFI_PRINTK("IPFIRE: error cleaning ftp buffer!\n");
		return invalid_ftpinfo;
	}

	if(sscanf(cleaned, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &a1,  &a2, &a3,   &a4, &p1, &p2) != 6)
		return invalid_ftpinfo;
	/* compute address */
	ftpi.ftp_addr = a4;
	n = a1;
	n = n << 24;
	m = a2;
	m = m << 16;
	o = a3;
	o = o << 8;
	ftpi.ftp_addr = ftpi.ftp_addr + n + m + o;
	ftpi.ftp_addr = htonl(ftpi.ftp_addr);	
	/* port */
	n = p1;
	n = n << 8;
	ftpi.ftp_port = p2 + n;
	ftpi.ftp_port = htons(ftpi.ftp_port);
	
	return ftpi;
}


