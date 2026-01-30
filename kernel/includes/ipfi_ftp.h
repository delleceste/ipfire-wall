#ifndef IPFI_FTP_H
#define IPFI_FTP_H

/* See ipfi.c for details and 
 * use of this software. 
 * (C) 2005 Giacomo S. 
 */

#include "ipfi_netl.h"
#include "ipfi.h"
#include "ipfi_translation.h"
#include "ipfi_machine.h" 

typedef struct
{
  __u32 ftp_addr;
  __u16 ftp_port;
  short valid;
}ftp_info;

/* returns 1 if a new entry is added, 0 if the skb data do not
 * contain ftp 227 information about ip and port, 
 * -1 if an error occurs */
struct state_table* ftp_support(struct state_table* tentry,
                                const struct sk_buff* skb);

/* if skb data contain ftp address and port, allocate and return the new entry
 * to be added to the dynamic tables list */
struct state_table* packet_contains_ftp_params(const struct sk_buff* skb,
					       const struct state_table* orig_entry, char *ftp_buffer);
					       
/* just inspect if skb contains 227 command  ("Entering passive mode") */
int data_start_with_227(const struct sk_buff* skb, char *ftp_buffer);

/* returns a new kmallocated struct state_table. It is the copy of the 
 * original ftp table, with the new address and port. 
 * _Remember_ to initialize a new timer and to add the rule at the tail
 * of the list in the calling function. */
struct state_table* 
get_params_and_alloc_newentry(const struct state_table* orig, char *ftp_buffer);

/** inspects skb data and retrieves ftp address and port.
 * @return a structure of type ftp_info, which has the flag valid 
 * set to 1 if it is valid, 0 if something failed. The caller must
 * check against the valid flag.
 */
ftp_info get_ftpaddr_and_port(char *ftp_buffer);
			
/* takes ftp string and fills in integers representing ip and port */
int get_u8s(__u8* a1, __u8* a2, __u8* a3, __u8* a4, __u8* p1, __u8* p2);

/* checks a bit of syntax in buffer related to 227 command */
inline int check_buf(const char* ftpcmd);

#endif
