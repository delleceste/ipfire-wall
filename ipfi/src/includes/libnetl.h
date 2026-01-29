#ifndef LIBNETL_H
#define LIBNETL_H
#include <sys/socket.h> /* for sa_family_t */
#include <linux/types.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <linux/socket.h>

#define NETLINK_IPFI_DATA 		MAX_LINKS - 3
#define NETLINK_IPFI_CONTROL 		MAX_LINKS - 2
#define NETLINK_IPFI_GUI_NOTIFIER	MAX_LINKS - 1


struct netl_handle
{
	int fd;
	struct sockaddr_nl local;
	struct sockaddr_nl peer;
};

/* allocates a netlink handle containing socket file descriptor
 * and netlink source and destination addresses
 */
/* protocol: NETLINK_IPFI_DATA or NETLINK_IPFI_CONTROL */
struct netl_handle *alloc_netl_handle (int protocol); 
/* free socket and mallocated memory for handle */
struct netl_handle* netl_free_handle(struct netl_handle *h);
/* send a message to kernel */
int send_to_kern(const struct netl_handle *h, const void *msg, size_t len);
/* read a message from kernel space */
int read_from_kern(const struct netl_handle *h, unsigned char *buf, size_t len);
/* returns the string corresponding to the error code */
char* libnetl_err_string(void) ;
/* prints the string s followed by libnetl errors and errno */
void libnetl_perror(const char *s);

/* creation of the packet to send to kernel space */
/* allocates the netlink packet and fills in header fields */
struct nlmsghdr* alloc_and_fill_nlheader(int payload_size);
/* copies data to send into payload */
void* fill_payload(struct nlmsghdr* nlhmess, const void* data, size_t len);
/* frees nlmsghdr mallocated pointer */
struct nlmsghdr* netl_free_nlmess(struct nlmsghdr* nlmess);
	
#endif
