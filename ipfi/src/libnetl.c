/*  netlink library, made up of a private and a public interface for sendin'
 *  and receivin' messages to and from kernel via netlink sockets.
 *  Giacomo Strangolino.
 *  jacum@libero.it 
 */ 
 
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
 
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <errno.h>

#include <syslog.h>

#include "includes/libnetl.h"

#define NETL_RECVBUF 4096

/* private interface */

enum
  {
    LIBNETL_OK = 0,
    LIBNETL_MALLOC_FAILED,
    LIBNETL_FREE_NULL_POINTER,
    LIBNETL_ADDRLEN_MISMATCH,
    LIBNETL_ZERO_MESS,
    LIBNETL_ERR_SOCKET,
    LIBNETL_ERR_BIND,
    LIBNETL_ERR_RECVFROM,
    LIBNETL_ERR_SENDTO,
    LIBNETL_ERR_PIDKERN,
    LIBNETL_ERR_RTRUNC,
  };
/* last error number */
#define LIBNETL_BAD_ERRCODE 	LIBNETL_ERR_RTRUNC

static struct libnetl_error_coding
{
  int errnum;
  char errmess[64];
}libnetl_error_map[] = {
  {LIBNETL_OK, "ok/unknown error"},
  {LIBNETL_MALLOC_FAILED, "malloc failed()" },
  {LIBNETL_FREE_NULL_POINTER, "trying to free a NULL pointer!" },
  {LIBNETL_ADDRLEN_MISMATCH, "Address length mismatch" },
  {LIBNETL_ZERO_MESS, "Received 0 bytes" },
  {LIBNETL_ERR_SOCKET, "socket() error" },
  {LIBNETL_ERR_BIND, "bind() error" },
  {LIBNETL_ERR_RECVFROM, "recvfrom error" },
  {LIBNETL_ERR_SENDTO, "sendto() error" },
  {LIBNETL_ERR_PIDKERN, "unexpected pid number" },
  {LIBNETL_ERR_RTRUNC, "truncated message" },
  {LIBNETL_BAD_ERRCODE, "bad error code" }
};

static int netl_errno;

/* function prototypes */
static int netl_send_to_kernel(const struct netl_handle *h,
			       const void *msg, size_t len);

static int cceive_from_kernel(const struct netl_handle *h,
                                    void *buf, size_t len);

char * libnetl_strerror(int netl_errcode);

/* private functions */

static int netl_send_to_kernel(const struct netl_handle *h,
			       const void *msg, size_t len)
{
  int status = sendto(h->fd, msg, len, 0,
		      (struct sockaddr *)&h->peer, sizeof(h->peer));
  if (status < 0)
    {
      netl_errno = LIBNETL_ERR_SENDTO;
      syslog(LOG_ERR, "libnetl.c: netl_send_to_kernel(): sendto() error (%m)");
    }   
  return status;
}

/* uses netlink macros to check and access received buffer and extract data from it.
 * Extracts len bytes from the receive buffer netlink payload and copies them into
 * buf.
 */
static int netl_receive_from_kernel(const struct netl_handle *h, void *buf, size_t len)
{
  int status;
  unsigned addrlen = sizeof(h->peer);
  unsigned char tmpbuf[NETL_RECVBUF];
  memset(buf, 0, len);
  memset(tmpbuf, 0, sizeof(unsigned char) * NETL_RECVBUF);
  struct nlmsghdr *nh;
		
  /* receive from kernel */
  status = recvfrom(h->fd, tmpbuf, NETL_RECVBUF, 0,
		    (struct sockaddr *) &h->peer, &addrlen);
  /* recvfrom returned a negative value */
  if(status < 0) 
    {
      perror("libnetl.c: netl_receive_from_kernel(): recvfrom() error ");
      syslog(LOG_ERR, "libnetl.c: netl_receive_from_kernel(): recvfrom() error (%m)");
      netl_errno = LIBNETL_ERR_RECVFROM;
      return -1;
    }
  if(addrlen != sizeof(h->peer) ) 		/* must be equal */
    {
      netl_errno = LIBNETL_ADDRLEN_MISMATCH;
      syslog(LOG_ERR, "libnetl.c: netl_receive_from_kernel(): addrlen ! sizeof(h->peer)");
      return -1;
    }
  if (h->peer.nl_pid != 0) 			/* kernel pid = 0 */
    {
    printf("---->pid letto: %d, mio pid: %d\n", h->peer.nl_pid, getpid());
    syslog(LOG_ERR, "libnetl.c: netl_receive_from_kernel(): pid mismatch!\n" 
	"pid read: %d, my pid: %d\n", h->peer.nl_pid, getpid());
      netl_errno = LIBNETL_ERR_PIDKERN;
      return -1;
    }
  if (status == 0)   /* recvfrom got 0 bytes */
    {
      netl_errno = LIBNETL_ZERO_MESS;
      syslog(LOG_ERR, "libnetl.c: netl_receive_from_kernel(): recvfrom() got 0 bytes!");
      return -1;
    }
  nh = (struct nlmsghdr*) tmpbuf;
  
  /* NLMSG_OK returns true if the netlink message is not truncated and ok to parse. */
  if(NLMSG_OK(nh, status))
  {
    /* NLMSG_DATA() returns a pointer to the payload associated with the passed nlmsghdr. */
    memcpy(buf, NLMSG_DATA(nh), len);
  }
  else
  {
    printf("libnetl.c: netl_receive_from_kernel() NLMSG_OK not ok!\n");
    syslog(LOG_ERR, "libnetl.c: netl_receive_from_kernel() NLMSG_OK not ok!\n");
  }
  /* message truncated? see libipq in netfilter sources */
  return status;
}

/* error handling */
char * libnetl_strerror(int netl_errcode)
{
  if (netl_errcode < 0 || netl_errcode > LIBNETL_BAD_ERRCODE)
    netl_errcode = LIBNETL_BAD_ERRCODE;
  return libnetl_error_map[netl_errcode].errmess;
}

/* Public interface */

struct netl_handle *alloc_netl_handle (int protocol) /* returns a mallocated handle or NULL */
{
  struct netl_handle *netlh;
  netlh = (struct netl_handle*) malloc(sizeof(struct netl_handle) );
  if(netlh == NULL)
    perror("malloc() error");
  /* azzeriamo i bit della struttura */
  memset(netlh, 0, sizeof(struct netl_handle));
  netlh->fd = socket(PF_NETLINK, SOCK_RAW, protocol);
  if(netlh->fd < 0)
    {
      perror("Errore socket()");
      netl_errno = LIBNETL_ERR_SOCKET;
      free(netlh);
      return NULL;
    }
  /* indirizzo netlink locale */
  memset(&netlh->local, 0, sizeof(struct sockaddr_nl)); /* pulizia */
  netlh->local.nl_family = AF_NETLINK;
  netlh->local.nl_pid = getpid();  /* mio pid */
  netlh->local.nl_groups = 0;  /* unicast */
  /* bind() */
  if(bind(netlh->fd, (struct sockaddr *)&netlh->local, sizeof(netlh->local)) < 0)
    {
      perror("bind() error");
      netl_errno = LIBNETL_ERR_BIND;
      free(netlh);
      return NULL;
    }
  /* indirizzo remoto (del kernel) */
  memset(&netlh->peer, 0, sizeof(struct sockaddr_nl));
  netlh->peer.nl_family = AF_NETLINK;
  netlh->peer.nl_pid = 0;
  netlh->peer.nl_groups = 0;
  return netlh;	
}

/* close socket and free mallocated memory */
struct netl_handle * netl_free_handle(struct netl_handle *h)
{
  if (h) 
    {
      close(h->fd);
      free(h);
    }
  else
    printf("Trying to free a NULL pointer!\n");
  return NULL;
}

/* send message to kernel */
int send_to_kern(const struct netl_handle *h, const void *msg, size_t len)
{
  return netl_send_to_kernel(h, msg, len);
}

/* receive message from kernel */
int read_from_kern(const struct netl_handle *h, unsigned char *buf, size_t len)
{
  return netl_receive_from_kernel(h, buf, len);
}

/* print errors */
/* returns the string corresponding to the error code */
char* libnetl_err_string(void) 
{  
  return libnetl_strerror(netl_errno);
}

/* prints the string s followed by libnetl errors and errno */
void libnetl_perror(const char *s)
{
  if (s)
    fputs(s, stderr);
  else
    fputs("ERROR", stderr);
  if (netl_errno)
    fprintf(stderr, ": %s", libnetl_err_string());
  if (errno)
    fprintf(stderr, ": %s", strerror(errno));
  fputc('\n', stderr);
}

/* allocates the netlink packet and fills in header fields */
struct nlmsghdr* alloc_and_fill_nlheader(int payload_size)
{
  /** given the length of ancillary data, int NLMSG_LENGTH(size_t len)  returns 
   *   the size of the payload + header */
//    printf("alloc and fill nlheader: NLMSG_SIZE: %d NLMSG_LENGTH %d\n", NLMSG_SPACE(payload_size),
//     NLMSG_LENGTH(payload_size));
  struct nlmsghdr *nlhead;
  if( (nlhead	= (struct nlmsghdr*) malloc(NLMSG_SPACE(payload_size) ) )  == NULL)
    {
      netl_errno = LIBNETL_MALLOC_FAILED;
      return NULL;
    }		
  /* fill in the fields */
  nlhead->nlmsg_len = NLMSG_LENGTH(payload_size);
  nlhead->nlmsg_pid = getpid();  /* my pid */
  nlhead->nlmsg_flags = 0;
  return nlhead; /* return mallocated pointer of the structure */
}

/* copies data in dest into the payload of the netlink message and
 * returns a pointer to the allocated memory 
 */
void* fill_payload(struct nlmsghdr* nlhmess_header, const void* data, size_t len)
{
  /*  void *NLMSG DATA(struct nlmsghdr *nlh): given a netlink
   *  header structure, this macro returns a pointer to the ancilliary data
   *  which it contains.
   */
  return memcpy(NLMSG_DATA(nlhmess_header), data, len);
}

struct nlmsghdr* netl_free_nlmess(struct nlmsghdr* nlmess)
{
  if(nlmess != NULL)
    {
      free(nlmess);
      nlmess = NULL;
    }
  else
    printf("Trying to free a NULL pointer!\n");
  return NULL;
}
