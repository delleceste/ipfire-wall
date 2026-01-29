#ifndef IQFNETLINK_H
#define IQFNETLINK_H

//#include <linux/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <ipfire_structs.h>
#include <QObject>

#define NETLINK_IPFI_DATA 		MAX_LINKS - 3
#define NETLINK_IPFI_CONTROL 		MAX_LINKS - 2
#define NETLINK_IPFI_GUI_NOTIFIER	MAX_LINKS - 1

class Log;

extern "C"
{

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
	
		/* sends a command to kernel space. After this is done, memory 
 * dynamically allocated is freed. int type_of_message can be
 * one among COMMAND (to allocate space for a command 
 * structure), LISTENER_DATA (to allocate space for a listener_message
 * data structure), or KSTATS (to reserve space for a struct kernel_stats.
 */
	int 
	send_to_kernel( void* mesg, const struct netl_handle* handle, 
 			int type_of_message);
}

/* A singleton class */
class IQFNetlinkControl : public QObject
{
	Q_OBJECT
			
	public:
	
	static IQFNetlinkControl* instance();
	
	struct netl_handle *Handle();
	bool isSilentEnabled();
	
	/** Calls send_to_kernel() of the libnetlink library */
	int SendCommand(command *cmd);
	
	/** Calls read_from_kern() of the libnetlink library */
	int ReadCommand(command *cmdrec);
	
	/** Like the above, provided for convenience. Reads the statistics */
	int ReadStats(struct kernel_stats* kstats);
	
	/** Reads kstats light */
	int ReadStatsLight(struct kstats_light* klight);
	
	/** reads state tables */
	int ReadStateTable(struct state_info *sti);
	
	/** reads snat tables */
	int ReadSnatTable(struct snat_info *sni);
	
	/** reads dnat table */
	int ReadDnatTable(struct dnat_info *dni);
	
	int GetKtablesSizes(struct firesizes *fs);
	
	/** reads kernel tables memory usage */
	int GetKtablesUsage(struct ktables_usage *ktu);
	
	~IQFNetlinkControl();

	public slots:
		void enableSilent(bool enable);
		void enableStateLog(bool enable);		
	
	private: /* Singleton: the constructor is private */
		
	IQFNetlinkControl();
	
	
	static IQFNetlinkControl *_instance;
		
	struct netl_handle *nh_control;
	
	Log* log;
};

#endif






