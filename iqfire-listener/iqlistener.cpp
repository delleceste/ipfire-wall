#include "iqlistener.h"

#include <QThread>
#include <QStringList>
#include <colors.h>
#include <sys/types.h>
#include <linux/netlink.h>

#define NETLINK_IPFI_DATA 		MAX_LINKS - 3
#define NETLINK_IPFI_CONTROL 		MAX_LINKS - 2
#define NETLINK_IPFI_GUI_NOTIFIER	MAX_LINKS - 1

#define MAXMESLEN 512

extern "C"
{
	int check_stats(struct netlink_stats* ns, const ipfire_info_t* msg);
	int print_lostpack_info(const struct  netlink_stats* nls);

	char* translation(const char* eng);
	/* Returns < 0 if the packet does not have to be printed, 0 if the filter 
	* or the info are null, > 0 if the filter matches 
	*/
	int filter_packet_to_print(const ipfire_info_t* p, const ipfire_rule_filter* f);
	
	/* allocates and copies into memory entries from /etc/services */
	struct ipfire_servent *alloc_and_fill_services_list(void);

#define TR(eng) (translation(eng) )

	struct netl_handle
	{
		int fd;
		struct sockaddr_nl local;
		struct sockaddr_nl peer;
	};

	/* allocates a netlink handle containing socket file descriptor
	 * and netlink source and destination addresses
 	 */
	/* protocol: NETLINK_IPFI_DATA for the listener */
	struct netl_handle *alloc_netl_handle (int protocol); 
	/* free socket and mallocated memory for handle */
	struct netl_handle* netl_free_handle(struct netl_handle *h);
	
	/* read a message from kernel space */
	int read_from_kern(const struct netl_handle *h, unsigned char *buf, size_t len);
	/* returns the string corresponding to the error code */
	char* libnetl_err_string(void) ;
	/* prints the string s followed by libnetl errors and errno */
	void libnetl_perror(const char *s);
	int send_to_kernel( void* mesg, const struct netl_handle* handle, 
		int type_of_message);
	
	/* Printing functions, included in libipfire-common */
	void restore_color(int direction);
	int print_packet(const ipfire_info_t *pack, 
			 const struct ipfire_servent* ipfi_svent,
    			 const ipfire_rule_filter *filter);
	
	/* Returns a filter rule. 
	 * The caller must free_filter_rule() this returned structure after use!
	 */
	ipfire_rule_filter* setup_filter(const char* filter);
	
	/* This one frees the ipfire_rule dynamically allocated 
	 * by the setup_filter().
	 * It must be called to free the dynamically allocated resources.
	 */
	void free_filter_rule(ipfire_rule_filter *f);

	/* Returns 0 if pattern is NOT contained in string,
	 * the position of the end of the pattern in the string if the
	 * pattern is contained in string.
 	 */
	int string_contains_pattern(const char *string, const char* pattern);
}


Listener::Listener():
	svent(NULL),
	svent_pointer_save(NULL),
	nh_data(NULL),
	filter(NULL)
{
	/* Build listener netlink socket */
	listener_message lmess;	
	printf("Allocating netlink data socket..."), fflush(stdout);
	
	nh_data = alloc_netl_handle(NETLINK_IPFI_DATA);
	if(nh_data == NULL)
	{
		PRED, printf(TR("failed allocating netlink data socket:\n(\"%s\")\n"),
			     libnetl_err_string() ), PNL, PNL;
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("["), PGRN, printf("OK"), PCL, printf("]\n");
		
		lmess.message = STARTING;
	
		if(send_to_kernel( (void*) &lmess, nh_data, LISTENER_DATA) < 0)
		{
			libnetl_perror(TR("iqfire-listener: Listener(): error sending init message" ));
			exit(EXIT_FAILURE);
		}
	}
	
	/* Allocate servent for port resolution */
	svent = svent_pointer_save = alloc_and_fill_services_list();
	if(svent == NULL)
	{  		 
		PRED, printf(TR("Failed to allocate space for port services. Disabling."));
	}
	
	/* allocate and start the stdin reading thread */
	ListenerThread *stdin_reader = new ListenerThread(this);
	connect(stdin_reader, SIGNAL(finished() ), this, SLOT(threadFinished() ) );
	stdin_reader->start();
	
	/* Start the netlink socket DATA listening */
	startListening();
	
}

Listener::~Listener()
{
	printf("Listener exiting\n");
}

void Listener::enablePortResolution(bool en)
{
	if(en)
	{
		if(svent == NULL) /* if disabled, enable it! */
		{
			svent = svent_pointer_save; /* Restore the mallocated pointer */
			PGRN, printf(TR("Enabling port resolution.")), PNL, PNL;
		}
	}
	else
	{
		if(svent != NULL) /* if not null nullify it */
		{
			svent = NULL; /* disable the port resolution */
			PVIO, printf(TR("Disabling port resolution.")), PNL, PNL;
		}
	}

}

void Listener::startListening()
{
	int bytes_read, packs_lost;
	int quiet = 0;
	
	ipfire_info_t mes_from_kern;
	
	memset(&nlstats, 0, sizeof(struct netlink_stats) );
	
	while(1)
	{
		if( (bytes_read = read_from_kern(nh_data, 
		     (unsigned char*) &mes_from_kern, sizeof(ipfire_info_t) ) ) < 0)
		{
			libnetl_perror(TR( "listener(): error getting message from kernel!\n"));
			/* Go on reading, do not exit. */
		}
		else if(bytes_read == 0)
		{
			printf(TR("read 0 bytes!")), printf("\n");
		}
		else
		{
			if((packs_lost = check_stats(&nlstats, &mes_from_kern)) )
			{
				print_lostpack_info(&nlstats);
			}
			if(quiet == 0)
			{
				/* For now print without filters */
				print_packet(&mes_from_kern, svent, filter);	
			}
		}
	}
}

void Listener::threadFinished()
{
	printf("Freeing netlink data socket...");
	netl_free_handle(nh_data);
	nh_data = NULL;
	printf("["), PGRN, printf("OK"), PCL, printf("]"), PNL;
}

void Listener::applyFilter(QString &filter_str)
{
	filter = setup_filter(filter_str.toStdString().c_str());
	if(filter == NULL)
	{
		PRED; printf(TR("Error allocating the filter!"));
		PNL; printf(TR("Filter will not be applied.")); PNL; PNL;
	}
	else
	{
		printf("alloco il filtro %s\n", filter_str.toStdString().c_str());
	}
}

void Listener::disableFilter()
{
	if(filter != NULL)
	{
		free_filter_rule(filter);
		filter = NULL;
	}
	else
	{
		PNL; PVIO; printf(TR("The filter is already disabled")); PNL; PNL;
	}
}


ListenerThread::ListenerThread(QObject *parent) : QThread(parent)
{
	listener_parent = (Listener *) (parent);
}

ListenerThread::~ListenerThread()
{
	
}

void ListenerThread::run()
{
	char message[MAXMESLEN];
	while(1)
	{
		fgets(message, MAXMESLEN - 1, stdin);
		/* See if we have to quit */
		if( (strncmp(message, "quit", 4) == 0) ||
				   (strcmp(message, "q") == 0))
			break;
		
		if(strncmp(message, "resolv_ports", 12) == 0)
			listener_parent->enablePortResolution(true);
		else if(strncmp(message, "noresolv_ports", 14) == 0)
			listener_parent->enablePortResolution(false);
		/* first put strncmp("filter:disable"..) !
		 * then strncmp("filter:"..) 
		 */
		else if(strncmp(message, "filter:disable", 14) == 0)
			listener_parent->disableFilter();
		else if(strncmp(message, "filter:", 7) == 0)
			listener_parent->applyFilter(QString(message).remove("filter:"));
		
	}
}





