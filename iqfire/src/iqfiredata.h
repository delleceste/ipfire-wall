#ifndef IQFIRE_DATA
#define IQFIRE_DATA

#include <ipfire_structs.h>  
#include <QString>

class Log;

/* A singleton class */
class IQFireData 
{
	public:
	
	static IQFireData* instance(int argc = 0, char** argv = NULL);

	struct cmdopts prog_ops;
	struct userspace_opts uops;
	struct netlink_stats nlstats;
	command opts;
	
	QString mailer_options_filename,
		logfile_filename, language_filename;
		
	short loglevel, clearlog, justload, flush, rmmod, resolv_services, dns_resolver,
		mail, rc;
		
	unsigned int  mail_time, dns_refresh;
	
	char upper_username[PWD_FIELDS_LEN];
	
	/* methods */
	/* if uops is not NULL, the fields for the proc variables are 
	 * filled in.
	 */
	int GetIQFConfigFromFile(command* cmdopts, struct userspace_opts* uops);
	int GetIQFConfigFromCmdLine(int argc, char **argv);
	int sendOptionsToKernel(command *opts);
	void initCommand(command *com);
	
	private: /* Singleton: the constructor is private */
		
	IQFireData(int argc, char **argv);
	~IQFireData();
		
	static IQFireData* iqfdata_instance;
	Log* debug;
};

#endif





