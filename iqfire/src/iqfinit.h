#ifndef IQFINIT_H
#define IQFINIT_H

#include <ipfire_structs.h>
#include <macros.h>
#include <QString>

class IQFNetlinkControl;
class Log;

/* Initialization happens just one time after startup.
 * For this reason, let this be a singleton
 */
class IQFInitializer
{
	public:
	
	static IQFInitializer* instance(int argc, char** argv);
	static IQFInitializer* instance() { return _instance; }

	struct cmdopts prog_ops;
	struct userspace_opts uops;
	struct netlink_stats nlstats;
	command opts;
	
	int init(QString &initMsg);
	
	int SendGoodbye();
	
	bool HelloSucceeded() { return hello_ok; }
	
	unsigned procSysNetCoreMemDefault();
	unsigned procSysNetCoreMemMax();
	short int procPolicy();
	
	void setProcSysNetCoreMemDefault(unsigned n);
	void setProcSysNetCoreMemMax(unsigned n);
	void setProcPolicy(int policy);
	
	private: /* Singleton: the constructor is private */
		
	IQFInitializer(int argc, char **argv);
	~IQFInitializer();
		
	int SendHello(QString &helloResult);
	static IQFInitializer* _instance;
	bool hello_ok;
	IQFNetlinkControl *nlctrl;
	int argcount;
	QString appname;
	Log* log;
	
};

#endif







