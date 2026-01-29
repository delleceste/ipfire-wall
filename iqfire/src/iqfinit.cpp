#include "iqfinit.h"
#include "iqfnetlink.h"
#include "iqfiredata.h"
#include <QtDebug>
#include <QApplication>
#include <QFile>
#include <QSettings>
#include "iqflog.h"
#include "iqfire_module_load_check.h"

extern "C"
{
	int build_hello_command(command* cmdh, char* argv0 );
	int load_module(void);
}

IQFInitializer* IQFInitializer::_instance = NULL;

IQFInitializer* IQFInitializer::instance(int argc, char** argv)
{
	if(_instance == NULL)
		return (_instance = new IQFInitializer(argc, argv) );
	else
		return _instance;
}

IQFInitializer::IQFInitializer(int argc, char** argv)
{
	argcount = argc;
	appname = QString("%1").arg(argv[0]);
	nlctrl = NULL;
	log = Log::log();
}

IQFInitializer::~IQFInitializer()
{
	
}

int IQFInitializer::init(QString &initMsg)
{
	int ret, moduleLoadingRet = 1;
	/* check if startup script has left in /tmp a fail log */
	ModuleLoadCheck modload_check;
	if(modload_check.loadFailed())
	{
	  initMsg = modload_check.errorMessage();
	  return -1;
	}
	
	/* no fail log in /tmp: see if the module is already loaded or try to load it */
	if(getuid() == 0)
	{
		Log::log()->appendMsg("See if we need to load the kernel module...");
		if( (moduleLoadingRet = load_module() ) < 0)
			initMsg = "- Failed to load module\nPlease run, as root, \"/usr/bin/ipfire-kernel-updater\"\n"
			"This is probably dued to a kernel upgrade or an uncomplete installation";
		else if(moduleLoadingRet > 0)
		{
			initMsg = "- Module already loaded\n";
			Log::log()->appendOk("Module already loaded");
		}
		else
		{
			initMsg = "- Loaded module\n";
			Log::log()->appendOk("Module successfully loaded");
		}
	}
	
	if(moduleLoadingRet < 0)
		return -1;
	
	Log::log()->appendMsg(QString("Sending hello to the kernel (application pid: %1)").
			arg(getpid()));
	
	ret = SendHello(initMsg);
	/* root needs to load module and send options at startup,
	 * if the module is not already loaded.
	 */
	if(ret == HELLO_OK && getuid() == 0)
	{
		Log::log()->appendMsg("Hello sent with success, loading administrator's settings:");
		command com;
		IQFireData::instance()->initCommand(&com);
		Log::log()->appendMsg("Reading the configuration file...");
		IQFireData::instance()->GetIQFConfigFromFile(&com, NULL);
		Log::log()->Ok();
		Log::log()->appendMsg("Sending the options to the kernel...");
		IQFireData::instance()->sendOptionsToKernel(&com);
		Log::log()->Ok();
	}
	else if(ret == HELLO_OK)
	{
		Log::log()->Ok();
	}
	else
	{
		Log::log()->appendFailed("Initializing the user/kernel communication: firewall busy");
		Log::log()->appendFailed(initMsg);		
	}

	return ret;
}

int IQFInitializer::SendGoodbye()
{
  command exit_cmd;
  memset(&exit_cmd, 0, sizeof(command));
  exit_cmd.cmd = EXITING;
  printf("\e[1;32m*\e[0m sending goodbye to the kernel...\t");
  if(nlctrl == NULL)
  {
// 	  QMessageBox::critical(0, "Error sending goodbye", "The netlink handle is NULL!");
	perr("error sending goodbye to the kernel: netlink control not initialized?");
    	return -1;
  }
    if(nlctrl->SendCommand(&exit_cmd) < 0)
    {
      QString error = QString(TR("IQFInitializer::SendGoodbye(): failed sending goodbye!\n\"%1\""))
	    .arg(libnetl_err_string() );
      QMessageBox::critical(0, TR("Error"), error);
      log->appendFailed(error);
      return -1;
    }
    else
    {
	 log->appendOk(TR("Sent goodbye to kernel."));
	 printf("\e[1;32mOk\e[0m.\n");
    }
  return 0;
}

int IQFInitializer::SendHello(QString &resultMsg)
{
	command hellocmd;
	hello_ok = true;
	int ret;
	char appn[32];
	memset(appn, 0, 32 * sizeof(char));
	strncpy(appn, appname.toStdString().c_str(), 31);
	if(build_hello_command(&hellocmd, appn) < 0)
	{
		hello_ok = false;
		resultMsg = "Error building the hello command";
	}
	else
	{
		nlctrl = IQFNetlinkControl::instance();
		if(nlctrl->SendCommand(&hellocmd) < 0)
		{
			hello_ok = false;
			QString error = QString(TR("IQFInitializer::SendHello(): failed sending hello!\n\"%1\""))
	    			.arg(libnetl_err_string() );
			if(getuid() != 0)
			{
			  error += "\n\nBe sure that the root user has executed\n\n"
				"\"/etc/init.d/rc.ipfire  start\"\n\n"
				"on a command line prompt, or that the command above\n"
				"is automatically executed at system boot.\n"
				"\nContact the administrator if in doubt.";
			}
			else
			{
			  error += "\nFailed to load the kernel module. This might be dued to a\n"
			    "kernel image upgrade or to a kernel rebuild. Please execute, as root\n"
			    "\"ipfire-kernel-rebuild\"";
			}
     			QMessageBox::critical(0, TR("Error: is kernel module loaded?"), error);
			resultMsg += QString("Failed to send the hello message to the kernel.\n"
					"(%1)").arg(libnetl_err_string());
      			log->appendFailed(error);
		}
		else
		{
			ret = nlctrl->ReadCommand(&hellocmd);
			if(ret < 0)
			{
				QString error = QString(TR("IQFInitializer::SendHello(): failed receiving hello confirmation!\n\"%1\""))
	    			.arg(libnetl_err_string() );
     				QMessageBox::critical(0, TR("Error"), error);
				resultMsg += QString("Failed to read the response to the hello command.\n"
						"(%1)").arg(libnetl_err_string());
      				log->appendFailed(error);
			}
			else if(ret != HELLO_OK)
			{
				if(hellocmd.cmd == IPFIRE_BUSY)
					resultMsg = QString("Initializing the user/kernel communication:\n"
						"another instance with pid %1 seems to be running.\n"
						"Maybe it was not closed properly.\n"
						"Try killing it with command \"kill %2\"\n"
						"If this does not help, the administrator will have to execute\n"
						"\"/etc/init.d/rc.ipfire  reload\n"
						"from a command line prompt.\n"
						"\nThis error is dued to an uncorrect program termination (a bug?).")
						.arg(hellocmd.anumber).arg(hellocmd.anumber);
					
				else
					resultMsg = "Error initializing the user/kernel communication.\n"
						"Try rebuilding iqfire-wall and ipfire-wall, both userspace\n"
						"and kernel space modules.";
				return hellocmd.cmd;
			}
			else
			{
				log->appendOk(TR("Sent hello to kernel."));
				return hellocmd.cmd;
			}
		}
	}
	return -1;
}

unsigned IQFInitializer::procSysNetCoreMemDefault()
{
	QSettings s;
	QString procfile = s.value("PROC_SYS_NET_CORE_RMEM_DEFAULT", 
		QString("/proc/sys/net/core/rmem_default")).toString();
	QFile file(procfile);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
				"Check the settings and verify that the proc file name is correct\n"
				"and that you have the permission to read it.").arg(procfile));
		return -1;
	}
	QTextStream in(&file);
	QString line = in.readLine();
	file.close();
	return line.toUInt();
}

unsigned IQFInitializer::procSysNetCoreMemMax()
{
	QSettings s;
	QString procfile = s.value("PROC_SYS_NET_CORE_RMEM_MAX", 
				   QString("/proc/sys/net/core/rmem_max")).toString();
	QFile file(procfile);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
				"Check the settings and verify that the proc file name is correct\n"
				"and that you have the permission to read it.").arg(procfile));
		return -1;
	}
	QTextStream in(&file);
	QString line = in.readLine();
	file.close();
	return line.toUInt();
}

/* returns 0 if default policy is accept, 1 otherwise
 * Returns -1 if error 
 */
short int IQFInitializer::procPolicy()
{
	QSettings s;
	QString procfile = s.value("PROC_IPFIRE_POLICY", 
				   QString("/proc/IPFIRE/policy")).toString();
	QFile file(procfile);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
				"Check the settings and verify that the proc file name is correct\n"
				"and that you have the permission to read it.").arg(procfile));
		return -1;
	}
	QTextStream in(&file);
	QString line = in.readLine();
	file.close();
	
	if(line.contains("accept"))
		  return 1;
	else
		return 0;
}

	
void IQFInitializer::setProcSysNetCoreMemDefault(unsigned n)
{
	QSettings s;
	QString procfile = s.value("PROC_SYS_NET_CORE_RMEM_DEFAULT", 
				   QString("/proc/sys/net/core/rmem_default")).toString();
	QFile file(procfile);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
				"Check the settings and verify that the proc file name is correct\n"
				"and that you have the permission to read it.").arg(procfile));
	}
	else
	{
		QTextStream out(&file);
		out << n;
		file.close();
	}
}

void IQFInitializer::setProcSysNetCoreMemMax(unsigned n)
{
	QSettings s;
	QString procfile = s.value("PROC_SYS_NET_CORE_RMEM_MAX", 
		QString("/proc/sys/net/core/rmem_max")).toString();
	QFile file(procfile);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
				"Check the settings and verify that the proc file name is correct\n"
				"and that you have the permission to read it.").arg(procfile));
	}
	else
	{
		QTextStream out(&file);
		out << n;
		file.close();
	}
}

void IQFInitializer::setProcPolicy(int policy)
{
	QSettings s;
	QString proc_str;
	QString procfile = s.value("PROC_IPFIRE_POLICY", 
				   QString("/proc/IPFIRE/policy")).toString();
	QFile file(procfile);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
				"Check the settings and verify that the proc file name is correct\n"
				"and that you have the permission to read it.").arg(procfile));
	}
	else
	{
		if(policy > 0)
			proc_str = "accept";
		else if(policy == 0)
			proc_str = "drop";
		else
		{
			Log::log()->appendFailed("IQFInitializer::setProcPolicy(int policy) parameter "
				"must be 0 or > 0");
			return;
		}
		QTextStream out(&file);
		out << proc_str;
		file.close();
	}
}



