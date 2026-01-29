#ifndef IQFIRE_DATA_H
#define IQFIRE_DATA_H


#include "iqflog.h"
#include "iqfiredata.h"
#include "iqfnetlink.h"
#include <QSettings>
#include <QString>
#include <QDir>
#include <QtDebug>
#include <QFile>
#include <QTextStream>

extern"C"
{
	/* initializes file names to default values */
     int init_useropts(struct userspace_opts *uops);
     void init_cmdopts(struct cmdopts* cmdo);
     void init_command(command* cmd);
     int build_option_command(command* cmd);


	/* if type is USERNAME, user name is copied in info,
 	* else if type is HOMEDIR, home directory name is
 	* copied in info */
	int get_user_info(int type, char* info);

	/* transforms user name to upper case, after
 	* getting it by means of get_user_info() */
	void toupper_username(char* upperun);

	int check_proc_entries(short policy, unsigned proc_rmem_max, unsigned proc_rmem_default);
}

IQFireData* IQFireData::iqfdata_instance = NULL;

IQFireData* IQFireData::instance(int argc, char** argv)
{
	Q_UNUSED(argc);
	Q_UNUSED(argv);
	if(iqfdata_instance == NULL)
		return (iqfdata_instance = new IQFireData(argc, argv) );
	else
		return iqfdata_instance;
}

IQFireData::IQFireData(int argc, char** argv)
{
	Q_UNUSED(argc);
	Q_UNUSED(argv);
	/* Useth locally */
	command hellocmd, tmp_cmd;
	
  	init_cmdopts(&prog_ops);
 	init_useropts(&uops);
  	init_command(&opts);		/* all fields put to 0 */
  	init_command(&hellocmd);
	init_command(&tmp_cmd);
	
	/* Obtain an instance to the log console */
	debug = Log::log();
  	
  	toupper_username(upper_username);
	debug->message(TR("Getting configuration from the settings..."));
  	if(GetIQFConfigFromFile(&tmp_cmd, &uops) == 0)
	{
		debug->Ok();
		/* there are a couple of options which we copy also in prog_ops..
		 * will we really need it? 
		 */
		if(getuid() == 0) /* apply options if root */
		{
			memcpy(&opts, &tmp_cmd, sizeof(opts));
			prog_ops.user_allowed = opts.user_allowed;
			prog_ops.noflush_on_exit = opts.noflush_on_exit;
			debug->message("Applying values to /proc entries if needed...");
			if(check_proc_entries(uops.policy, uops.proc_rmem_max, uops.proc_rmem_default) >= 0)
				debug->Ok();
			else
				debug->Failed();
		}
		else
			debug->appendMsg("You are not root: no options will be applied.");
	}
// 	debug->message(TR("Getting command line arguments"));
//   	GetIQFConfigFromCmdLine(argc, argv);
// 	debug->Ok();
}

IQFireData::~IQFireData()
{

}

int IQFireData::GetIQFConfigFromFile(command *com, struct userspace_opts *uops)
{
	QSettings s;
	build_option_command(com); /* in common.c: initializes all values to reasonable ones :r */
// 	init_useropts(uops);
	/* Read all the settings from the ipfire configuration file for full compatibility */
	QString optionsFileName = s.value("IPFIRE_CONFDIR", 
		QVariant(QDir::homePath() + QString("/.IPFIRE/options"))).toString();
	QFile optFile(optionsFileName);
	if(!optFile.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open file \"%1\" for reading (%2)").
			arg(optionsFileName).arg(optFile.error()));
		return -1;
	}
	
	QString option = "";
	
	QTextStream in(&optFile);
	
	while (!in.atEnd()) 
	{
		option = in.readLine();
		if(!option.startsWith("#"))
		{
			if(option.contains("NAT=YES"))
				com->nat = true;
	
			if(option.contains("MASQUERADE=YES"))
				com->masquerade = true;
		
			if(option.contains("STATEFUL=YES"))
				com->stateful = true;
		
			if(option.contains("ALL_STATEFUL=YES"))
				com->all_stateful = true;

			if(option.contains("USER_ALLOWED=YES"))
				com->user_allowed = true;
		
			if(option.contains("NOFLUSH_ON_EXIT=YES"))
				com->noflush_on_exit = true;
		
			if(option.contains("LOGINFO_LIFETIME="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					com->loginfo_lifetime = splitted[1].toUInt();
			}
		
			if(option.contains("MAX_LOGINFO_ENTRIES="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					com->max_loginfo_entries = splitted[1].toUInt();
			}	
		
		
			if(option.contains("MAX_NAT_ENTRIES="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					com->max_nat_entries = splitted[1].toUInt();
			}	
		
		
			if(option.contains("MAX_STATE_ENTRIES="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					com->max_state_entries = splitted[1].toUInt();
			}
			if(option.contains("LOGUSER="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					com->loguser = splitted[1].toUInt();
			}	
			if(option.contains("LOGLEVEL="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					com->loglevel = splitted[1].toUInt();
			}
			if(uops != NULL && option.contains("PROC_RMEM_DEFAULT="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					uops->proc_rmem_default = splitted[1].toInt();
			}
			if(uops != NULL && option.contains("PROC_RMEM_MAX="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					uops->proc_rmem_max = splitted[1].toInt();
			}
			if(uops != NULL && option.contains("PROC_IPFIRE_POLICY="))
			{
				QStringList splitted = option.split("=");
				if(splitted.size() == 2)
					uops->policy = splitted[1].toInt();
			}	
			
		} /* if (!options.startsWith("#")) */
		/* controllare da interfaccia */
		/* check_max_lifetime_values(&opts); */
	}
	/* Go on with normal user settings */
	/* Removed loglevel and loguser for now */
// 	uops.dns_resolver = s.value("DNS_RESOLVE", QVariant(0)).toBool();
// 	uops.dns_refresh = s.value("DNS_REFRESH", QVariant(1800)).toUInt();
// 	/* uops filenames have been initialized by init_useropts */
// 	mailer_options_filename = s.value("MAILER_OPTIONS_FILENAME", 
// 		QVariant(QDir::homePath() + QString("/.IPFIRE/mailer/options")))
// 		.toString();
// 	
// 	language_filename = s.value("LANGUAGE_FILENAME", QVariant("")).toString();
	optFile.close();
	return 0;
}

int IQFireData::GetIQFConfigFromCmdLine(int argc, char **argv)
{
	Q_UNUSED(argc);
	Q_UNUSED(argv);
	return 0;
}

int IQFireData::sendOptionsToKernel(command *opts)
{
	if(opts != NULL)
	{
		opts->cmd = OPTIONS;
		opts->options=1;
		/* there is no rule in an option command: create a dummy rule */
		memset(&opts->content.rule, 0, sizeof(opts->content.rule) );
		
		if(IQFNetlinkControl::instance()->SendCommand(opts) < 0)
		{
			Log::log()->appendFailed("There was an error sending options to the kernel");
			return -1;
		}
		else
		{
			if(IQFNetlinkControl::instance()->ReadCommand(opts) < 0)
			{
				Log::log()->appendFailed("Error getting a response from the kernel about options");
				return -1;
			}
			else
			{
				if(opts->cmd == IPFIRE_BUSY)
				{
					Log::log()->appendFailed(QString("The firewall seems to be busy:\n"
					"is another instance already running, with pid %1?").
							arg(opts->anumber));
					return -1;
				}
				else
					Log::log()->appendOk("New options sent to the kernel");
			}
		}	
	}
	return 0;
}

void IQFireData::initCommand(command *com)
{
	init_command(com);
}

#endif






