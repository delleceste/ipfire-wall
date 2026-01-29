#include "iqfnetlink.h"
#include "iqflog.h"
#include <QtDebug>

IQFNetlinkControl *IQFNetlinkControl::_instance = NULL;

IQFNetlinkControl* IQFNetlinkControl::instance()
{
	if(_instance == NULL)
		return (_instance = new IQFNetlinkControl() );
	else
		return _instance;
}

IQFNetlinkControl::IQFNetlinkControl()
{
	/* Obtain an instance to the log console */
	log = Log::log();
	log->message(TR("\nCreating netlink socket..."));
	nh_control = alloc_netl_handle(NETLINK_IPFI_CONTROL);
	if(nh_control == NULL)
	{
		log->message(libnetl_err_string() );
		log->Failed();
	}
	else
		log->Ok();
}

IQFNetlinkControl::~IQFNetlinkControl()
{
	printf("\e[1;32m*\e[0m freeing control communication link...\t");
	netl_free_handle(nh_control);
	printf("\e[1;32mOk\e[0m.\n");
}

int IQFNetlinkControl::SendCommand(command *cmd)
{	
  int bytes_sent = 0;
  if( (bytes_sent = send_to_kernel((void *) cmd, 
	nh_control, CONTROL_DATA) ) < 0)
    {
      log->appendFailed(QString("IQFNetlinkControl::SendCommand() error: \"%1\"").
		  arg(libnetl_err_string() ) );
      return -1;
    } 
  /* each object to be sent is freed after being sent by send_to_kernel() */	
		
  return bytes_sent;
}

int IQFNetlinkControl::ReadCommand(command *cmdrec)
{	
  int bytes_read = 0;
	
  if( (bytes_read = read_from_kern(nh_control, (unsigned char*) cmdrec, 
				   sizeof(command) ) ) < 0)
    {
      log->appendFailed(QString("IQFNetlinkControl::ReadCommand() error: \"%1\"").
		  arg(libnetl_err_string() ) );
      return -1; /* abort further reading */
    }
		
  return bytes_read;
}

int IQFNetlinkControl::ReadStats(struct kernel_stats* kstats)
{
	int bytes_read = 0;
	
	if( (bytes_read = read_from_kern(nh_control, (unsigned char*) kstats, 
	     sizeof(struct kernel_stats) ) ) < 0)
	{
		log->appendFailed(QString("IQFNetlinkControl::ReadStats() error: \"%1\"").
				arg(libnetl_err_string() ) );
		return -1; /* abort further reading */
	}
		
	return bytes_read;
}

int IQFNetlinkControl::ReadStatsLight(struct kstats_light* kstatsl)
{
	int bytes_read = 0;
	
	if( (bytes_read = read_from_kern(nh_control, (unsigned char*) kstatsl, 
	     sizeof(struct kstats_light) ) ) < 0)
	{
		log->appendFailed(QString("IQFNetlinkControl::ReadStatsLight() error: \"%1\"").
				arg(libnetl_err_string() ) );
		return -1; /* abort further reading */
	}
		
	return bytes_read;
}


int IQFNetlinkControl::ReadStateTable(struct state_info *sti)
{
  int bytes_read = 0;
  if( (bytes_read = read_from_kern(nh_control, (unsigned char*) sti, sizeof(struct state_info) ) ) < 0)
  {
	log->appendFailed(QString("IQFNetlinkControl::ReadStateTable error: \"%1\"").arg(libnetl_err_string() ) );
	return -1; /* abort further reading */
  }	
  return bytes_read;
}

int IQFNetlinkControl::ReadSnatTable(struct snat_info *sni)
{
  int bytes_read = 0;
  if( (bytes_read = read_from_kern(nh_control, (unsigned char*) sni, sizeof(struct snat_info) ) ) < 0)
  {
	log->appendFailed(QString("IQFNetlinkControl::ReadSnatTable error: \"%1\"").arg(libnetl_err_string() ) );
	return -1; /* abort further reading */
  }	
  return bytes_read;
}

int IQFNetlinkControl::ReadDnatTable(struct dnat_info *dni)
{
  int bytes_read = 0;
  if( (bytes_read = read_from_kern(nh_control, (unsigned char*) dni, sizeof(struct dnat_info) ) ) < 0)
  {
	log->appendFailed(QString("IQFNetlinkControl::ReadDnatTable error: \"%1\"").arg(libnetl_err_string() ) );
	return -1; /* abort further reading */
  }	
  return bytes_read;
}

int IQFNetlinkControl::GetKtablesUsage(struct ktables_usage *ktu)
{
  int bytes_read = 0;
  command cmd;
  memset(&cmd, 0, sizeof(command) );
  cmd.cmd = PRINT_KTABLES_USAGE;
  
  if(SendCommand(&cmd) < 0) /* request */
    log->appendFailed("Failed to send request for kernel tables usage in IQFNetlinkControl::GetKtablesUsage()");
  else /* request ok, read response */
  {
    if( (bytes_read = read_from_kern(nh_control, (unsigned char*) ktu, sizeof(struct ktables_usage) ) ) < 0)
    {
	  log->appendFailed(QString("IQFNetlinkControl::GetKtablesUsage() error: \"%1\"").arg(libnetl_err_string() ) );
	  return -1; /* abort further reading */
    }
  }
  return bytes_read;
}

int IQFNetlinkControl::GetKtablesSizes(struct firesizes *fs)
{
  int bytes_read = 0;
  command cmd;
  memset(&cmd, 0, sizeof(command) );
  cmd.cmd = KSTRUCT_SIZES;
  
  if(SendCommand(&cmd) < 0) /* request */
    log->appendFailed("Failed to send request for kernel tables sizes in IQFNetlinkControl::GetKtablesSizes()");
  else /* request ok, read response */
  {
    if( (bytes_read = read_from_kern(nh_control, (unsigned char*) fs, sizeof(struct firesizes) ) ) < 0)
    {
	  log->appendFailed(QString("IQFNetlinkControl::GetKtablesSizes() error: \"%1\"").arg(libnetl_err_string() ) );
	  return -1; /* abort further reading */
    }
  }
  return bytes_read;
}


void IQFNetlinkControl::enableSilent(bool enabled)
{
	command cmd;	
	memset(&cmd, 0, sizeof(command) );
	cmd.is_rule = 0;
	/* not a rule, an option */
	cmd.options = 1;
	/* The passed value of enabled must be START_LOGUSER or
	* STOP_LOGUSER, defined in ipfire_userspace.h
	*/
	if(enabled)
	{
		cmd.cmd = STOP_LOGUSER;
		log->appendMsg("Changing silent modality to verbose...");
	}
	else
	{
		cmd.cmd = START_LOGUSER;
		log->appendMsg("Changing silent modality to silent...");
	}
	
	if(SendCommand(&cmd) < 0)
		log->Failed();
	else
		log->Ok();
}
		
bool IQFNetlinkControl::isSilentEnabled()
{
	command cmd;	
	memset(&cmd, 0, sizeof(command) );
	cmd.is_rule = 0;
	/* not a rule, an option */
	cmd.options = 1;
	/* The passed value of enabled must be START_LOGUSER or
	* STOP_LOGUSER, defined in ipfire_userspace.h
	*/
	cmd.cmd = IS_LOGUSER_ENABLED;
	log->appendMsg("Asking kernel for silent modality enabled/disabled...");
	if(SendCommand(&cmd) < 0)
		log->Failed();
	else
	{
		if(ReadCommand(&cmd) < 0)
			log->Failed();
		else
		{
			if(cmd.anumber == 0) /* silent */
			{
				log->message(" Silent modality.");
				return true;
			}
			else
			{
				log->message(" Verbose modality.");
				return false;
			}
		}
	}
	log->appendFailed("Unable to determine kernel/user communication modality. Supposing verbose.");
	return false;
}
		
void IQFNetlinkControl::enableStateLog(bool enable)
{
	
}






