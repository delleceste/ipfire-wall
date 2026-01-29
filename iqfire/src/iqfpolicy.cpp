#include "iqfpolicy.h"
#include "iqfnetlink.h"
#include "iqflog.h"
#include <colors.h>

#include <arpa/inet.h>

#include <QSettings> /* for the file names */
#include <QDir> /* for the home path */
#include <QtDebug>
#include <QMessageBox>

extern "C"
{
	int get_integer(const char* line);
	int get_string_n(char *string, const char* line, int limit);
	int get_address(struct in_addr *addr, const char* line);
	void init_rule(ipfire_rule* rule);
	void init_command(command* cmd);
	int get_string(char *string, const char* line);
	/* each element of the vector pointed by rules is copied in a 
 	 * command struct and then sent to kernel 
 	 */
	int send_rules_to_kernel(ipfire_rule* rules,  int nrules);
	int build_rule_command(command *cmd);
	#ifdef ENABLE_RULENAME
	void get_rule_name(const char* line, char* name);
	#endif
	
	/* save_rules() sends file pointer and a rule
	* to be written on file */
	int write_rule(FILE* fp, const ipfire_rule r, int index);

	/* writes headers in configuration files, i.e. comments
 	* to those files for a user who wants to explore them */
	void write_header(FILE* fp, int whichfile);
}

Policy* Policy::_instance = NULL;

Policy* Policy::instance()
{
	if(_instance == NULL)
		return (_instance = new Policy() );
	else
		return _instance;
}

Policy::Policy()
{
	allocation_succeeded = true;
	GetFileNames();
	if( AllocateRules() < 0)
		allocation_succeeded = false;	
	log = Log::log();
	memset(&d_nullRule, 0, sizeof(d_nullRule));
}

Policy::~Policy()
{
	
}

int Policy::setDenialRules(QVector <ipfire_rule> dr)
{
	int i;
	QVector<ipfire_rule> new_denial_rules;
	new_denial_rules.clear();
	for(i = 0; i < dr.size(); i++)
	{
		if(dr[i].owner == getuid())
		{
			dr[i].position = i + 1; /* Position starts from 1 */
			new_denial_rules.push_back(dr[i]);
		}
		else
		{
			log->appendFailed(QString("The denial rule \"%1\" hasn't been added because\n"
					"its owner is %2 and not %3!").arg(dr[i].rulename).arg(dr[i].owner).
				arg(getuid()));
			return -1;
		}
	}
	denial_rules = new_denial_rules;
	return denial_rules.size();
}
		
int Policy::setAcceptRules(QVector <ipfire_rule> ar)
{
	int i;
	QVector<ipfire_rule> new_accept_rules;
	new_accept_rules.clear();
	for(i = 0; i < ar.size(); i++)
	{
		if(ar[i].owner == getuid())
		{
			ar[i].position = i + 1; /* Position starts from 1 */
			new_accept_rules.push_back(ar[i]);		
		}
		else
		{
			log->appendFailed(QString("The permission rule \"%1\" hasn't been added because\n"
					"its owner is %2 and not %3!").arg(ar[i].rulename).arg(ar[i].owner).
					arg(getuid()));
			return -1;
		}
	}
	accept_rules = new_accept_rules;
	return accept_rules.size();
}
		
int Policy::setTranslationRules(QVector <ipfire_rule> tr)
{
	int i;
	QVector<ipfire_rule> new_translation_rules;
	new_translation_rules.clear();
	for(i = 0; i < tr.size(); i++)
	{
		if(tr[i].owner == getuid() && getuid() == 0)
		{
			tr[i].position = i + 1; /* Position starts from 1 */
			new_translation_rules.push_back(tr[i]);
		}
		else
		{
			log->appendFailed(QString("The translation rule \"%1\" hasn't been added because\n"
					"its owner is %2 and not %3!").arg(tr[i].rulename).arg(tr[i].owner).
					arg(getuid()));
			return -1;
		}
	}
	translation_rules = new_translation_rules;
	return translation_rules.size();
}

int Policy::AllocateRules()
{
	FILE *fp;
	int i;
	/* Denial rules */
	fp = fopen(blacklist_filename.toStdString().c_str(), "r");
	if(fp == NULL)
	{
		QMessageBox::critical(0, "Error allocating the rules", 
			QString("Error opening the file \"%1\" for reading the denial rules!\n(%2)").
			arg(blacklist_filename).arg(strerror(errno)));
		return -1;
	}
	else
	{
		denial_rules = parse_rulefile_and_alloc_ruleset(fp, DENIAL);
	}
	
	/* Permission rules */
	fp = fopen(permission_filename.toStdString().c_str(), "r");
	if(fp == NULL)
	{
		QMessageBox::critical(0, "Error", 
			QString("Error opening the file \"%1\" for reading the permission rules!\n(%2)").
			arg(permission_filename).arg(strerror(errno)));
		return -1;
	}
	else
	{
		accept_rules = parse_rulefile_and_alloc_ruleset(fp, ACCEPT);
	}
	
	if(getuid() == 0) /* Only root can read and allocate the translation rules */
	{
		fp = fopen(translation_filename.toStdString().c_str(), "r");
		if(fp == NULL)
		{
			QMessageBox::critical(0, "Error", 
				QString("Error opening the file \"%1\" for reading the translation rules!\n(%2)").
				arg(blacklist_filename).arg(strerror(errno)));
			return -1;
		}
		else
		{
			translation_rules = parse_rulefile_and_alloc_ruleset(fp, TRANSLATION);
		}
	}
	
	/* Set the position of the rule from our point of view.
	 * The position must start from 1 because it represents the
	 * response of the kernel firewall in case of denial and
	 * permission rules .
	 */
	for(i = 0; i < denial_rules.size(); i++)
	{
		
		denial_rules[i].position = i + 1; /* Position starts from 1 */
	}
	for(i = 0; i < accept_rules.size(); i++)
	{
		accept_rules[i].position = i + 1; /* Position starts from 1 */
	}
	for(i = 0; i < translation_rules.size(); i++)
		translation_rules[i].position = i + 1; /* Position starts from 1 */
	
	return denial_rules.size() + accept_rules.size() + translation_rules.size();
}
		
void Policy::ReloadRules()
{
	
}
		
int Policy::DeleteRule(int position)
{
	position = 0; /* Avoid warning */
	return 0;
}
		
int Policy::AddRUle(int position)
{
	position = 0; /* Avoid warning */
	return 0;	
}

int Policy::appendRule(ipfire_rule& rule)
{
	/* be sure about the owner */
	rule.owner = getuid();
	switch(rule.nflags.policy)
	{
		case ACCEPT:
			/* The rule position is at the tail of the vector.
			 * The vector will grow of one element and the position
			 * starts from 1.
			 */
			rule.position = accept_rules.size() + 1;
			accept_rules.push_back(rule);
			updateAcceptRules();
			break;
		case DENIAL:
			rule.position = denial_rules.size() + 1;
			denial_rules.push_back(rule);
			updateDenialRules();
			break;
		case TRANSLATION:
			rule.position = translation_rules.size() + 1;
			translation_rules.push_back(rule);
			updateTranslationRules();
			break;
		default:
			qDebug() << "Invalid policy " << rule.nflags.policy << 
				"(int Policy::appendRule(ipfire_rule& rule) )";
			return -1;
			break;
	}
	return 0;
}

void Policy::GetFileNames()
{
	QSettings s;
	if(!s.contains("PERMISSION_FILENAME")) /* first time */
		s.setValue("PERMISSION_FILENAME", QVariant(QDir::homePath() + QString("/.IPFIRE/allowed")));
	if(!s.contains("BLACKLIST_FILENAME")) /* first time */
		s.setValue("BLACKLIST_FILENAME", QVariant(QDir::homePath() + QString("/.IPFIRE/blacklist")));
	
	if(getuid() == 0)
		if(!s.contains("TRANSLATION_FILENAME")) /* first time */
			s.setValue("TRANSLATION_FILENAME", QDir::homePath() + "/.IPFIRE/translation");			
		
	blacklist_filename = s.value("BLACKLIST_FILENAME", 
		QVariant(QDir::homePath() + QString("/.IPFIRE/blacklist"))).toString();
	translation_filename = s.value("TRANSLATION_FILENAME",
		QVariant(QDir::homePath() + QString("/.IPFIRE/translation"))).toString();
	blacksites_filename = s.value("BLACKSITES_FILENAME",
		QVariant(QDir::homePath() + QString("/.IPFIRE/blacksites"))).toString();
	permission_filename = s.value("PERMISSION_FILENAME",
		QVariant(QDir::homePath() + QString("/.IPFIRE/blacksites"))).toString();
	
// 	qDebug() << "GetFileNames() filenames: " << permission_filename<< blacklist_filename  <<
// 		translation_filename << blacksites_filename;
}

ipfire_rule *Policy::ToLowLevelRulePointer(QVector<ipfire_rule *> in)
{
	int i;
	ipfire_rule * vrules;
	
	vrules = (ipfire_rule *) malloc(sizeof(ipfire_rule) * in.size() );	
	if(vrules == NULL)
		QMessageBox::critical(0, "Error!", "Error allocating rule pointer!");
	else
	{
		for(i = 0; i < in.size(); i++)
			memcpy(&vrules[i], in[i], sizeof(ipfire_rule));
	}
	return vrules;
}

/** Calls SendRulesToKernel for each vector of rules */
int Policy::SendAllRulesToKernel()
{
	if(SendRulesToKernel(denial_rules) < 0)
    	{
    		QMessageBox::critical(0, "Error", 
			("Error sending denial rules to kernel space!"));
		return -1;
    	}
	if(SendRulesToKernel(accept_rules) < 0)
    	{
    		QMessageBox::critical(0, "Error", 
			("Error sending permission rules to kernel space!"));
		return -1;
    	}
	if(getuid() == 0)
	{		
		if(SendRulesToKernel(translation_rules) < 0)
    		{
    			QMessageBox::critical(0, "Error", 
				("Error sending translation rules to kernel space!"));
			return -1;
    		}
	}
	return 0;
}

int Policy::SendRulesToKernel(QVector<ipfire_rule > rules)
{	
  int i, bytes_read;
  command cmd, cmd_ack;
	
  IQFNetlinkControl *iqfnl = IQFNetlinkControl::instance();
	
  for(i=0; i < rules.size(); i++)
    {
      init_command(&cmd);
      build_rule_command(&cmd);
      /* now copy the rule at position i in the appropriate field of cmd */
      memcpy(&cmd.content.rule, &rules[i], sizeof(ipfire_rule) );

      /* send rule to kernel */
      if(iqfnl->SendCommand(&cmd) < 0)
	{
	  log->appendFailed(QString("send_rules_to_kernel(): error sending rule %1 to kernel!").arg(i+1));
	  return -1;
	}
      /* after sending the rule in kernel space, we wait for an acknowledgment */
      if( (bytes_read = iqfnl->ReadCommand( &cmd_ack ) ) < 0)
	{
		log->appendFailed(QString("Error getting acknowledgment from kernel!\n(%1)"));
	  	return -1; /* abort further reading */
	}
      else
	{
	  if(cmd_ack.cmd == RULE_ALREADY_PRESENT)
	  {
	    log->appendFailed(QString("Rule %1 (\"%2\") already present. Not loaded again.").arg(
		   cmd.content.rule.position).arg(rules[i].rulename));
// 		 log->appendFailed(QString("Rule %1 (\"%2\") already present. Not loaded again.").arg(
// 		   i).arg(rules[i].rulename));
	  }
	  else if(cmd_ack.cmd == RULE_NOT_ADDED_NO_PERM)
		  log->appendFailed("RULE NOT ADDED: YOU DON'T HAVE THE PERMISSION\n"
			"TO ADD RULES TO FIREWALL. CONTACT ADMINISTRATOR.\n");
	}
    }
  return 0;
}

/* This is private and is called by updateXXXRules() */
void Policy::updateRules(int policy)
{
	QString strpolicy;
	command flush_cmd;
	
	IQFNetlinkControl* iqfnl = IQFNetlinkControl::instance();
	
	memset(&flush_cmd, 0, sizeof(command));
	
	switch(policy)
	{
		case DENIAL:
			flush_cmd.cmd = FLUSH_DENIAL_RULES;	/* flush specified ruleset */
			strpolicy = "denial";
			break;
		case ACCEPT:
			flush_cmd.cmd = FLUSH_PERMISSION_RULES; /* flush specified ruleset */
			strpolicy = "permission";
			break;
		case TRANSLATION:
			if(getuid() == 0)
			{
				flush_cmd.cmd = FLUSH_TRANSLATION_RULES;
				strpolicy = "translation";
			}
			else
			{
				qDebug() << "error: cannot call this if you are not root!";
				log->appendFailed("error: updateRules(): cannot call this if you are not root!");
				return;
			}
			break;
		default:
			qDebug() << "updateRules: invalid policy " << policy;
			return;
	}		
		
	if(iqfnl->SendCommand(&flush_cmd) < 0)
	{
		log->appendFailed("Failed to send the flush command to the kernel");
		return;
	}

	memset(&flush_cmd, 0, sizeof(command));
	/* the kernel will respond */
	if(iqfnl->ReadCommand(&flush_cmd) < 0)
	{
		log->appendFailed("Failed to read the confirmation for the flush command from the kernel");
		return;
	}
	
	/* Check the response from the kernel */
	if(flush_cmd.cmd == FLUSH_RULES) /* cmd must be of this type... */
		log->appendOk(QString("Flushed %1 %2 rules before reloading them.").arg(flush_cmd.anumber).
			     arg(strpolicy));
	else 	/* ...otherwise we have received something wrong */
		log->appendFailed(QString("The kernel responded %1 instead of %2 for the flush request").
			arg(flush_cmd.cmd).arg(FLUSH_RULES));
	
	/* Ok the rules of the specified policy have been flushed. Now reload them */
	switch(policy)
	{
		case DENIAL:
			if(SendRulesToKernel(denial_rules) < 0)
			{
				log->appendFailed(QString("Failed to send %1 denial rules to the kernel").
					arg(denial_rules.size()));
			}
			else
				log->appendOk(QString("Successfully updated %1 denial rules.").arg(denial_rules.size()));
			break;
		case ACCEPT:
			if(SendRulesToKernel(accept_rules) < 0)
			{
				log->appendFailed(QString("Failed to send %1 permission rules to the kernel").
					arg(accept_rules.size()));
			}
			else
				log->appendOk(QString("Successfully updated %1 permission rules.").arg(accept_rules.size()));
			break;
		case TRANSLATION:
			if(getuid() == 0)
			{
				if(SendRulesToKernel(translation_rules) < 0)
				{
					log->appendFailed(QString("Failed to send %1 translation rules to the kernel").
							arg(translation_rules.size()));
				}
				else
					log->appendOk(QString("Successfully updated %1 translation rules.").
						arg(translation_rules.size()));
			}
			else
			{
				qDebug() << "error: cannot call this if you are not root!";
				log->appendFailed("error: updateRules(): cannot call this if you are not root!");
				return;
			}
			break;
		default:
			qDebug() << "updateRules: invalid policy " << policy;
			return;
	}
	/* after sending the rules to the kernel we read them again, so that we are sure that there are 
	 * no duplicated rules in the ruleset.
	 * denial_rules, accept_rules, translation_rules are passed by reference and refilled by GetCurrentUser...
	 */
	GetCurrentUserKernelRules(denial_rules, accept_rules, translation_rules);
	/* now denial_rules, accept_rules, translation_rules contain exactly a copy of the kernel rules.
	 * A subsequent call to saveRules will save the clean ruleset present into the kernel
	 */ 
	return;
}

int Policy::GetCurrentUserKernelRules(QVector<ipfire_rule > &v_den,
				   QVector<ipfire_rule > &v_acc,
				   QVector<ipfire_rule > &v_tr)
{
  int ret;
  QVector<ipfire_rule> denr, accr, transr;
  v_den.clear();
  v_acc.clear();
  
  ret = GetKernelRules(denr, accr, transr);
  
  foreach(ipfire_rule rule, denr)
    if(rule.owner == getuid())
      v_den.push_back(rule);
    
  foreach(ipfire_rule rule, accr)
    if(rule.owner == getuid())
      v_acc.push_back(rule);
   
  if(getuid() == 0)
  {
    v_tr.clear();
    foreach(ipfire_rule rule, transr)
      if(rule.owner == getuid())
	v_tr.push_back(rule);
  }
  return ret;
}

void Policy::updateAcceptRules()
{
	QSettings s;
	updateRules(ACCEPT);
	if(s.value("AUTOSAVE_RULES_ON_CHANGE").toBool() == true)
		saveRules();
}
		
void Policy::updateTranslationRules()
{
	QSettings s;
	updateRules(TRANSLATION);
	if(s.value("AUTOSAVE_RULES_ON_CHANGE").toBool() == true)
		saveRules();
}

void Policy::updateDenialRules()
{
	QSettings s;
	updateRules(DENIAL);
	if(s.value("AUTOSAVE_RULES_ON_CHANGE").toBool() == true)
		saveRules();
}

/* manages saving all rules (3 vectors)
 * calls write_header() and write_rule()
 * to write each rule on each file 
 * Taken from ipfire_userspace.c and adapted
 */
void Policy::saveRules()
{	
	FILE* fp;
	int rnum = 0;	
	int i, total_rules;
	int rulecount = 0;
	short whichfile = 0;
	char filename[MAXFILENAMELEN];
	QVector <ipfire_rule> rules;
	
	/* DENIAL is 0 ... TRANSLATION is 2 */
	total_rules = denial_rules.size() + accept_rules.size();
	if(getuid() == 0)
		total_rules +=  translation_rules.size();
	
	emit saveProgressMaximum(total_rules);
	
	while(whichfile < 3)
	{
		if(whichfile == DENIAL) 
		{
			strncpy(filename, blacklist_filename.toStdString().c_str(), 
				MAXFILENAMELEN);
			rules = denial_rules;
			rnum = denial_rules.size();
		} 
		else if(whichfile ==  ACCEPT) 
		{  
			strncpy(filename, permission_filename.toStdString().c_str(), 
				MAXFILENAMELEN);
			rules = accept_rules;
			rnum = accept_rules.size();
		}
		else if(whichfile == TRANSLATION)
		{
			strncpy(filename, translation_filename.toStdString().c_str(),
				MAXFILENAMELEN);
			rules = translation_rules;
			rnum = translation_rules.size();
		}
		
		
		
		fp = fopen(filename, "w");
		if(fp == NULL)
		{
			Log::log()->appendFailed(QString("Error opening file: \"%1\" (%2)").arg(filename).arg(strerror(errno)));
			return;
		}
		/* write something on top of files to describe them */
		write_header(fp, whichfile);
		
		i = 0;
		while(i < rnum)
		{
			write_rule(fp, rules[i], i);
// 			qDebug() << "option mss" << rules[i].pkmangle.mss.enabled << rules[i].pkmangle.mss.option;
			i++;
			rulecount++;
			emit saveProgressChanged(rulecount);
		}
		/* write the keyword "END" at end of rules */
		if(rnum > 0)
			fprintf(fp, "END");
		Log::log()->appendOk(QString("Successfully saved the rules on the file: \"%1\"")
			.arg(filename));
		fclose(fp);
		fp = NULL;
		whichfile ++;
	  /* We have saved allowed and blacklist: if we are not
	  * root we have finished */
		if(whichfile == TRANSLATION && getuid() != 0)
			break;
	} /* while */
	
	return;
}




QVector<ipfire_rule > Policy::parse_rulefile_and_alloc_ruleset
	(FILE* fp, int whichfile)
{
  unsigned ruleno = 0, i = 0;
  unsigned linenum = 0;
  char line[MAXLINELEN];
  char key[MAXLINELEN];
  short next_policy_is_blacksite = 0;
	
#ifdef ENABLE_RULENAME
  char rulename[RULENAMELEN];
#endif
  struct in_addr address;
  ipfire_rule arule;
  short protocol;
  short tyos;
  u16 total_len;
  u16 sport;
  u16 dport;
  char devicename[IFNAMSIZ];
  init_rule(&arule);
  
  QVector <ipfire_rule > rules;
  rules.clear();
  
  while(fgets(line, MAXLINELEN, fp) != NULL)
    {
      linenum++;
      /* delete endline */
      if(strlen(line) > 0 && line[strlen(line)-1] == '\n')
	line[strlen(line)-1]='\0';
    
      /* start reading file */
      if(strncmp(line, "#", 1) == 0)
	;
      else if(strncmp(line, "INDEVICE=", 9) == 0)
	{
	  get_string(devicename, line);
	  strncpy(arule.devpar.in_devname, devicename, IFNAMSIZ);
	  arule.nflags.indev = 1;
	}
      else if(strncmp(line, "OUTDEVICE=", 10) == 0)
	{
	  get_string(devicename, line);
	  strncpy(arule.devpar.out_devname, devicename, IFNAMSIZ);
	  arule.nflags.outdev = 1;
	}
	 else if(strncmp(line, "_END_SRCADDR=", 13) == 0)
	{
	  if( arule.nflags.src_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.samean = INTERVAL;
	      arule.ip.ipsrc[1] = address.s_addr;
	    }
	  else
	    perror("Error getting source address from line");
	}
      else if(strncmp(line, "_END_SRCADDR_NOT=", 17) == 0)
	{
	  if( arule.nflags.src_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.samean = INTERVAL_DIFFERENT_FROM;
	      arule.ip.ipsrc[1] = address.s_addr;
	    }
	  else
	    perror("Error getting source address from line");
	}
      else if(strncmp(line, "MYSRCADDR", 9) == 0)
	{
	  if(arule.nflags.src_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.src_addr = MYADDR;	
	      arule.parmean.samean = SINGLE;
	    }					
	}
      else if(strncmp(line, "MYSRCADDR_NOT", 13) == 0)
	{
	  if(arule.nflags.src_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.src_addr = MYADDR;	
	      arule.parmean.samean = DIFFERENT_FROM;					
	    }					
	}
      else if(strncmp(line, "_END_DSTADDR=", 13) == 0)
	{
	  if(arule.nflags.dst_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.damean = INTERVAL;
	      arule.ip.ipdst[1] = address.s_addr;
	    }
	  else
	    perror("Error getting destination address from line");
	}
      else if(strncmp(line, "_END_DSTADDR_NOT=", 17) == 0)
	{
	  if(arule.nflags.dst_addr != ONEADDR)
	    goto error_nofirst_interval;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.parmean.damean = INTERVAL_DIFFERENT_FROM;
	      arule.ip.ipdst[1] = address.s_addr;
	    }
	  else
	    perror("Error getting destination address from line");
	}
      /* let kernel select our interface address depending on
       * direction of packet */
      else if(strncmp(line, "MYDSTADDR", 9) == 0)
	{
	  if(arule.nflags.dst_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.dst_addr = MYADDR;
	      arule.parmean.damean = SINGLE;
	    }					
	}
      else if(strncmp(line, "MYDSTADDR_NOT", 13) == 0)
	{
	  if(arule.nflags.dst_addr)
	    goto conflicting_parameters;
	  else
	    {
	      arule.nflags.dst_addr = MYADDR;
	      arule.parmean.damean = DIFFERENT_FROM;
	    }
	}
      else if(strncmp(line, "PROTOCOL=", 9) == 0)
	{
	  protocol = (short) get_integer(line);
	  /* [...] do some checkin' before assignment! */
	  arule.ip.protocol = protocol;
	  arule.nflags.proto = 1;
	}
      else if(strncmp(line, "TOTAL_LENGTH=", 13) == 0)
	{
	  total_len = (u16) get_integer(line);
	  /* [...] do some checkin' before assignment! */
	  arule.ip.total_length = total_len;
	  arule.nflags.tot_len = 1;
	}
      else if(strncmp(line, "TOS=", 4) == 0)
	{
	  tyos = (u8) get_integer(line);
	  /* [...] do some checkin' before assignment! */
	  arule.ip.tos = tyos;
	  arule.nflags.tos = 1;
	}
        else if(strncmp(line, "_END_SRCPORT=", 13) == 0)
	{
	  if(! arule.nflags.src_port)
	    goto error_nofirst_interval;
	  sport= htons( (u16) get_integer(line) );
	  arule.tp.sport[1] = sport;
	  /* [...] checks! */
	  arule.parmean.spmean=INTERVAL;
	}
      else if(strncmp(line, "_END_DSTPORT=", 13) == 0)
	{
	  if(! arule.nflags.dst_port)
	    goto error_nofirst_interval;
				
	  arule.tp.dport[1] = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.parmean.dpmean=INTERVAL;
	}
      else if(strncmp(line, "SYN=TRUE", 8) == 0)
	{
	  arule.nflags.syn=1;
	  arule.tp.syn = 1;
	}
      else if(strncmp(line, "FIN=TRUE", 8) == 0)
	{
	  arule.nflags.fin=1;
	  arule.tp.fin = 1;
	}
      else if(strncmp(line, "PSH=TRUE", 8) == 0)
	{
	  arule.nflags.psh=1;
	  arule.tp.psh = 1;
	}
      else if(strncmp(line, "ACK=TRUE", 8) == 0)
	{
	  arule.nflags.ack=1;
	  arule.tp.ack = 1;
	}
      else if(strncmp(line, "RST=TRUE", 8) == 0)
	{
	  arule.nflags.rst=1;
	  arule.tp.rst = 1;
	}
      else if(strncmp(line, "URG=TRUE", 8) == 0)
	{
	  arule.nflags.urg=1;
	  arule.tp.urg= 1;
	}
      /* false versions */
      else if(strncmp(line, "SYN=FALSE", 9) == 0)
	{
	  arule.nflags.syn=1;
	  arule.tp.syn = 0;
	}
      else if(strncmp(line, "FIN=FALSE", 9) == 0)
	{
	  arule.nflags.fin=1;
	  arule.tp.fin = 0;
	}
      else if(strncmp(line, "PSH=FALSE", 9) == 0)
	{
	  arule.nflags.psh=1;
	  arule.tp.psh = 0;
	}
      else if(strncmp(line, "ACK=FALSE", 9) == 0)
	{
	  arule.nflags.ack=1;
	  arule.tp.ack = 0;
	}
      else if(strncmp(line, "RST=FALSE", 9) == 0)
	{
	  arule.nflags.rst=1;
	  arule.tp.rst = 0;
	}
      else if(strncmp(line, "URG=FALSE", 9) == 0)
	{
	  arule.nflags.urg=1;
	  arule.tp.urg= 0;
	}	
      /* icmp related */
      else if(strncmp(line, "ICMP_TYPE=", 10) == 0)
	{
	  arule.nflags.icmp_type = 1;
	  arule.icmp_p.type = (u8) get_integer(line);
	}
      else if(strncmp(line, "ICMP_CODE=", 10) == 0)
	{
	  arule.nflags.icmp_code = 1;
	  arule.icmp_p.code = (u8) get_integer(line);
	}
      else if(strncmp(line, "ICMP_ECHO_ID=", 12) == 0)
	{
	  arule.nflags.icmp_echo_id = 1;
	  arule.icmp_p.echo_id = (u16) get_integer(line);
	}
      else if(strncmp(line, "ICMP_ECHO_SEQ=", 13) == 0)
	{
	  arule.nflags.icmp_echo_seq= 1;
	  arule.icmp_p.echo_seq = (u16) get_integer(line);
	}
      /* frag mtu removed */
      /* direction of the packet */
      else if(strncmp(line, "DIRECTION=INPUT", 15) == 0)
	arule.direction = IPFI_INPUT;
      else if(strncmp(line, "DIRECTION=OUTPUT", 16) == 0)
	arule.direction = IPFI_OUTPUT;
      else if(strncmp(line, "DIRECTION=FORWARD", 17) == 0)
	arule.direction = IPFI_FWD;
      else if(strncmp(line, "DIRECTION=POST", 14) == 0)
	arule.direction = IPFI_OUTPUT_POST;
      else if(strncmp(line, "DIRECTION=PRE", 13) == 0)
	arule.direction = IPFI_INPUT_PRE;
      /* state connection tracking / nat / masquerading options */
      else if(strncmp(line, "KEEP_STATE=YES", 14) == 0)
	 arule.state = arule.nflags.state  = 1;
      else if(strncmp(line, "FTP_SUPPORT=YES", 14) == 0)
	arule.nflags.ftp = 1;
      else if(strncmp(line, "NOTIFY=YES", 14) == 0)
	      arule.notify = 1;
      else if(strncmp(line, "NAT=YES", 7) == 0)
	arule.nat = 1;
      else if(strncmp(line, "SNAT=YES", 8) == 0)
	{
	  arule.nat = 1;
	  arule.snat = 1;
	}
      else if(strncmp(line, "MASQUERADE=YES", 14) == 0 )
	{
	  arule.masquerade = 1;
	}
      else if(strncmp(line, "NATURAL_LANGUAGE=YES", 20) == 0)
      {
		arule.natural = 1;
      }
      else if(strncmp(line, "NEWADDR=", 8) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.newaddr = 1;
	      arule.newaddr = address.s_addr;
	    }
	  else
	    perror("Error getting source address from line");
	}
      else if(strncmp(line, "NEWPORT=", 8) == 0)
	{
	  arule.newport = htons( (u16) get_integer(line) );
	  arule.nflags.newport = 1;
	}
      /*
       * packet mangling options 
       */
      else if(strncmp(line, "MSS_VALUE=TO_PMTU", 17) == 0)
      {
	arule.pkmangle.mss.enabled = 1;
	arule.pkmangle.mss.option = ADJUST_MSS_TO_PMTU;
      }
      else if(strncmp(line, "MSS_VALUE=", 10) == 0)
      {
	if(arule.ip.protocol == IPPROTO_TCP)
	{
	  arule.pkmangle.mss.enabled = 1;
	  arule.pkmangle.mss.option = MSS_VALUE;
	  arule.pkmangle.mss.mss = (u16) get_integer(line);
	}
	else
	  printf(TR("MSS_VALUE mangle option is only available for TCP protocol"));
      }
	
      else if(strncmp(line, "NAME=", 5) == 0)
	{
#ifdef ENABLE_RULENAME
	  get_rule_name(line, rulename);
	  strncpy(arule.rulename, rulename, RULENAMELEN);
#else  /* warn user */
	  printf(VIOLET "WARNING" CLR ": option \"NAME\" is disabled.\n"
		 "If you want to enable it, you must compile IPFIRE with\n"
		 "option \"ENABLE_RULENAME\", " UNDERL RED "both" NL
		 "in userspace program and in kernel modules. See manual\n"
		 "for further explanation." NL );
#endif
	}
     /* Start parsing lines which might indicate multiple values */
     /* ============================================== */
     /* source address(es) */
     i = 0;
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "SRCADDR%d=" : "SRCADDR="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.src_addr = ONEADDR;
	      arule.ip.ipsrc[i] = address.s_addr;
	      struct in_addr ina, ina0;
	      ina.s_addr = arule.ip.ipsrc[i];
	     if(i > 0)
	      {
		arule.parmean.samean = MULTI;
				
	      }
	    }
	  else
	    perror("Error getting source address from line");
	}
	i++;
     }
     i = 0;
     /* destination address(es) */ 
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "DSTADDR%d=" : "DSTADDR="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.dst_addr = ONEADDR;
	      arule.ip.ipdst[i] = address.s_addr;
	      if(i > 0)
	      {
		arule.parmean.damean = MULTI;
// 		struct in_addr ina;
// 		ina.s_addr = arule.ip.ipdst[i];
// 		printf("multiple destination address: element %d: %s\n", i, inet_ntoa(ina));
	      }
	    }
	  else
	    perror("Error getting destination address from line");
	}	
	i++;
     }
     i = 0;
     /* destination address(es), "different from" */ 
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "SRCADDR%d_NOT=" : "SRCADDR_NOT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  /* rimosso dalla versione MULTI */
// 	  if(arule.nflags.src_addr)
// 	    goto conflicting_parameters;
				
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.src_addr = ONEADDR;
	      arule.ip.ipsrc[i] = address.s_addr;
	      if(i == 0)
		arule.parmean.samean = DIFFERENT_FROM;
	      else
	      {
		arule.parmean.samean = MULTI_DIFFERENT;
// 		struct in_addr ina;
// 		ina.s_addr = arule.ip.ipsrc[i];
// 		printf("multiple source addresses DIFFERENT FROM: element %d: %s\n", i, inet_ntoa(ina));
	      }
	    }
	  else
	    perror("Error getting source address from line");
	}
	i++;
     }
     i = 0;
     /* multiple destination addresses different from */
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "DSTADDR%d_NOT=" : "DSTADDR_NOT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  if(get_address(&address, line) > 0)
	    {
	      arule.nflags.dst_addr = ONEADDR;
	      arule.ip.ipdst[i] = address.s_addr;
	      if(i == 0)
		arule.parmean.damean = DIFFERENT_FROM;
	      else
	      {
		arule.parmean.damean = MULTI_DIFFERENT;
// 		struct in_addr ina;
// 		ina.s_addr = arule.ip.ipdst[i];
// 		printf("multiple destination addresses DIFFERENT FROM: element %d: %s\n", i, inet_ntoa(ina));
	      }
	    }
	  else
	    perror("Error getting source address from line");
	}
	i++;
     }
     
     /* PORTS */
      i = 0;
     /* multiple source ports */
     while(i < MAXMULTILEN)
     {
	snprintf(key, MAXLINELEN, (i > 0 ? "SRCPORT%d=" : "SRCPORT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  sport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.sport[i]=sport;
	  arule.nflags.src_port=1;
	  if(i > 0)
	  {
	    arule.parmean.spmean = MULTI;
// 	    printf("multiple source ports: element %d: %d\n", i, ntohs(sport));
	  }
	}
	i++;
     }
 
     i = 0;
     /* multiple destination ports */
     while(i < MAXMULTILEN)
     {
        snprintf(key, MAXLINELEN, (i > 0 ? "DSTPORT%d=" : "DSTPORT="), i + 1);
	if(strncmp(line,key, strlen(key)) == 0)
	{
	  dport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.dport[i]=dport;
	  arule.nflags.dst_port=1;
	  if(i > 0)
	  {
	    arule.parmean.dpmean = MULTI;
// 	    printf("multiple destination ports: element %d: %d\n", i, ntohs(dport));
	  }
	}
	i++;
     }
     
     i = 0;
     /* multiple source ports different from */
     while(i < MAXMULTILEN)
     {
        snprintf(key, MAXLINELEN, (i > 0 ? "SRCPORT%d_NOT=" : "SRCPORT_NOT="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  sport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.sport[i]=sport;
	  arule.nflags.src_port=1;
	  if(i ==0)
	    arule.parmean.spmean = DIFFERENT_FROM;
	  else
	  {
	    arule.parmean.spmean = MULTI_DIFFERENT;
// 	    printf("multiple source ports different from: element %d: %d\n", i, ntohs(sport));
	  }
	}
	i++;
     }
     
     i = 0;
     /* multiple destination ports different from */
     while(i < MAXMULTILEN)
     {
        snprintf(key, MAXLINELEN, (i > 0 ? "DSTPORT%d_NOT=" : "DSTPORT_NOT="), i + 1);
	if(strncmp(line, key, strlen(key)) == 0)
	{
	  dport = htons( (u16) get_integer(line) );
	  /* [...] checks! */
	  arule.tp.dport[i]=dport;
	  arule.nflags.dst_port=1;
	  if(i ==0)
	    arule.parmean.dpmean = DIFFERENT_FROM;
	  else
	  {
	    arule.parmean.dpmean = MULTI_DIFFERENT;
// 	    printf("multiple destination ports different from: element %d: %d\n", i, ntohs(dport));
	  }
	}
	i++;
     }
     /* Finished parsing multiple elements :P */
     /* ===================================== */
      if(  ( (strncmp(line, "RULE", 4) == 0)  && ( ruleno > 0) ) ||
		( (strncmp(line, "BSRULE", 6) == 0)  && ( ruleno > 0) ) |
		( (strncmp(line, "END", 3) == 0)   && ( ruleno > 0) )   )   
	{
	  /* set the right policy, depending on the file we are parsing */			
	  /* if previously next_policy_is_blacksite was set */
	  if(next_policy_is_blacksite)
	    arule.nflags.policy = BLACKSITE;
	  else /* policy depends on file we are reading */
	    arule.nflags.policy = whichfile;
				
	  if(arule.direction != NODIRECTION)
	    arule.nflags.direction = 1;
	  else
	    arule.nflags.direction = 0;
	  /* is this a blacksite rule? If yes, modify policy */
	  if( (strncmp(line, "BSRULE", 6) == 0) &&
	      (whichfile == DENIAL) )
	    next_policy_is_blacksite = 1;
	  else
	    next_policy_is_blacksite = 0;
	  /* set the owner of the rule */
	  arule.owner = getuid();
	  if(arule.direction == NODIRECTION)
	    {
	      printf("Error: parameter \"DIRECTION=OUTPUT|PRE|POST|INPUT|FORWARD\""
		     "\nnot specified and the rule is a nat/masquerading one!\n"
		     "I won't add any rule from this configuraton file!\n");
	      printf("RULE N. %d\n", ruleno);
	      goto error;
					
	    }
	  arule.position = rules.size() + 1;
	  rules.push_back(arule);
	  if(strncmp(line, "END", 3) == 0) /* found last rule */
	    return rules;
	  
	  ruleno++;
	  init_rule(&arule);			/* reinitialize rule */
	  arule.direction = 0;
	  arule.ip.protocol = IPPROTO_IP; /* dummy protocol */
	  
	}
      else if( (strncmp(line, "RULE", 4) == 0) && (ruleno == 0) ) 
	{
	  /* 1st rule declaration */
	  ruleno++;
	  next_policy_is_blacksite = 0; /* 1st rule not a blacksite one */
	}
      else if( (strncmp(line, "BSRULE", 6) == 0) && (ruleno == 0) )
	{
	  ruleno++;
	  next_policy_is_blacksite = 1; /* 1st rule blacksite */
	}				
//       else
// 	printf("Keyword \"%s\" at line %d not valid!\n", line, linenum);
    }
  return rules; /* number of rules read if file is empty */
 error:
  return rules;
 error_nofirst_interval:
  printf("You can't specify an end interval without first specifying\n"
	 "the first value of the interval itself! (line %d)",
	 linenum);
  return rules;
 conflicting_parameters:
  printf("You specified a value for a parameter and now you mean\n"
	 "the opposite: bad! Check line %d.", linenum);
	
  return rules;
}

/* returns all the rules loaded into the kernel. Updates adm_xxx_rules with the root rules
 */
int Policy::GetKernelRules(QVector<ipfire_rule > &v_den,
		QVector<ipfire_rule > &v_acc,
     		QVector<ipfire_rule > &v_tr)
{
	ipfire_rule dummy_rule;
	command rule;
	command rulelist_req;
	init_rule(&dummy_rule);
	unsigned counter = 0;
	rulelist_req.cmd = PRINT_RULES;
	
	/* Initialize vectors */
	v_den.clear();
	v_acc.clear();
	v_tr.clear();
	
	IQFNetlinkControl *iqfnl = IQFNetlinkControl::instance();
	
	if(iqfnl->SendCommand(&rulelist_req) < 0)
	{
		log->appendFailed(QString("Error sending rule list request"));
		return -1;
	}
	
	while(1)
	{
		counter ++;
		if(iqfnl->ReadCommand(&rule) < 0)
		{
			log->appendFailed(QString("Error sending rule list request:\n(%1)"));
			return -1;
		}
		if(rule.cmd == PRINT_FINISHED)
		{
			/* Rule list finishes */
			break;
		}
		else
		{
			switch(rule.content.rule.nflags.policy)
			{
				case DENIAL:
					if(rule.content.rule.owner == 0)
					  adm_denial_rules.push_back(rule.content.rule);
					v_den.push_back(rule.content.rule);
					break;
				case ACCEPT:
					if(rule.content.rule.owner == 0)
					  adm_accept_rules.push_back(rule.content.rule);
					v_acc.push_back(rule.content.rule);
					break;
				case TRANSLATION:
					if(rule.content.rule.owner == 0)
					  adm_translation_rules.push_back(rule.content.rule);
					v_tr.push_back(rule.content.rule);
				break;
				default:
					log->appendFailed(QString("Unrecognized policy %1")
							.arg(rule.content.rule.nflags.policy));
					break;	
			}
		}
	}
	return 0;
}

/* Updates all rules in the kernel.
 * First flushes the current rules, then writes 
 * the new ones.
 * Verifies the UID before updating the rules, 
 * updating just the user's rules.
 * Let's say it does extra checks, because the all_rules 
 * vector should be already ready with the user's rules.
 */
void Policy::updateAllKernelRules(QVector<ipfire_rule *> all_rules)
{
	Q_UNUSED(all_rules);
}

QList<unsigned int> Policy::rulesNumbers()
{
	QVector<ipfire_rule > v_den, v_acc, v_tr;
	QList <unsigned int> rstats;
	if(GetKernelRules(v_den, v_acc, v_tr) < 0)
		Log::log()->appendFailed("QList<unsigned int> Policy::rulesNumbers():"
			" error getting kernel rules");
	else
	{
		rstats << v_den.size() << v_acc.size() << v_tr.size();	
	}
	return rstats;
}

/* returns by reference one of the rules stored in the permission vectors or the 
 * d_nullRule class null rule.
 */
ipfire_rule& Policy::permissionRuleByPosition(int pos, bool admin)
{
  int i;
  if(admin)
  {
    for(i = 0; i < adm_accept_rules.size(); i++)
    {
      if(adm_accept_rules[i].position == pos)
	return adm_accept_rules[i];
    }
  }
  else
  {
    for(i = 0; i < accept_rules.size(); i++)
    {
      if(accept_rules[i].position == pos)
	return accept_rules[i];
    }
  }
  return d_nullRule;
}

