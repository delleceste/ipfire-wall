#include "rule_builder.h"
#include "iqfruletree.h"
#include "iqf_message_proxy.h"
#include "macros.h"
#include <QString>
#include <QtDebug>
#include <QStringList>
#include <QTreeWidgetItem>
#include <QMessageBox>

/* address manipulation */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SOURCE 	0
#define DEST	1

RuleBuilder::RuleBuilder()
{
  rule = NULL;
  rule = (ipfire_rule *) malloc(sizeof(ipfire_rule));
  init_rule(rule);
  _ruleValid = true;
}

RuleBuilder::RuleBuilder(ipfire_rule arule)
{
  rule = NULL;
  rule = (ipfire_rule *) malloc(sizeof(ipfire_rule));
	memcpy(rule, &arule, sizeof(ipfire_rule));
	_ruleValid = true;
}

RuleBuilder::~RuleBuilder()
{
	if(rule)
	  free(rule);
}

void RuleBuilder::init()
{
	init_rule(rule);
}

bool RuleBuilder::isAny(QString &s)
{
	if( (s.contains("-") && s.length() == 1) ||
		(s.compare("any", Qt::CaseInsensitive) == 0) ||
	  	s.length() == 0)
		return true;
	else
		return false;
}

void RuleBuilder::setPolicy(int p)
{
	if(p != ACCEPT && p != DENIAL && p != TRANSLATION &&
		  p != BLACKSITE)
		_ruleValid = false, _failureReasons << " invalid policy ";
	else
		rule->nflags.policy = p;
}

void RuleBuilder::setPolicy(QString p)
{
	if(p == "ACCEPT")
		rule->nflags.policy = ACCEPT;
	else if(p == "DENIAL")
		rule->nflags.policy = DENIAL;
	else if(p == "TRANSLATION")
		rule->nflags.policy = TRANSLATION;
	else if(p == "BLACKSITE")
		rule->nflags.policy = BLACKSITE;
	else /* cannot be something else, nor any */
		_ruleValid = false, _failureReasons << " invalid policy ";
}
		
void RuleBuilder::setInDevname(QString dname)
{
	if(isAny(dname))
		return;
	if(!dname.contains("-") && !dname.isEmpty())
	{
		memset(rule->devpar.in_devname, 0, IFNAMSIZ);
		strncpy(rule->devpar.in_devname, dname.toStdString().c_str(), IFNAMSIZ-1);
		rule->nflags.indev = 1;
	}
}
		
void RuleBuilder::setOutDevname(QString dname)
{
	if(isAny(dname))
		return;
	if(!dname.contains("-") && !dname.isEmpty())
	{
		memset(rule->devpar.out_devname, 0, IFNAMSIZ);
		strncpy(rule->devpar.out_devname, dname.toStdString().c_str(), IFNAMSIZ-1);
		rule->nflags.outdev = 1;
	}
}
		
void RuleBuilder::setSip(QString s)
{
	QString original = s;
	QString copy = s;
	char addr[MAXLINELEN]; /* This will store the address */
	
	if(isAny(s))
		return;
	
	if(s.contains("MY", Qt::CaseInsensitive) || s.contains("my", Qt::CaseInsensitive) 
		  || s.contains("ADDR", Qt::CaseInsensitive))
		copy = "me";
	
	if(s.contains("!") || s.contains("NOT", Qt::CaseInsensitive))
		s = QString("! %1").arg(copy).remove("NOT").remove("IN");
	else
		s = copy;
	
	memset(addr, 0, MAXLINELEN);
	strncpy(addr, s.toStdString().c_str(), MAXLINELEN - 1);
	int ret;
	if((ret = ip_helper(addr, SOURCE) )< 0)
	{
		QMessageBox::information(0, "Error in source address",
			QString("The input %1 does not represent a valid\n"
				"address or interval of addresses.\n"
				"The accepted syntax is the following:\n"
				"192.168.0.2 (single address)\n"
				"!192.168.0.2 (address different from this)\n"
					"192.168.0.0 - 192.168.0.255 (an interval)\n"
					"192.168.0.0/24 (address/decimal netmask)\n"
					"192.168.0.0/255.255.255.0 (address/netmask)\n").
					arg(original));
		_ruleValid = false;
		_failureReasons << QString(" invalid source ip address \"%1\" ").arg
				(original);
	}
	////  qDebug()<< "ip_helper ritornato per sip" << ret;
}
		
void RuleBuilder::setDip(QString s)
{
	char addr[MAXLINELEN]; /* This will store the address */
	QString original = s;
	QString copy = s;
	
	if(isAny(s))
		return;
	
	if(s.contains("MY", Qt::CaseInsensitive) || s.contains("my", Qt::CaseInsensitive) 
		  || s.contains("ADDR", Qt::CaseInsensitive))
		copy = "me";
	
	if(s.contains("!") || s.contains("NOT", Qt::CaseInsensitive))
		s = QString("! %1").arg(copy).remove("NOT").remove("IN");
	else 
		s = copy;
	
	memset(addr, 0, MAXLINELEN);
	strncpy(addr, s.toStdString().c_str(), MAXLINELEN - 1);
	////  qDebug()<< "dip: chiamo ip_helper con: " << s;
	int ret;
	if((ret = ip_helper(addr, DEST)) < 0)
	{
		QMessageBox::information(0, "Error in destination address",
			QString("The input %1 does not represent a valid\n"
				"address or interval of addresses.\n"
				"The accepted syntax is the following:\n"
			 	"192.168.0.2 (single address)\n"
				"!192.168.0.2 (address different from this)\n"
				"192.168.0.0 - 192.168.0.255 (an interval)\n"
				"!192.168.0.0 - 192.168.0.255 (not inside the specified interval)\n"
				"192.168.0.0/24 (address/decimal netmask)\n"
				"192.168.0.0/255.255.255.0 (address/netmask)\n").
					arg(original));
		_ruleValid = false;
		_failureReasons << QString(" invalid destination ip address \"%1\" ").arg
				(original);
	}
	////  qDebug()<< "ip_helper ritornato per dip" << ret;
}
		
void RuleBuilder::setSport(QString s)
{	
	if(isAny(s))
		return;
	char *tmp;
	tmp = new char[s.length() + 1];
	memset(tmp, 0, sizeof(char) * (s.length() + 1));
	strncpy(tmp, s.toStdString().c_str(), s.length() + 1);
	////  qDebug()<< "Port helper: chiamo con stringa " << s;
	if(port_helper(tmp, SOURCE) < 0)
	{
		QMessageBox::information(0, "Error in the source port syntax",
					 QString("The input %1 does not represent a valid\n"
							 "port or interval of ports.\n"
							 "The accepted syntax is the following:\n"
							 "5000 (single port)\n"
							 "!5000 (port different from this)\n"
							 "5000 - 6000  (an interval)\n"
							 "!5000 - 6000 (not in this interval)\n").
							 arg(s));
		_ruleValid = false;
		_failureReasons << QString(" invalid source port \"%1\" ").arg
				(s);
	}
	delete tmp;
}
		
void RuleBuilder::setDport(QString s)
{
	if(isAny(s))
		return;
	char *tmp;
	tmp = new char[s.length() + 1];
	memset(tmp, 0, sizeof(char) * (s.length() + 1));
	strncpy(tmp, s.toStdString().c_str(), s.length() + 1);
	if(port_helper(tmp, DEST) < 0)
	{
		QMessageBox::information(0, "Error in the destination port syntax",
					 QString("The input %1 does not represent a valid\n"
							 "port or interval of ports.\n"
							 "The accepted syntax is the following:\n"
							 "5000 (single port)\n"
							 "!5000 (port different from this)\n"
							 "5000 - 6000  (an interval)\n"
							 "!5000 - 6000 (not in this interval)\n").
							 arg(s));
		_ruleValid = false;
		_failureReasons << QString(" invalid destination port \"%1\" ").arg
				(s);
	}
	delete tmp;
}
		
void RuleBuilder::setOwner(int uid)
{
	rule->owner = uid;
}
		
void RuleBuilder::setOwner(QString username)
{
	struct passwd* pwd;
	pwd = getpwnam(username.toStdString().c_str());
	if(pwd == NULL)
	{
		QMessageBox::information(0, "Warning", 
			QString("There is no user ID corresponding to the name \"%1\"\n"
			"Setting your user id instead (%2)").arg(username).arg(getuid()));
		rule->owner = getuid();
	}
	else
		rule->owner = pwd->pw_uid;	
}
		
/* TCP, UDP, ICMP */ 
void RuleBuilder::setProtocol(QString p)
{
	if(p.contains("any", Qt::CaseInsensitive)
		  || p.contains("-"))
	{
		rule->nflags.proto = 0;
	}
	else
	{ 
		rule->nflags.proto = 1;
		if(p == "TCP")
			rule->ip.protocol = IPPROTO_TCP;
		else if(p == "UDP")
			rule->ip.protocol = IPPROTO_UDP;
		else if( p == "ICMP")
			rule->ip.protocol = IPPROTO_ICMP;
		else if( p == "IGMP")
			rule->ip.protocol = IPPROTO_IGMP;
		else 
		{
			QMessageBox::information(0, "Error",
				QString("The protocol \"%1\" is not valid!").arg(p));
			rule->nflags.proto = 0;
			_ruleValid = false;
			_failureReasons << QString(" invalid protocol \"%1\" ").arg
					(p);
		}
	}
}

void RuleBuilder::setDirection(int d)
{
	rule->nflags.direction = 1;
	rule->direction = d;
}
				
void RuleBuilder::setDirection(QString d)
{
	rule->nflags.direction = 1;
	if(d == "INPUT" || d == "IN")
		rule->direction = IPFI_INPUT;
	else if(d == "OUTPUT" || d == "OUT")
		rule->direction = IPFI_OUTPUT;
	else if(d == "FWD" || d == "FORWARD")
		rule->direction = IPFI_FWD;
	else if(d == "PRE" || d == "PREROUTING" || d == "PRE ROUTING")
		rule->direction = IPFI_INPUT_PRE;
	else if(d == "POST" || d == "POSTROUTING"|| d == "POST ROUTING")
		rule->direction = IPFI_OUTPUT_POST;
	else 
	{
		QMessageBox::information(0, "Error specifying the direction",
			QString("The direction \"%1\" is not valid!\n"
			       "The possibilities are:\n"
			       "INPUT or IN (for packets coming INTO the machine)\n"
			       "OUTPUT  or OUT (for packets going OUT from the machine or OUT DNAT)\n"
			       "FORWARD or FWD (for packets to be forwarded from this \n"
			       "                machine to another)\n"
			       "PRE or PREROUTING (for DNAT)\n"
			       "POST or POSTROUTING (for SNAT or MASQUERADE)").arg(d));
		rule->nflags.direction = 0;
		_ruleValid = false;
		_failureReasons << QString(" invalid direction \"%1\" ").arg
				(d);
	}
		
}
		
/* This accepts NAT, SNAT, MASQUERADE or MASQ */
void RuleBuilder::setNatType(QString type)
{
	if(type == "SNAT" || type == "SOURCE NAT")
	{
		rule->nat = rule->snat = 1;
	}
	else if(type == "DNAT" || type == "DESTINATION NAT")
		rule->nat = 1;
	else if(type == "MASQ" || type == "MASQUERADE")
		rule->masquerade = 1;
	else
	{
		QMessageBox::information(0, "Error specifying the NAT type",
			QString("The type \"%1\" is not valid!\n"
				"The possibilities are:\n"
				"SNAT or SOURCE NAT\n"
			        "DNAT or DESTINATION NAT\n"
			        "MASQ or MASQUERADE").arg(type));
		_ruleValid = false;
		_failureReasons << QString(" invalid nat type \"%1\" ").arg
				(type);
	}
		
}
		
/* flags must be 
 * SYN on ACK off URG off [...]
 * as built by rule_stringifier and separated
 * by spaces 
 */
void RuleBuilder::setFlags(QString flags)
{
	if(flags.contains("SYN on", Qt::CaseInsensitive))
		rule->nflags.syn = rule->tp.syn = 1;
	else if(flags.contains("SYN off", Qt::CaseInsensitive))
		rule->nflags.syn =1, rule->tp.syn = 0
				;
	if(flags.contains("ACK on", Qt::CaseInsensitive))
		rule->nflags.ack = rule->tp.ack = 1;
	else if(flags.contains("ACK off", Qt::CaseInsensitive))
		rule->nflags.ack =1, rule->tp.ack = 0;
				
	if(flags.contains("URG on", Qt::CaseInsensitive))
		rule->nflags.urg = rule->tp.urg = 1;
	else if(flags.contains("URG off", Qt::CaseInsensitive))
		rule->nflags.urg = 1, rule->tp.urg = 0;
	
	if(flags.contains("FIN on", Qt::CaseInsensitive))
		rule->nflags.fin = rule->tp.fin = 1;
	else if(flags.contains("FIN off", Qt::CaseInsensitive))
		rule->nflags.fin = 1, rule->tp.fin = 0;
	
	if(flags.contains("PSH on", Qt::CaseInsensitive))
		rule->nflags.psh = rule->tp.psh = 1;
	else if(flags.contains("PSH off", Qt::CaseInsensitive))
		rule->nflags.psh = 1, rule->tp.psh = 0;
	
	if(flags.contains("RST on", Qt::CaseInsensitive))
		rule->nflags.rst = rule->tp.rst = 1;
	else if(flags.contains("RST off", Qt::CaseInsensitive))
		rule->nflags.rst = 1, rule->tp.rst = 0;
}
		
/* state can be 
 * YES
 * or
 * NO
 */
void RuleBuilder::setState(QString state)
{
	if(state.contains("YES", Qt::CaseInsensitive))
		rule->state = rule->nflags.state = 1;
	else
		rule->state = rule->nflags.state = 0;
}
		
void RuleBuilder::setNotify(QString noti)	
{
	if(noti.contains("YES", Qt::CaseInsensitive))
		rule->notify = 1;
	else
		rule->notify = 0;
}	

void RuleBuilder::setFTP(QString ftp)
{
	if(ftp.contains("YES", Qt::CaseInsensitive))
		rule->nflags.ftp = 1;
	else
		rule->nflags.ftp = 0;
}		
		
void RuleBuilder::setName(QString name)
{
	if(name.length() > RULENAMELEN - 1)
		QMessageBox::information(0, "Rule name too long!",
			QString("Error the name \"%1\" is too long!\n"
				"The maximum number of characters is %2.\n"
			       "The name will be truncated").
					arg(name).arg(RULENAMELEN));
	memset(rule->rulename, 0, RULENAMELEN);
	strncpy(rule->rulename, name.toStdString().c_str(), RULENAMELEN - 1);
}		
		
		
void RuleBuilder::setNewIP(QString ip)
{
	if(ip.contains("-") || ip.count('.') != 3)
		return;
	struct in_addr add;

	if(inet_pton(AF_INET, ip.toStdString().c_str(), &add) <= 0)
	{
		QMessageBox::information(0, "Error in input address for NAT",
			QString("The address \"%1\" is not a valid IPv4 address!").
					arg(ip));
		_ruleValid = false;
		_failureReasons << QString(" invalid new ip address \"%1\" ").arg
				(ip);
	}
	else
	{
		rule->nflags.newaddr = 1;
		rule->newaddr = add.s_addr;
	}
}

void RuleBuilder::setNewPort(QString port)
{
	////  qDebug()<< "setNEWDport" << port;
	if(port.contains('-') || port.toInt() == 0)
		return;
	if( (port.toInt() < MINPORT) || (port.toUInt() > MAXPORT) )
	{
		QMessageBox::information(0, "Error in the input port for NAT",
			QString("The port \"%1\" is out of the allowed range %2-%3").
				arg(port).arg(MINPORT).arg(MAXPORT));
		_ruleValid = false;
		_failureReasons << QString(" invalid new port \"%1\" ").arg
				(port);
	}
	else
	{
		rule->newport = htons( (u16) (port.toUInt()) );
		rule->nflags.newport = 1;
	}
}

void RuleBuilder::setMssOption(int opt)
{
  rule->pkmangle.mss.enabled = 1;
  rule->pkmangle.mss.option = opt;
}

void RuleBuilder::setMssValue(unsigned short value)
{
  rule->pkmangle.mss.enabled = 1;
  rule->pkmangle.mss.option = MSS_VALUE;
  rule->pkmangle.mss.mss = value;
}

void RuleBuilder::setOptions(QString s)
{
  qDebug() << "setto mss con stringa s " << s;
  bool ok;
  if(s.contains("FTP_SUPPORT=YES"))
    rule->nflags.ftp = 1;
  QRegExp mssRe("MSS=(\\d\\d\\d{0,1}\\d{0,1})");
  int pos = mssRe.indexIn(s);
  QStringList list = mssRe.capturedTexts();
  qDebug() << "captured list" << list;
  if(list.size() == 2 && list.at(1).toUInt(&ok) > 40 && list.at(1).toUInt(&ok) < 1460 && ok)
  {
    rule->pkmangle.mss.enabled = 1;
    rule->pkmangle.mss.option = MSS_VALUE;
    rule->pkmangle.mss.mss = list.at(1).toUInt();
  }
  else if(s.contains("MSS") && s.contains("PMTU"))
  {
     rule->pkmangle.mss.enabled = 1;
     rule->pkmangle.mss.option = ADJUST_MSS_TO_PMTU;
  }
  else if(s == "-" || s.isEmpty())
    rule->pkmangle.mss.enabled = 0;
  else if(!rule->nflags.ftp) /* this is a minimal check! Pass it if FTP_SUPPORT=YES was found */
  {
    QMessageBox::information(0, "Error setting options", QString(
      "The option \"%1\" for the MSS manipulation or FTP support is not correct:\n"
      "Possible values for FTP support are:\n"
      "FTP_SUPPORT=YES\n"
      "Possible values for MSS options are:\n"
      "\"MTU=X\", being X an integer greater than 40 and less than or equal to 1460;\n"
      "\"MTU=TO_PMTU\", an advanced (and recommended) setting to let the firewall\n"
      "correctly setup the Maximum Segment Size on the basis of the path MTU discovery.").
      arg(s));
      _ruleValid = false;
      _failureReasons << QString("The MSS setting \"%1\" is not correct. Set it through the Add Rule "
       " interface if in doubt").arg(s);
  }
}

/* Taken from the ipfi lib, but without the fgets() obviously */
int RuleBuilder::get_line(char * dest)
{
	//fgets(dest, MAXLINELEN, stdin);
	/* throw away newline */
	if(strlen(dest) > 0)
	{
		if(dest[strlen(dest) - 1] == '\n')
			dest[strlen(dest) - 1] = '\0';
	}
	if( (strlen(dest) == 1) && (strncmp(dest, "x", 1) == 0) )
		return -1;
	else if(strlen(dest) == 0)
		return 0;
	return 1;
}

int RuleBuilder::ip_helper(char* addr, int direction)
{
	int ret;
	ipfire_rule *r = rule;
	QString qsip = QString(addr);
	
	if( (ret = get_line(addr) ) < 0)
		return -1;
	else if(ret == 0)
		return 0;
	
	if(qsip.contains("any", Qt::CaseInsensitive))
		return 0;
	
	if(strlen(addr) == 0)
		return -1;
	if(addr[0] == '!') /* address different from */
	{
		remove_exclmark(addr);
		qsip = QString(addr); /* QString without leading ! */
		if(strcmp(addr, "me") == 0 )
		{
			if(direction == SOURCE)
			{
				r->nflags.src_addr = MYADDR;
				r->parmean.samean = DIFFERENT_FROM;
			}
			else if(direction == DEST)
			{
				r->nflags.dst_addr = MYADDR;
				r->parmean.damean = DIFFERENT_FROM;
			}
			else
			{
				return -1;
			}
			return 1;
		}
		
      /* is_cidr, in ipfire_userspace.c, finds if
		* addr is expressed in the form 
		* x.y.z.w/a.b.c.d or x.y.z.w/n. cidr_to_interval(),
      * transforms cidr notation in interval notation */
		else if(qsip.contains(','))
		{
		   if(this->fillIPList(qsip, r, direction, true))
		     return 1;
		   else
		     return -1;
		}
		else if( is_cidr(addr) == 1 )
		{
			if(cidr_to_interval(addr) < 0)
				return -1;
		}
		
		if(is_interval(addr) )
		{
			if(fill_not_ip_interval(addr, r, direction) < 0)
				return -1;
		}
		else
		{
			if(fill_not_ip(addr, r, direction) < 0)
				return -1;
		}
		return 1;
	}
	else
	{
		if(strcmp(addr, "me") == 0)
		{
			if(direction == SOURCE)
			{
				r->nflags.src_addr = MYADDR;
				r->parmean.samean = SINGLE;
			}
			else if(direction == DEST)
			{
				r->nflags.dst_addr = MYADDR;
				r->parmean.damean = SINGLE;
			}
			else
			{
				return -1;
			}
			return 1;
		}
		
		if(qsip.contains(','))
		{
		  if(this->fillIPList(qsip, r, direction, false))
		    return 1;
		  return -1;
		}
		else /* old code is ok, with commonlib */
		{
		    if(is_cidr(addr) )
			    if(cidr_to_interval(addr) < 0)
				    return -1;
		    
		    if(is_interval(addr) )
		    {
			    if(fill_ip_interval(addr, r, direction) < 0)
				    return -1;
			    return 1;
		    }
		    else 
		    {
			    if(fill_plain_address(addr, r, direction) < 0)
				    return -1;
		    }
		}
	}
	return 1;
}


int RuleBuilder::port_helper(char* port, int direction)
{
	ipfire_rule *r = rule;
	int ret;
	QString qsport(port);
	
	
	if( (ret = get_line(port) ) < 0)
		return -1;
	if(qsport.contains("any", Qt::CaseInsensitive))
		return 0;
	if(qsport.contains("-") && !qsport.contains(QRegExp("[0-9]")))
		return 0;
				
	else if(ret == 0)
		return 0;

	if(strlen(port) == 0)
		return -1;
	
	if(port[0] == '!') /* address different from */
	{
		remove_exclmark(port);
		qsport = QString(port); /* QString without exclamation mark */
		if(qsport.contains(','))
		{
		  /* true to signal DIFFERENT, direction for SOURCE */
		  if(this->fillPortList(qsport, r, direction, true))
		    return 1;
		  return -1;
		}
		else if(is_interval(port) )
		{
			if(fill_not_port_interval(port, r, direction) < 0)
				return -1;
		}
		else
		{
			if(fill_not_port(port, r, direction) < 0)
				return -1;
		}
		return 1;
	}
	else if(qsport.contains(','))
	{
		/* true to signal DIFFERENT, direction for SOURCE */
		if(this->fillPortList(qsport, r, direction, false))
		  return 1;
		return -1;
	}
	else if(is_interval(port) )
	{
		if(fill_port_interval(port, r, direction) < 0)
			return -1;
		return 1;
	}
	else 
	{
		if(fill_plain_port(port, r, direction) < 0)
			return -1;
	}
	return 1;
	
}

QString RuleBuilder::failuresHtmlRepresentation()
{
	QString h;
	
	h += "<div id=\"content\">";
	
	h += "<style type=\"text/css\"> .content { background-color:rgb(255, 100, 100); }";
	
	h += "<h4>The rule is not correct, for the following reasons:</h4>";
	
	h += "<p><ul>";
	
	for(int i = 0; i < _failureReasons.size(); i++)
	{
		h += QString("<li>%1</li>").arg(_failureReasons[i]);
	}
	
	h += "</style>";
			
	h += "</p></ul>";
	
	h += "</div>";
	
	QString html = IQFMessageProxy::msgproxy()->insertInfoIntoHtmlHeader(h);
	return html;
}

bool RuleBuilder::fillIPList(QString ip, ipfire_rule* prule, int direction, bool different)
{
  QStringList ips;
  int i = 0;
  qDebug() << "FILL IP LIS: " << ip;
  ips = ip.split(',', QString::SkipEmptyParts);
  __u32 address;
  if(ips.size() > 1)
  {
    foreach(QString ip, ips)
    {
      ip = ip.trimmed();
      if( i < MAXMULTILEN)
      {
	qDebug() << "stringa ip " << ip;
	 if(inet_pton(AF_INET, ip.toStdString().c_str(), &address) <= 0)
	  {
	    QMessageBox::information(0, "Error in inet_pton()", QString("Cannot convert %1 into an IP address").arg(ip));
	    return -1;
	  }
	if(direction == SOURCE)
	{
	  prule->ip.ipsrc[i] = address;
	  prule->nflags.src_addr = ONEADDR;
	  if(different)
	    prule->parmean.samean = MULTI_DIFFERENT;
	  else
	     prule->parmean.samean = MULTI;
	  struct in_addr ina;
	  ina.s_addr = prule->ip.ipsrc[i];
	  ////  qDebug()<< "++++++++++++++++ source ip added: " << inet_ntoa(ina);
	}
	else if(direction == DEST)
	 {
	  prule->ip.ipdst[i] = address;
	  prule->nflags.dst_addr = ONEADDR;
	  if(different)
	    prule->parmean.damean = MULTI_DIFFERENT;
	  else
	     prule->parmean.damean = MULTI;
	  struct in_addr ina;
	   ina.s_addr = prule->ip.ipdst[i];
	}
	else
	{
	  return false;
	}
      }
      else /* leave cycle */
	break;
      i++;
    }
    return true;
  }
  else
    return false;
}

bool RuleBuilder::fillPortList(QString pts, ipfire_rule* prule, int direction, bool different)
{
  QStringList ports;
  int i = 0;
  bool ok;
  ports = pts.split(',', QString::SkipEmptyParts);
  ////  qDebug()<< "Porte in fillPortList(): " << ports;
  if(ports.size() > 1)
  {
    foreach(QString p, ports)
    {
      p = p.trimmed();
      int port = p.toInt(&ok);
      if(port <= 0 || port > 65535 || !ok)
      {
	QMessageBox::information(0, "Error", QString("Port %1 out of range (0-65535) or cannot convert!").arg(p));
	return false;
      }
      __u16 shport = p.toUShort();
      if( i < MAXMULTILEN)
      {
	if(direction == SOURCE)
	{
	  prule->tp.sport[i] = htons(shport);
	  prule->nflags.src_port = 1;
	  if(different)
	    prule->parmean.spmean = MULTI_DIFFERENT;
	  else
	    prule->parmean.spmean = MULTI;
	  ////  qDebug()<< "++++++++++++ spirce port added : " << ntohs(prule->tp.sport[i]);
	}
	else if(direction == DEST)
	{
	  prule->tp.dport[i] = htons(shport);
	  prule->nflags.dst_port = 1;
	  if(different)
	    prule->parmean.dpmean = MULTI_DIFFERENT;
	  else
	    prule->parmean.dpmean = MULTI;
	}
	else
	{
	  return false;
	}
      }
      else /* leave cycle */
	break;
      i++;
    }
    return true;
  }
  else
    return false;
}














