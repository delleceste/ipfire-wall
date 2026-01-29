#include "machineSentenceToRule.h"
#include "sentenceSectionAnalyzer.h"
/* for policy, direction */
#include <ipfire_structs.h>
#include <macros.h>

#include <QtDebug>

MachineSentenceToRule::MachineSentenceToRule(MachineSentence& ms)
{
  d_ms = ms;
  d_errmsg = "No error";
  d_conversionOk = true;
  d_warnings = false;
  d_direction = NODIRECTION;
  d_policy = -1; /* unset */
  
  d_keywords << "SOURCE" << "DEST" << "INIF" << "OUTIF"  << "IFACE"<< "!SIP" << "!DIP" << "SIP" << "DIP" << "!IP" << "IP" << "SPORT" << "DPORT" << "PORT" 
    << "INPUT" << "OUTPUT" << "FWD" << "PRE" << "POST" << "SNAT" << "DNAT"
    << "MASQ" << "TCP" << "UDP" << "ICMP" << "IGMP" << "ALLOW" << "DENY";
  d_keywords << "SYN" << "ACK" << "PSH" << "FIN" << "RST" << "URG";
  d_keywords << "KEEP_STATE" << "DONT_KEEP_STATE" << "NOTIFY" << "DONT_NOTIFY";
  
  d_uniqueKeywords << "INIF" << "OUTIF"  << "!SIP" << "!DIP" << "SIP" << "DIP" << "SPORT" << "DPORT";
}

bool MachineSentenceToRule::buildConverter()
{
  d_conversionOk = true;
  unsigned short ipcnt = 0;
  unsigned short ptcnt = 0;
  bool ok;
  /* we should have the sentence split in a list of strings
   * each of them containing a keyword with in case a value.
   * The variable 'd_sections' contains the splitted sentence.
   */
   foreach(QString section, d_sections)
   {
     
    SentenceSectionAnalyzer san(section);
    qDebug() << "sezione " << section;
    if(san.containsInif() || san.containsOutif())
    {
      if(san.containsInif())
      {
	inif = san.inIf(&ok);
	if(!ok)
	{
	  d_conversionOk = false;
	  d_errmsg = "An error occurred while getting input interface";
	}
      }
      if(san.containsOutif())
      {
	outif = san.outIf(&ok);
	if(!ok)
	{
	  d_conversionOk = false;
	  d_errmsg = "An error occurred while getting output interface";
	}
      }
    }
    if(san.containsIf()) /* not specified if in or out: try to understand, if possible */
    {
      iface = san.iface(&ok);
      if(!ok)
	{
	  d_conversionOk = false;
	  d_errmsg = "An error occurred while getting network interface (generic: not in nor out)";
	}
    }
    
    /* IP addresses */
    if(san.isSip() || san.isDip() || san.isIp())
    {
	ipcnt++;
	/* first step: watch if the section is an IP address or a list or an interval */
	if(san.containsIpInterval())
	{
	  ip = san.ipInterval(&ok);
	  if(!ok)
	  {
	    d_conversionOk = false;
	    d_errmsg = "An error occurred while interpreting an ip interval: " + san;
	  }
	}
	else if(san.containsIpList())
	{
	  ip = san.ipList(&ok);
	  if(!ok)
	  {
	    d_conversionOk = false;
	    d_errmsg = "An error occurred while interpreting an ip list: " + san;
	  }
	}
	else if(san.containsIp())
	{
	    ip = san.ip(&ok);
	    if(!ok)
	    {
	      d_conversionOk = false;
	      d_errmsg = "An error occurred while interpreting an ip: " + san;
	    }
	}
	
	if(ipSet() && san.isIpNot())
	  ip = "!" + ip;
	
	qDebug() << "<<<<<<<<< IP >>>>>>>>>>>>> " << ipcnt << ip;
	
	if(san.isSip())
	  sip = ip;
	else if(san.isDip())
	  dip = ip;
	/* ip1 e ip2: we know they are ips, but do not know if they are source or dest */
	 
	else if(ipcnt == 1) /* first (or only one IP present ) */
	  ip1 = ip;
	else if(ipcnt == 2) /* second ip present and undetermined */
	  ip2 = ip;
    }
    /* 2. ports */
    else if(san.isSport() || san.isDport() || san.isPort())
    {
	  ptcnt++;
	  if(san.containsPortInterval())
	  {
	    port = san.portInterval(&ok);
	    if(!ok)
	    {
	      d_conversionOk = false;
		d_errmsg = "An error occurred while interpreting a port interval: " + san;
	    }
	  }
	  else if(san.containsPortList())
	  {
	    port = san.portList(&ok);
	    if(!ok)
	    {
	      d_conversionOk = false;
	      d_errmsg = "An error occurred while interpreting a port list: " + san;
	    }
	  }
	  else if(san.containsPort())
	  {
	    port = san.port(&ok);
	    if(!ok)
	    {
	      d_conversionOk = false;
	      d_errmsg = "An error occurred while interpreting a single port: " + san;
	    }
	  }
	  
	  /* `different from' flag: `!' */ 
	  if(portSet() && san.isPortNot())
	    port = "!" + port;
	  
	  if(san.isSport())
	    sport = port;
	  else if(san.isDport())
	    dport = port;
	  else if(ptcnt == 1)
	    port1 = port;
	  else if(ptcnt == 2)
	    port2 = port;
	  
	  qDebug() <<"         situazione porte: " << sport << dport << port1 << port2 << " sport dport port1 port2 ";
    }
    
    /* direction */
    if(san.isDirection())
      d_direction = san.direction();
    /* policy */
    if(san.isPolicy())
      d_policy = san.policy();
    /* protocol */
    if(san.isProtocol())
      protocol = san.protocol();
    
    if(san.isState())
      d_state = san.state();
    
    if(san.isNotify())
      d_notify = san.notify();
    
    if(d_policy == TRANSLATION)
    {
      d_snat = san.isSnat();
      d_dnat = san.isDnat();
      d_masq = san.isMasquerade();
    }
    
    d_owner = getuid();
    
   }
   return d_conversionOk;
  
}

/* analyzes the information gathered by buildConverter() and tries to 
 * understand what to do with the item to create. This should fix all
 * the strings sip, dip, sport, dport.. needed to finally build the
 * string list for the rule item.
 */
bool MachineSentenceToRule::analyzeContents()
{
  if(!protocolSet())
  {
    d_warnings = true;
    d_warn << "Protocol is not set: assuming TCP";
    protocol = "TCP";
  }
  
  qDebug() << "analyzeContents: owner: %d" << d_owner;
  
  if(d_direction == NODIRECTION)
  {
    d_conversionOk = false;
    d_errmsg = "Direction missing: cannot continue!";
    return false;
  }
  
  if(d_policy < 0)
  {
    d_conversionOk = false;
    d_errmsg = "Policy missing: cannot continue!";
    return false;
  }  
  
  /* we have policy, owner, direction: we know where to put the item in the rule tree */
  /* go on now.. */
  
  qDebug() << "network interfaces: " << iface << inif << outif;
  /* network interface(s) */
  if(d_direction != IPFI_FWD)
  {
    if(iface != inif && inifSet() && ifSet())
    {
      d_conversionOk = false;
      d_errmsg = QString("Direction different from forward but two different interfaces specified: %1 and (input) %2!").arg(iface).arg(inif);
      return false;
    }
    if(iface != outif && outifSet() && ifSet())
    {
      d_conversionOk = false;
      d_errmsg = QString("Direction different from forward but two different interfaces specified: %1 and (output) %2!").arg(iface).arg(outif);
      return false;
    }
    if(inifSet() && d_direction != IPFI_INPUT)
    {
       d_conversionOk = false;
      d_errmsg = QString("Input interface provided (\"%1\") but direction is not input").arg(inif);
      return false;
    }
    if(outifSet() && d_direction != IPFI_OUTPUT)
    {
       d_conversionOk = false;
      d_errmsg = QString("Output interface provided (\"%1\") but direction is not output").arg(outif);
      return false;
    }
    if(!outifSet() && !inifSet() && ifSet()) /* generically provided an interface name: input or output depends on direction */
    {
      if(d_direction == IPFI_INPUT)
	inif = iface;
      else if(d_direction == IPFI_OUTPUT)
	outif = iface;
    }
  }
  else /* forward */
  {
    /* input interface explicitly specified, but output not */
    if(inifSet() && !outifSet() && ifSet() && inif != iface)
    {
      d_warnings = true;
      d_warn << QString("Input interface explicitly specified: \"%1\", but I assume that \"%2\" is the output one (it is not explicitly indicated)");
      outif = iface;
    }
    else if(outifSet() && !inifSet() && ifSet() && outif != iface)
    {
      d_warnings = true;
      d_warn << QString("Output interface explicitly specified: \"%1\", but I assume that \"%2\" is the input one (it is not explicitly indicated)");
      inif = iface;
    }
  }
    
  
  /* impossible case: ip1 set and ip2 set: cannot distinguish which one is source or
   * dest
   */
  qDebug() << "situazione ip: " << ip1Set() <<  ip2Set() << sipSet()  << dipSet();
  if(ip1Set() && ip2Set() && !(sipSet() || dipSet()) && d_direction != IPFI_FWD)
  {
    d_conversionOk = false;
    d_errmsg = "Cannot determine which is source and which is dest between " + ip1 +
      " and " + ip2;
    return false;
  }
  else if(ip1Set() && ip2Set() && !(sipSet() || dipSet()) && d_direction == IPFI_FWD)
  {
    sip = ip1;
    dip = ip2;
    ip1 = ip2 = QString(); /* sip and dip assigned: reset ip1 and ip2 */
    d_warnings = true;
    d_warn << QString("No explicit <em>source</em> nor <em>destination</em> keyword has been specified for the "
      "forward rule.<br/>Taking the first address(es) (%1) as source and the second (%2) as destination. Refine your "
      "syntax if you want to avoid ambiguities").arg(sip).arg(dip);
  }
  /* unspecified if source or dest, but _only_ one IP found and saved in ip1 */
  else if(!sipSet() && !dipSet() && ip1Set())
  {
    /* try to guess */
    switch(d_direction)
    {
    /* input direction: if no ip is specified, assume source IP, i.e. the 
     * IP we want/do not want to let in */
      case IPFI_INPUT:
	sip = ip1;
	ip1 = QString(); /* reset ip1 because it has been assigned */
	break;
      /* output: assume IP refers to the destination we want to allow/deny */
      case IPFI_OUTPUT:
	dip = ip1;
	ip1 = QString(); /* reset ip1 because it has been assigned */
	break;
      case IPFI_FWD:
	d_conversionOk = false;
	d_errmsg = "Forward rule specified but no source/destination IP provided";
	return false;
    }
  }
  if(sipSet() && genericIpSet())
  {
    /* one source ip explicitly set, the other not: we must suppose it is dest */
    d_warnings = true;
    d_warn << QString("%1 was specified as source IP, but %2 was not explicitly said to "
      "be a destination one: assuming %3 a destination IP").arg(sip).arg(ip2).arg(ip2);
    dip = genericIp();
  }
  else if(dipSet() && genericIpSet())
  {
    d_warnings = true;
    d_warn << QString("%1 was specified as destination IP, but %2 was not explicitly said to "
      "be a source one: assuming %3 a source IP").arg(sip).arg(ip2).arg(ip2);
    sip = genericIp();
  }
  
   /* impossible case: port1 set and port2 set: cannot distinguish which one is source or
   * dest
   */
  if(port1Set() && port2Set() && !(sportSet() || dportSet()))
  {
    d_conversionOk = false;
    d_errmsg = "Cannot determine which is source and which is dest between ports " + port1 +
      "and " + port2;
    return false;
  }
  /* unspecified if source or dest, but one IP found and saved in ip1 */
  else if(!sportSet() && !dportSet() && port1Set())
  {
    /* try to guess */
    switch(d_direction)
    {
    /* input direction: if no source or dest is specified, assume destination, i.e. the 
     * port we want/do not want to open for input or output connections.
     * The assumption made here is different from the one made in addresses case
     */
      case IPFI_INPUT:
      case IPFI_OUTPUT:
	d_warnings = true;
	d_warn << QString("No \"source\" or \"destination\" was specified for the port %1. We assume destination port").arg(port1);
	dport = port1;
	break;
      case IPFI_FWD:
	d_conversionOk = false;
	d_errmsg = "Forward rule specified but I do not know what port is source or dest";
	return false;
    }
  }
  else if(sportSet() && genericPortSet())
  {
    /* one source port explicitly set, the other not: we must suppose it is dest */
    d_warnings = true;
    d_warn << QString("%1 was specified as source port, but %2 was not explicitly said to "
      "be a destination one: assuming %3 a destination port").arg(sport).arg(port2).arg(port2);
    dport = genericPort();
  }
  else if(dportSet() && genericPortSet())
  {
    d_warnings = true;
    d_warn << QString("%1 was specified as destination port, but %2 was not explicitly said to "
      "be a source one: assuming %3 a source port").arg(dport).arg(port2).arg(port);
    sport = genericPort();
  }
 
  if(!sportSet())
    sport = "-";
  if(!dportSet())
    dport = "-";
  if(!sipSet())
    sip = "-";
  if(!dipSet())
    dip = "-";
  
  if(stateSet())
    d_state = state();
  else
    d_state = "YES";
  
  if(notifySet())
    d_notify = notify();
  else
    d_notify = "NO";
  
  flags = "-";
  
  return true;
}

QStringList MachineSentenceToRule::toRuleItem()
{
  QStringList items;
  bool ret;
  if(!checkKeywordUniqueness())
  {
    return items;
  }
  /* look if there is something to filter or to arrange before splitting. Maybe some redundant
   * keywords must be changed. For example: 'SOURCE IP' might become the keyword 'SIP'
   */
  preFilter();
  /* split into sentences by keyword */
  splitSentenceByKeywords();
  /* fill in the converter class elements, gathering as much information as possible */
  ret = buildConverter();
  /* analyze what we gathered in the previous phase */
  ret = analyzeContents();
  
  if(ret)
  {
    if(warnings())
    {
      pwarn("Analysis succeeded, with warnings:");
      qDebug() << warningsList();
    }
    else
    {
      pok("Analysis succeeded: these are the results:");
    }
    items << "natural rule" << protocol << sip  << dip << sport << dport << inif << outif << d_state << d_notify << flags;
  }
  
  return items;
}

QString MachineSentenceToRule::sdirection()
{
  QString ret = "NODIRECTION";
  switch(direction())
  {
    case IPFI_INPUT:
      ret = "INPUT";
      break;
    case IPFI_OUTPUT:
      ret = "OUTPUT";
      break;
     case IPFI_FWD:
      ret = "FORWARD";
  }
  return ret;
}

QString MachineSentenceToRule::spolicy()
{
  QString ret;
  switch(policy())
  {
    case ACCEPT:
      ret =  "ACCEPT";
      break;
     case DENIAL:
      ret = "DENY";
      break;
     case TRANSLATION:
      ret = "TRANSLATION";
      break;
     default:
      ret = "POLICY UNSPECIFIED";
      break;
  }
  return ret;
}
    
QString MachineSentenceToRule::sowner()
{
  QString ret = QString().number(d_owner);
  return ret;
}
    
QString MachineSentenceToRule::genericIp()
{
  if(ip1Set())
    return ip1;
  if(ip2Set())
    return ip2;
  return "-";
}
    
QString MachineSentenceToRule::genericPort()
{
  if(port1Set())
    return port1;
  if(port2Set())
    return port2;
  return "-";
}

void MachineSentenceToRule::splitSentenceByKeywords()
{
  int index, len;
  QString key;
  for(int i = 0; i < d_keywords.size(); i++)
  {
    index = 0;
    key = d_keywords[i];
    QRegExp re(QString("\\b%1\\b").arg(key));
    re.setCaseSensitivity(Qt::CaseInsensitive);
    if(d_ms.contains(re))
    {
      index = re.indexIn(d_ms, index);
      len = re.matchedLength();
      while(index >= 0 && !alreadyRead(index))
      {
	d_sectionsPos.push_back(index);
	setPortionRead(index, index + len - 1);
	index = re.indexIn(d_ms, index + len);
      }
    }
  }
  if(d_sectionsPos.size() > 1)
  {
    qSort(d_sectionsPos.begin(), d_sectionsPos.end());
    int j = 0, endcycle;
    QString part;
    for(int i = 1; i < d_sectionsPos.size() + 1; i++)
    {
      part = QString();
      if(i == d_sectionsPos.size())
	endcycle = d_ms.length();
      else if(i < d_sectionsPos.size())
	endcycle = d_sectionsPos.at(i);

      while(j < endcycle && j < d_ms.length())
      {
	part += d_ms[j];
	j++;
      }
      part = part.trimmed();
      d_sections << part;
    }
  }
  qDebug() << "d_sections: " << d_sections;
}

void MachineSentenceToRule::setPortionRead(int start, int end)
{
  QPair<int, int> portion;
  portion.first = start;
  portion.second = end;
  portionsRead.push_back(portion);
}

bool MachineSentenceToRule::alreadyRead(int pos)
{
  for(int i = 0; i < portionsRead.size(); i++)
  {
    QPair<int, int> portion = portionsRead.at(i);
    if(pos >= portion.first && pos <= portion.second)
      return true;
  }
  return false;
}

void MachineSentenceToRule::preFilter()
{
    if(d_ms.contains(QRegExp("SOURCE\\s+IP")))
      d_ms.replace(QRegExp("SOURCE\\s+IP"), "SIP");
    if(d_ms.contains(QRegExp("FROM\\s+IP")))
      d_ms.replace(QRegExp("FROM\\s+IP"), "SIP");
    if(d_ms.contains(QRegExp("DEST\\s+IP")))
      d_ms.replace(QRegExp("DEST\\s+IP"), "DIP");
    
     if(d_ms.contains(QRegExp("SOURCE\\s+PORT")))
      d_ms.replace(QRegExp("SOURCE\\s+PORT"), "SPORT");
    if(d_ms.contains(QRegExp("DEST\\s+PORT")))
      d_ms.replace(QRegExp("DEST\\s+PORT"), "DPORT");
    
    /* ! version */
    if(d_ms.contains(QRegExp("SOURCE\\s+!IP")))
      d_ms.replace(QRegExp("SOURCE\\s+!IP"), "!SIP");
    if(d_ms.contains(QRegExp("DEST\\s+!IP")))
      d_ms.replace(QRegExp("DEST\\s+!IP"), "!DIP");
    
     if(d_ms.contains(QRegExp("SOURCE\\s+!PORT")))
      d_ms.replace(QRegExp("SOURCE\\s+!PORT"), "!SPORT");
    if(d_ms.contains(QRegExp("DEST\\s+!PORT")))
      d_ms.replace(QRegExp("DEST\\s+!PORT"), "!DPORT");
}

bool MachineSentenceToRule::checkKeywordUniqueness()
{
  foreach(QString keyword, d_uniqueKeywords)
  {
    if(d_ms.count(keyword) > 1)
    {
      d_conversionOk = false;
      d_errmsg = QString("The sentence \"<em>%1</em>\" contains %2 \"<strong>%3</strong>\" keywords."
	"<br/>Each keyword must be unique. Check the syntax in your natural text").arg(d_ms).arg(d_ms.count(keyword)).
	arg(keyword);
      return false;
    }
  }
  return true;
}


