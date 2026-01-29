#include "table_interpreter.h"
#include <arpa/inet.h> /* for inet_ntoa */
#include <iqfpolicy.h>
#include <pwd.h>

QString TableInterpreter::fromAddr(unsigned sa)
{
  QString ret;
   char address[INET_ADDRSTRLEN];
   if(inet_ntop(AF_INET, &sa, address, INET_ADDRSTRLEN) < 0)
     ret = "conversion error with inet_ntop()";
   else
     ret = QString(address);
   return ret;
}
  
QString TableInterpreter::fromPort(unsigned short pt, unsigned short proto)
{
  if(proto == IPPROTO_TCP || proto == IPPROTO_UDP)
    return QString("%1").arg(ntohs(pt));
  else
    return QString("-");
}
  
QString TableInterpreter::fromDir(short dir)
{
  switch(dir)
  {
    case IPFI_INPUT_PRE:
      return "PRE";
    case IPFI_OUTPUT_POST:
      return "POST";
    case IPFI_INPUT:
      return "IN";
    case IPFI_OUTPUT:
      return "OUT";
    case IPFI_FWD:
      return "FWD";
  }
  return "ERROR";
}
    
QString TableInterpreter::fromProto(short proto)
{
  switch(proto)
  {
    case IPPROTO_TCP:
      return "TCP";
    case  IPPROTO_UDP:
      return "UDP";
    case  IPPROTO_ICMP:
      return "ICMP";
    case  IPPROTO_IGMP:
      return "IGMP";
  }
  return "ERR";
}
  
QString TableInterpreter::fromState(struct state_t st)
{
  QString ret;
  __u8 state = st.state;
  
  if(state == SYN_SENT)
      ret = "SETUP";
  else if(state == SYN_RECV)
     ret =  "SETUP OK";
  else if(state == ESTABLISHED)
     ret =  "EST";
  else if(state == LAST_ACK)
      ret =  "LAST ACK";
  else if(state == CLOSE_WAIT)
     ret =  "CLOSE WAIT";
  else if(state == INVALID_STATE)
    ret =  "?";
  else if(state == FIN_WAIT)
     ret =  "FIN WAIT";
  else if(state == IPFI_TIME_WAIT)
     ret =  "TIME WAIT";
  else if(state == GUESS_ESTABLISHED)
     ret =  "EST?";
  else if(state == CLOSED)
     ret =  "CLOSED";
  else if(state == NOTCP)
     ret =  "S";
  else if(state == UDP_NEW)
     ret = "NEW";
 else if(state == UDP_ESTAB)
     ret = "STREAM";
  else if(state == ICMP_STATE)
     ret = "ICMP";
  else if(state == IGMP_STATE)
	  ret = "IGMP";
 else if(state == GUESS_CLOSING)
    ret = "CLOSING?";
  else if(state == INVALID_FLAGS)
    ret = "INVALID FLAGS!";
  else if(state == NULL_FLAGS)
     ret = "NULL syn fin rst ack FLAGS!";
  else if(state == GUESS_SYN_RECV)
    ret = "SETUP OK?";
  else if(state != IPFI_NOSTATE)
    ret = "STATE: %d";
  return ret;
}

QStringList TableInterpreter::stateToList()
{
  QStringList sl;
  unsigned int rulePos;
  char username[PWD_FIELDS_LEN];
  struct passwd * pwd;
    sl << fromDir(si->direction) << 
    fromProto(si->protocol) << 
    fromAddr(si->saddr) <<
    fromPort(si->sport, si->protocol) <<
    fromAddr(si->daddr) <<
    fromPort(si->dport, si->protocol);
    switch(si->direction)
    {
      case IPFI_INPUT:
      case IPFI_INPUT_PRE:
	sl << QString(si->in_devname) << "-";
	break;
      case IPFI_OUTPUT:
      case IPFI_OUTPUT_POST:
	sl << "-" << QString(si->out_devname);
	break;
      case IPFI_FWD:
	sl << QString(si->in_devname) << QString(si->out_devname);
	break;
    }
    sl << fromState(si->state);
    sl << timeoutDHMS(si->timeout);
    rulePos = si->originating_rule;
    /* permissionRuleByPosition() returns a reference */
    ipfire_rule& rule = Policy::instance()->permissionRuleByPosition(rulePos, si->admin);
    sl << QString("%1").arg(rule.rulename);
    sl << QString("%1").arg(rulePos);
    if(si->admin)
      sl << "admin";
    else if((pwd = getpwuid(getuid())) != NULL)
	sl << pwd->pw_name;
    else 
      sl << "UNKNOWN";
    
    return sl;
}

QStringList TableInterpreter::snatToList()
{
  QStringList sl;
  sl << fromDir(sni->direction);
  sl << fromProto(sni->protocol);
  sl << fromAddr(sni->saddr);
  sl << fromPort(sni->sport, sni->protocol);
  sl << fromAddr(sni->newsaddr);
  sl << fromPort(sni->newsport, sni->protocol);
  sl << fromAddr(sni->daddr);
  sl << fromPort(sni->dport, sni->protocol);
  sl << QString(sni->out_devname);
  sl << fromState(sni->state);
  sl << timeoutDHMS(sni->timeout);
  return sl;
}

QStringList TableInterpreter::dnatToList()
{
   QStringList sl;
  sl << fromDir(dni->direction);
  sl << fromProto(dni->protocol);
  sl << fromAddr(dni->saddr);
  sl << fromPort(dni->sport, dni->protocol);
  sl << fromAddr(dni->daddr);
  sl << fromPort(dni->dport, dni->protocol);
  sl << fromAddr(dni->newdaddr);
  sl << fromPort(dni->newdport, dni->protocol);
  switch(dni->direction)
    {
      case IPFI_INPUT_PRE:
	sl << QString(dni->in_devname) << "-";
	break;
      case IPFI_OUTPUT_POST:
      case IPFI_OUTPUT:
	sl << "-" << QString(dni->out_devname);
	break;
    }
  sl << fromState(dni->state);
  sl << timeoutDHMS(dni->timeout);
  return sl;
}

QString TableInterpreter::timeoutDHMS(unsigned int to)
{
	QString ret;
	unsigned int d, h, m, s;
	s = to % 60;
	m = (to / 60) % 60;
	h = (to / 3600) % 24;
	d = (to / (3600 * 24) );
	if(d > 0)
	  ret += QString("%1d").arg(d);
	if(h > 0)
	  ret += QString("%1h").arg(h);
	if(m > 0)
	  ret += QString("%1m").arg(m);
	if(s > 0)
	  ret += QString("%1s").arg(s);
	return ret;
}





