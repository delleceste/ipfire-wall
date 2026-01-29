#include "sentenceSectionAnalyzer.h"
#include <QList>
#include <QStringList>
#include <QtDebug>
#include <QRegExp>
#include <regexps.h>
#include <macros.h> /* pinfo, perr, pok... */
/* need to know policy and direction */
#include <ipfire_structs.h>
/* for ip address check */
#include <arpa/inet.h> /* inet_pton() needs it */

SentenceSectionAnalyzer::SentenceSectionAnalyzer(QString s) : QString(s)
{
  
}

bool SentenceSectionAnalyzer::isProtocol()
{
  return (contains("TCP") || contains("UDP") || contains("ICMP") || contains("IGMP"));
}

QString SentenceSectionAnalyzer::protocol()
{
  QString ret = QString();
  if(isProtocol())
  {
    if(contains("TCP"))
      ret = "TCP";
    else if(contains("UDP"))
      ret  = "UDP";
     else if(contains("ICMP"))
      ret  = "ICMP";
     else if(contains("IGMP"))
      ret  = "IGMP";
  }
  return ret;
}

bool SentenceSectionAnalyzer::isDirection()
{
  if(contains("INPUT") || contains("OUTPUT") || contains("FWD") 
    || contains("PRE") || contains("POST"))
    return true;
  return false;
}
    
int SentenceSectionAnalyzer::direction()
{
  if(contains("INPUT"))
    return IPFI_INPUT;
  else if(contains("OUTPUT"))
    return IPFI_OUTPUT;
  else if(contains("FWD"))
    return IPFI_FWD;
  else if(contains("PRE"))
    return IPFI_INPUT_PRE;
  else if(contains("POST"))
    return IPFI_OUTPUT_POST;
  else 
    return NODIRECTION;
}
    
bool SentenceSectionAnalyzer::isPolicy()
{
  if(contains("ALLOW") || contains ("DENY") || contains("SNAT") || 
    contains("DNAT") || contains("MASQ"))
    return true;
  else
    return false;
}

int SentenceSectionAnalyzer::policy()
{
   if(contains("ALLOW"))
    return ACCEPT;
  else if(contains("DENY"))
    return DENIAL;
  else if(contains("DNAT") || contains("SNAT") || contains("MASQ"))
    return TRANSLATION;
  else
    return -1;
}
 
bool SentenceSectionAnalyzer::isIp()
{
  if(!contains("SIP") && !contains("DIP") && contains("IP") && (containsIp() || containsIpInterval() || containsIpList()) )
    return true;
  return false;
}    
 
bool SentenceSectionAnalyzer::isSip()
{
  if(contains("SIP") && (containsIp() || containsIpInterval() || containsIpList()) )
    return true;
  else if(contains("SOURCE") && (containsIp() || containsIpInterval() || containsIpList()) )
    return true;
  return false;
}

bool SentenceSectionAnalyzer::isDip()
{
  if(contains("DIP") && (containsIp() || containsIpInterval() || containsIpList()) )
    return true;
  else if(contains("DEST") && (containsIp() || containsIpInterval() || containsIpList()) )
    return true;
  return false;
}

 bool SentenceSectionAnalyzer::isIpNot()
 {
   if(containsIp() || containsIpInterval() || containsIpList())
   {
     if(contains("!"))
       return true;
   }
   return false;
 }

QString SentenceSectionAnalyzer::ip(bool *ok)
{
   QString ret;
  *ok = true;
  if(contains(QRegExp(IP_REGEXP)) && nonOverlapCount(IP_REGEXP) == 1)
  {
    QRegExp rx(IP_REGEXP);
    int pos = rx.indexIn(*this);
    QStringList list = rx.capturedTexts();
    if(list.size() > 0 && pos >= 0)
    {
//       qDebug() << "ip singolo: catturato " << list;
      ret = list[0];
    }
    *ok = checkIp(ret);
  }
  else
    *ok = false;
  return ret;
}
    
bool SentenceSectionAnalyzer::containsInif()
{
  if(contains("INIF"))
    return true;
  return false;
}

bool SentenceSectionAnalyzer::containsOutif()
{
  if(contains("OUTIF"))
    return true;
  return false;
}

bool SentenceSectionAnalyzer::containsIf()
{
  if(contains(QRegExp(IF_REGEXP)))
  {
    qDebug() << *this << "contains inif";
    return true;
  }
  qDebug() << *this << "DONT contains inif";
  return false;
}
 
QString SentenceSectionAnalyzer::inIf(bool *ok)
{
   QString ret;
   *ok = true;
   
   if(containsInif())
   {
    QRegExp rx(IF_REGEXP);
    int pos = rx.indexIn(*this);
    QStringList list = rx.capturedTexts();
    if(list.size() > 0)
      ret = list[0];
    else
      *ok = false;
   }
   else
     *ok = false;
   qDebug() << "san inif" << ret;
   return ret;
}
 
QString SentenceSectionAnalyzer::outIf(bool *ok)
{
   QString ret;
   *ok = true;
   
   if(containsOutif())
   {
    QRegExp rx(IF_REGEXP);
    int pos = rx.indexIn(*this);
    QStringList list = rx.capturedTexts();
    if(list.size() > 0)
      ret = list[0];
    else
      *ok = false;
   }
   else
     *ok = false;
   return ret;
}
 
QString SentenceSectionAnalyzer::iface(bool *ok)
{
   QString ret;
   *ok = true;
   QRegExp rx(IF_REGEXP);
  int pos = rx.indexIn(*this);
  QStringList list = rx.capturedTexts();
  if(list.size() > 0)
    ret = list[0];
  else
    *ok = false;
    
   qDebug() << "* generic interface" << ret;
   return ret;
}
 
/* true if it contains a single IP */
bool SentenceSectionAnalyzer::containsIp()
{
  if(contains(QRegExp(IP_REGEXP)) && nonOverlapCount(IP_REGEXP) == 1)
    return true;
  return false;
}

bool SentenceSectionAnalyzer::containsIpInterval()
{
  if(contains(QRegExp(IP_INTERVAL_REGEXP)) ||
    contains(QRegExp(IP_AND_MASK_REGEXP)))
    {
//       qDebug() << "section " << *this << "contains ip interval or mask";
      return true;
    }
  return false;
}

bool SentenceSectionAnalyzer::containsIpList()
{
  if(contains(QRegExp(IP_REGEXP)) && nonOverlapCount(IP_REGEXP) > 1)
  {
//     qDebug() << "section " << *this << "contains ip list";
    return true;
  }
  return false;
}  

QString SentenceSectionAnalyzer::ipInterval(bool *ok)
{
  QString ret;
  *ok = true;
  if(contains(QRegExp(IP_INTERVAL_REGEXP)) && 
    nonOverlapCount(IP_INTERVAL_REGEXP) == 1)
  {
    QRegExp rx(IP_INTERVAL_REGEXP);
    int pos = rx.indexIn(*this);
    QStringList list = rx.capturedTexts();
    if(list.size() > 0)
    {
//       qDebug() << "intervallo: catturato " << list;
      ret = list[0];
//       qDebug() << "count" << nonOverlapCount(IP_INTERVAL_REGEXP);
    }
     /* also check ip consistency, additional check ;-) */
     QStringList ips = ret.split("-");
     if(ips.size() != 2) 
       *ok = false;
     else
       *ok = checkIp(ips[0]) | checkIp(ips[1]);
  }
  else if(contains(QRegExp(IP_AND_MASK_REGEXP)) && 
    nonOverlapCount(IP_AND_MASK_REGEXP) == 1)
  {
     QRegExp rx(IP_AND_MASK_REGEXP);
      int pos = rx.indexIn(*this);
    QStringList list = rx.capturedTexts();
    if(list.size() > 0)
    {
//       qDebug() << "intervallo (maschera): catturato " << list;
      ret = list[0];
//       qDebug() << "count" << nonOverlapCount(IP_AND_MASK_REGEXP);
    }
    /* also check ip consistency, additional check ;-) */
    QStringList ips = ret.split("/");
    if(ips.size() != 2) 
      *ok = false;
    else
      *ok = checkIp(ips[0]) | checkIp(ips[1]);
  }
 
  return ret;
}

QString SentenceSectionAnalyzer::ipList(bool *ok)
{
  QString ret;
  if(contains(QRegExp(IP_INTERVAL_REGEXP)) || contains(QRegExp(IP_AND_MASK_REGEXP)))
  {
    *ok = false;
    perr("called ipList but interval or ip/mask found.");
    return ret;
  }
  if(contains(QRegExp(IP_REGEXP)) && nonOverlapCount(IP_REGEXP) > 1)
  {
    /* good */
    int pos = 0;
    QRegExp rx(IP_REGEXP);
    while(pos >= 0)
    {
      pos = rx.indexIn(*this, pos);
      QStringList capt = rx.capturedTexts();
      if(capt.size() > 0 && pos >= 0)
      {
	pok("catturato un ip in una lista! -> %s" , qstoc(capt[0]));
	ret += capt[0] + ", ";
	*ok = checkIp(capt[0]);
	if(!ok)
	{
	  perr("The IP address \"%s\" is not valid.", qstoc(capt[0]));
	  break;
	}
      }
      pos += rx.matchedLength();
    }
    /* remove last , and space */
    ret.remove(ret.length() - 2, 2);
//     qDebug() << "IP estratti sotto forma di lista (in unica stringa): " << ret;
    
  }
  return ret;
}
    
bool SentenceSectionAnalyzer::isPort()
{
  if(!contains("SPORT") && !contains("DPORT") && contains("PORT")  && (containsPort() || containsPortInterval() || containsPortList()) )
    return true;
  return false;
}   

bool SentenceSectionAnalyzer::isSport()
{
  if(contains("SPORT") && (containsPort() || containsPortInterval() || containsPortList()) )
    return true;
  else if(contains("SOURCE") && (containsPort() || containsPortInterval() || containsPortList()) )
    return true;
  return false;
}

bool SentenceSectionAnalyzer::isDport()
{
  if(contains("DPORT") && (containsPort() || containsPortInterval() || containsPortList()) )
    return true;
  else if(contains("DEST") && (containsPort() || containsPortInterval() || containsPortList()) )
    return true;
  return false;
}

bool SentenceSectionAnalyzer::isPortNot()
 {
   if(containsPort() || containsPortInterval() || containsPortList())
   {
     if(contains("!"))
       return true;
   }
   return false;
 }


QString SentenceSectionAnalyzer::port(bool *ok)
{
  QString ret;
  *ok = true;
  if(contains(QRegExp(PORT_REGEXP)) && nonOverlapCount(PORT_REGEXP) == 1)
  {
    QRegExp rx(PORT_REGEXP);
    int pos = rx.indexIn(*this);
    QStringList list = rx.capturedTexts();
    if(list.size() > 0 && pos >= 0)
    {
//       qDebug() << "porta singola: catturata " << list;
      ret = list[0];
    }
    *ok = checkPort(ret);
  }
  else
    *ok = false;
  return ret;
}

bool SentenceSectionAnalyzer::containsPort()
{
   if(contains(QRegExp(PORT_REGEXP)) && nonOverlapCount(PORT_REGEXP) == 1)
      return true;
   return false;
}

bool SentenceSectionAnalyzer::containsPortList()
{
   qDebug() << "section: " << *this << "SentenceSectionAnalyzer::containsPortList():: regexp " << PORT_REGEXP << " contains " << contains(QRegExp(PORT_REGEXP)) << " nonOverlapCount " << nonOverlapCount(PORT_REGEXP);
   if(contains(QRegExp(PORT_REGEXP)) && nonOverlapCount(PORT_REGEXP) > 1)
      return true;
   else
     qDebug() << "section: " << *this << "SentenceSectionAnalyzer::containsPortList():: regexp " << PORT_REGEXP << " contains " << contains(QRegExp(PORT_REGEXP)) << " nonOverlapCount " << nonOverlapCount(PORT_REGEXP);
   return false;
}

bool SentenceSectionAnalyzer::containsPortInterval()
{
  QString portInterval = QString(PORT_REGEXP) + "\\-" + QString(PORT_REGEXP);
  if(contains(QRegExp(portInterval)))
    return true;
  return false;
}

QString SentenceSectionAnalyzer::portInterval(bool *ok)
{
  QString ret;
  *ok = true;
  qDebug() << "port interval: analisi di " << *this << "\nregexp:\n\"" << PORT_REGEXP << "\"";
  QString portInterval = QString(PORT_REGEXP) + "\\-" + QString(PORT_REGEXP);
  if(contains(QRegExp(portInterval)) && 
    nonOverlapCount(portInterval) == 1)
  {
    QRegExp rx(portInterval);
    int pos = rx.indexIn(*this);
    QStringList list = rx.capturedTexts();
    if(list.size() > 0)
    {
//       qDebug() << "intervallo DI PORTE: catturato " << list;
      ret = list[0];
    }
     /* also check port consistency, additional check ;-) */
     QStringList ps = ret.split("-");
     if(ps.size() != 2) 
       *ok = false;
     else
       *ok = checkPort(ps[0]) | checkPort(ps[1]);
  }
  else
    qDebug() << *this << " dont contains a port interval";
  return ret;
}

QString SentenceSectionAnalyzer::portList(bool *ok)
{
  QString ret;
  /* PORT_REGEXP must be included in brackets before "-" separator */
  QString portInterval = QString(PORT_REGEXP) + "\\-" + QString(PORT_REGEXP);
  if(contains(QRegExp(portInterval)))
  {
    *ok = false;
    perr("called portList but interval or ip/mask found.");
    return ret;
  }
  if(contains(QRegExp(PORT_REGEXP)) && nonOverlapCount(PORT_REGEXP) > 1)
  {
    /* good */
    int pos = 0;
    QRegExp rx(PORT_REGEXP);
    while(pos >= 0)
    {
      pos = rx.indexIn(*this, pos);
      QStringList capt = rx.capturedTexts();
      if(capt.size() > 0 && pos >= 0)
      {
	pok("catturato una porta in una lista! -> %s" , qstoc(capt[0]));
	ret += capt[0] + ", ";
	*ok = checkPort(capt[0]);
	if(!ok)
	{
	  perr("The Port  \"%s\" is not valid.", qstoc(capt[0]));
	  break;
	}
      }
      pos += rx.matchedLength();
    }
    /* remove last , and space */
    ret.remove(ret.length() - 2, 2);
//     qDebug() << "Porte estratte sotto forma di lista (in unica stringa): " << ret;
    
  }
  qDebug() << "regexp " << PORT_REGEXP << " contains " << contains(QRegExp(PORT_REGEXP)) << " nonOverlapCount " << nonOverlapCount(PORT_REGEXP);
  return ret;
}

int SentenceSectionAnalyzer::nonOverlapCount(QString regexp)
{
  int cnt = 0;
  int pos = 0;
  QRegExp rx(regexp);
  pos = rx.indexIn(*this, pos);
  while(pos >= 0)
  {
    cnt++;
    pos += rx.matchedLength();
    pos = rx.indexIn(*this, pos);
  }
  return cnt;
}

bool SentenceSectionAnalyzer::checkIp(QString &ip)
{
  struct in_addr ina;
  int ret = inet_pton(AF_INET, ip.toStdString().c_str(), &ina);
  if(ret <= 0)
    return false;
  return true;
}
  
bool SentenceSectionAnalyzer::checkPort(QString &port)
{
  bool ok;
  int pt = port.toInt(&ok);
  if(!ok)
    return false;
  if(pt > 0 && pt < 65536)
    return true;
  return false;
}

 bool SentenceSectionAnalyzer:: isSnat()
 {
   return contains("SNAT");
 }
 
 bool SentenceSectionAnalyzer:: isDnat()
 {
   return contains("DNAT");
 }
 
 bool SentenceSectionAnalyzer:: isMasquerade()
 {
   return contains("MASQ");
 }

bool SentenceSectionAnalyzer::isState()
{
  return contains("STATE");
}

bool SentenceSectionAnalyzer::isNotify()
{
  return contains("NOTIFY");
}

QString SentenceSectionAnalyzer::state()
{
  if(contains("DONT_KEEP_STATE"))
    return "NO";
  return "YES";
}

QString SentenceSectionAnalyzer::notify()
{
  if(contains("DONT_NOTIFY"))
    return "NO";
  return "YES";
}




