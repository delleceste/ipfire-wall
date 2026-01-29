#include "rule_stringifier.h"
#include <arpa/inet.h>

RuleStringifier::RuleStringifier(ipfire_rule* rule) 
{
	r = rule;
}
	
QString RuleStringifier::Sip()
{
	QString ret;
	char address[INET_ADDRSTRLEN];
	char address2[INET_ADDRSTRLEN];
	
	if(r->nflags.src_addr)
	{
		inet_ntop(AF_INET, &r->ip.ipsrc[0], address, INET_ADDRSTRLEN);
		if( (r->parmean.samean == SINGLE) && (r->nflags.src_addr == ONEADDR) )
			ret = QString(address);
			
		else if( (r->parmean.samean == DIFFERENT_FROM) &&
					(r->nflags.src_addr == ONEADDR) )
			ret = QString("!%1").arg(address);
			
		else if( (r->parmean.samean == DIFFERENT_FROM) && (r->nflags.src_addr == MYADDR) )
			ret = "!MY";
			
		else if( (r->parmean.samean == SINGLE) && (r->nflags.src_addr == MYADDR) )
			ret = "MY";
			
		else if(r->parmean.samean == INTERVAL)
		{
			ret = QString("%1").arg(address);
			inet_ntop(AF_INET, &r->ip.ipsrc[1], address2, INET_ADDRSTRLEN);
			ret += "-";
			ret += QString("%1").arg(address2);
		}
		else if(r->parmean.samean == INTERVAL_DIFFERENT_FROM)
		{
			ret = QString("!%1").arg(address);
			inet_ntop(AF_INET, &r->ip.ipsrc[1], address2, INET_ADDRSTRLEN);
			ret += "-";
			ret += QString("%1").arg(address2);
		}
		else if(r->parmean.samean == MULTI)
		{
		  for(int i = 0; i < MAXMULTILEN && r->ip.ipsrc[i] != 0; i++)
		  {
		    inet_ntop(AF_INET, &r->ip.ipsrc[i], address, INET_ADDRSTRLEN);
		    ret += QString("%1, ").arg(address);
		  }
		  ret.remove(ret.length() - 2, 2);
		}
		else if(r->parmean.samean == MULTI_DIFFERENT)
		{
		  ret = "!";
		  for(int i = 0; i < MAXMULTILEN && r->ip.ipsrc[i] != 0; i++)
		  {
		    inet_ntop(AF_INET, &r->ip.ipsrc[i], address, INET_ADDRSTRLEN);
		    ret += QString("%1, ").arg(address);
		  }
		  ret.remove(ret.length() - 2, 2);
		}
	}
	else 
		ret = "-";
	return ret;
	
}
	
QString RuleStringifier::Dip()
{ 
	struct in_addr addr;
	QString ret;
	char address[INET_ADDRSTRLEN];
	char address2[INET_ADDRSTRLEN];
	
	if(r->nflags.dst_addr)
	{
		inet_ntop(AF_INET, &r->ip.ipdst[0], address, INET_ADDRSTRLEN);

		if( (r->parmean.damean == SINGLE) && (r->nflags.dst_addr == ONEADDR) )
			ret = QString(address);
		else if( (r->parmean.damean == DIFFERENT_FROM) && (r->nflags.dst_addr == ONEADDR) )
			ret = QString("!%1").arg(address);
		else if( (r->parmean.damean == DIFFERENT_FROM) &&
				(r->nflags.dst_addr == MYADDR) )
			ret = "!MY";
		else if( (r->parmean.damean == SINGLE) && (r->nflags.dst_addr == MYADDR) )
			ret = "MY";
			
		else if(r->parmean.damean == INTERVAL)
		{
			ret = QString("%1").arg(address);
			inet_ntop(AF_INET, &r->ip.ipdst[1], address2, INET_ADDRSTRLEN);
			ret += "-";
			ret += QString("%1").arg(address2);
		}
		else if(r->parmean.damean == INTERVAL_DIFFERENT_FROM)
		{
			ret = QString("!%1").arg(inet_ntoa(addr));
			inet_ntop(AF_INET, &r->ip.ipdst[1], address2, INET_ADDRSTRLEN);
			ret += "-";
			ret += QString("%1").arg(address2);
		}
		else if(r->parmean.damean == MULTI)
		{
		  for(int i = 0; i < MAXMULTILEN && r->ip.ipdst[i] != 0; i++)
		  {
		    inet_ntop(AF_INET, &r->ip.ipdst[i], address, INET_ADDRSTRLEN);
		    ret += QString("%1, ").arg(address);
		  }
		  ret.remove(ret.length() - 2, 2);
		}
		else if(r->parmean.damean == MULTI_DIFFERENT)
		{
		  ret = "!";
		  for(int i = 0; i < MAXMULTILEN && r->ip.ipdst[i] != 0; i++)
		  {
		    inet_ntop(AF_INET, &r->ip.ipdst[i], address, INET_ADDRSTRLEN);
		    ret += QString("%1, ").arg(address);
		  }
		  ret.remove(ret.length() - 2, 2);
		}
	}
	else 
		ret = "-";
	return ret;
}
	
QString RuleStringifier::Sport()
{
  QString ret = QString("-");
	if(r->nflags.src_port)
	{
		if(r->parmean.spmean == SINGLE)
			return QString("%1").arg(ntohs(r->tp.sport[0]) );
		else if(r->parmean.spmean == DIFFERENT_FROM)
			return QString("!%1").arg(ntohs(r->tp.sport[0]) );
		else if(r->parmean.spmean == INTERVAL)
			return QString("%1-%2").arg(ntohs(r->tp.sport[0])).arg(
			       ntohs(r->tp.sport[1]) );
		else if(r->parmean.spmean == MULTI)
		{
		  ret = "";
		  for(int i = 0; i < MAXMULTILEN && r->tp.sport[i] != 0; i++)
		    ret += QString("%1, ").arg(ntohs(r->tp.sport[i]));
		  ret.remove(ret.length() - 2, 2);
		}
		else if(r->parmean.spmean == MULTI_DIFFERENT)
		{
		  ret = "!";
		  for(int i = 0; i < MAXMULTILEN && r->tp.sport[i] != 0; i++)
		    ret += QString("%1, ").arg(ntohs(r->tp.sport[i]));
		ret.remove(ret.length() - 2, 2);
		}					
	}
	return ret;
}
	
QString RuleStringifier::Dport()
{
	  QString ret = QString("-");
	if(r->nflags.dst_port)
	{
		if(r->parmean.dpmean == SINGLE)
			return QString("%1").arg(ntohs(r->tp.dport[0]) );
		else if(r->parmean.dpmean == DIFFERENT_FROM)
			return QString("!%1").arg(ntohs(r->tp.dport[0]) );
		else if(r->parmean.dpmean == INTERVAL)
			return QString("%1-%2").arg(ntohs(r->tp.dport[0])).arg(
		ntohs(r->tp.dport[1]) );
		else if(r->parmean.dpmean == MULTI)
		{
		  ret = "";
		  for(int i = 0; i < MAXMULTILEN && r->tp.dport[i] != 0; i++)
		    ret += QString("%1, ").arg(ntohs(r->tp.dport[i]));
		  ret.remove(ret.length() - 2, 2);
		}
		else if(r->parmean.dpmean == MULTI_DIFFERENT)
		{
		  ret = "!";
		  for(int i = 0; i < MAXMULTILEN && r->tp.dport[i] != 0; i++)
		    ret += QString("%1, ").arg(ntohs(r->tp.dport[i]));
		  ret.remove(ret.length() - 2, 2);
		}
		/*return QString("!%1-%2").arg(ntohs(r->tp.dport[0])).arg(
		ntohs(r->tp.dport[1]) );	*/				
	}
	return ret;
}
	
QString RuleStringifier::Proto()
{
	if(!r->nflags.proto)
		return QString("---");
	switch(r->ip.protocol)
	{
		case IPPROTO_TCP:
			return QString("TCP");
		case IPPROTO_UDP:
			return QString("UDP");
		case IPPROTO_ICMP:
			return QString("ICMP");
		case IPPROTO_IGMP:
			return QString("IGMP");	
		default:
			return QString("%1 (UNUSPPORTED)").arg(r->ip.protocol);
	}
	return QString("INVALID");
}
	
QString RuleStringifier::Name()
{
#ifdef ENABLE_RULENAME
	return QString(r->rulename);
#else
	return QString("Names not avail.");
#endif
}
	
QString RuleStringifier::Dir()
{
	QString d;
	if(!r->nflags.direction)
		return QString("-");
	switch(r->direction)
	{
		case IPFI_INPUT:
			d = "IN";
			break;
		case IPFI_OUTPUT:
			d = "OUT";
			break;
		case IPFI_INPUT_PRE:
			d = "PRE";
			break;
		case IPFI_OUTPUT_POST:
			d = "post";
			break;
		case IPFI_FWD:
			d = "FWD";
			break;
		default:
			d = "INVALID";
			break;
	}
	return d;
}
	
QString RuleStringifier::OutDev()
{
	QString odev = "-";
	if(r->nflags.outdev)
		odev = QString(r->devpar.out_devname);
	return odev;
}

QString RuleStringifier::InDev()
{
	QString idev = "-";
	if(r->nflags.indev)
		idev = QString(r->devpar.in_devname);
	return idev;
}
	
QString RuleStringifier::Syn()
{
	QString f = "";
	if(r->nflags.syn)
	{
		if(r->tp.syn)
			f = "SYN on ";
		else
			f = "SYN off ";
	}
	return f;
	
}
	
QString RuleStringifier::Rst()
{
	QString f = "";
	if(r->nflags.rst)
	{
		if(r->tp.rst)
			f = "RST on ";
		else
			f = "RST off ";
	}
	return f;
}
	
QString RuleStringifier::Urg()
{
	QString f = "";
	if(r->nflags.urg)
	{
		if(r->tp.urg)
			f = "URG on ";
		else
			f = "URG off ";
	}
	return f;
}
	
QString RuleStringifier::Psh()
{
	QString f = "";
	if(r->nflags.psh)
	{
		if(r->tp.psh)
			f = "PSH on ";
		else
			f = "PSH off ";
	}
	return f;
}
	
QString RuleStringifier::Ack()
{
	QString f = "";
	if(r->nflags.ack)
	{
		if(r->tp.ack)
			f = "ACK on ";
		else
			f = "ACK off ";
	}
	return f;
}
	
QString RuleStringifier::Fin()
{
	QString f = "";
	if(r->nflags.fin)
	{
		if(r->tp.fin)
			f = "FIN on ";
		else
			f = "FIN off ";
	}
	return f;
}

QString RuleStringifier::Owner()
{
	struct passwd* pwd;
	pwd = getpwuid(r->owner);
	if(pwd == NULL)
		return QString("INVALID");

	return QString(pwd->pw_name);	
}

QString RuleStringifier::State()
{
	if(r->state)
		return QString("YES");
	else
		return QString("NO");
}

QString RuleStringifier::Notify()
{
	if(r->notify)
		return QString("YES");
	else
		return QString("NO");
}


QString RuleStringifier::NewPort()
{
	QString ret;
	if(r->nflags.newport == 1)
		ret = QString("%1").arg(ntohs(r->newport));
	else 
		ret = "-";
	return ret;
}
	
	
QString RuleStringifier::NewIP()
{
	QString ret;
	char address[INET_ADDRSTRLEN];
	struct in_addr addr;
	addr.s_addr = r->newaddr;
	if(r->nflags.newaddr == 1 && inet_ntop(AF_INET, &r->newaddr, address, INET_ADDRSTRLEN))
		ret = QString(address);
	else 
		ret = QString("-");
	
// 	printf("\e[1;32mnew address in NewIP(): r->nflags.newaddr: %d\e[0m\n", r->nflags.newaddr);
	return ret;
			
}

QString RuleStringifier::ftpSupport()
{
  QString ftp;
  if(r->nflags.ftp)
    ftp = " FTP_SUPPORT=YES ";
  return ftp;
}

QString RuleStringifier::mssOption()
{
  QString option;
  if(r->pkmangle.mss.enabled && r->pkmangle.mss.option == MSS_VALUE)
	  option = QString("MSS=%1").arg(r->pkmangle.mss.mss);
  else if(r->pkmangle.mss.enabled && r->pkmangle.mss.option == ADJUST_MSS_TO_PMTU)
	  option = "MSS=TOPMTU";
  else
	  option = "-";
  return option;
}


	


