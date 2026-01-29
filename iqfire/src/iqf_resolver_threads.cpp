#include "iqf_resolver_threads.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>       /* for AF_INET (in gethostbyaddr() ) */
#include <QtDebug>
#include <QApplication>
#include <errno.h>

#include "resolution_event.h"

IQFSingleResolverThread::IQFSingleResolverThread(QObject* parent, QString numeric, QString type) : 
	IQFResolverThread(parent)
{
	d_numeric = numeric;
	d_type = type;
}

QString IQFSingleResolverThread::threadRepresentation()
{
	QString r;
	r = QString("Single resolver thread: [%1]").arg(d_numeric);
	return r;
}

void IQFSingleResolverThread::run()
{
	int ret;
	struct sockaddr_in sa;
	struct in_addr add;
	sa.sin_family = AF_INET;
	int len = sizeof(struct sockaddr_in);
	QString resolvedAsString;
	
	if(d_numeric.count('.') == 3) /* ip */
	{
		char addbuf[NI_MAXHOST];
		if(inet_pton(AF_INET, d_numeric.toStdString().c_str(), &add) <= 0)
			qDebug() << "error in ip address " << d_numeric << "(" <<
					strerror(errno) << ")";
		else
		{
			sa.sin_addr.s_addr = add.s_addr;
			/* resolve the name, pass NULL for the service (port) */
			if((ret = getnameinfo((const sockaddr *) &sa, len, addbuf,
			    NI_MAXHOST, NULL, NI_MAXSERV, NI_NAMEREQD)))
			{
			/* If there is an error we leave the IP as is and we 
			* append a string describing the error */
				resolvedAsString = QString("%1 (unresolved)")
						.arg(d_numeric);
			}
			else
			{
				resolvedAsString = QString(addbuf);
			}
		}
	}
	else if(d_numeric.toUInt() != 0) /* port */
	{
		char sbuf[NI_MAXSERV];
		sa.sin_port = htons(d_numeric.toUInt());
		
		if((ret = getnameinfo((const sockaddr *) &sa, len, NULL,
		    NI_MAXHOST, sbuf, NI_MAXSERV, NI_NAMEREQD)))
		{
			/* If there is an error we leave the IP as is and we 
			* append a string describing the error */
			resolvedAsString = QString("%1 (unresolved)")
					.arg(d_numeric);
		}
		else
		{
			resolvedAsString = QString(sbuf);
		}
	}
	else
		qDebug() << "Resolver::run(): invalid argument " << d_numeric;
	
	ResolutionEvent *re = new ResolutionEvent(d_numeric, d_type, resolvedAsString);
	qApp->postEvent(parent(), re);
}

IQFQuadResolverThread::IQFQuadResolverThread(QObject *parent, unsigned long sip,
			       unsigned long dip, unsigned short sport,
	  unsigned short dport) : IQFResolverThread(parent)
{
	ipsrc = sip;
	ipdst = dip;
	psrc = sport;
	pdst = dport;
}

QString IQFQuadResolverThread::threadRepresentation()
{
	QString r;
	struct sockaddr_in sas, sad;
	/* will contain the names */
	char shbuf[NI_MAXHOST];
	char dhbuf [NI_MAXHOST];
	int len = sizeof(struct sockaddr_in);
	sas.sin_family = sad.sin_family = AF_INET;
	sas.sin_addr.s_addr = ipsrc;
	sad.sin_addr.s_addr = ipdst;
	sas.sin_port = psrc;
	sad.sin_port = pdst;
	
	inet_ntop(AF_INET, (const void *)&ipsrc, shbuf, len);
	inet_ntop(AF_INET, (const void *)&ipdst, dhbuf, len);
	
	r = QString("QuadResolver Thread: { SOURCE IP: %1 SOURCE PORT: %2 - DEST. IP:"
			 " %3 DEST. PORT: %4 }").arg(shbuf).arg(ntohs(psrc)).arg(dhbuf).arg(ntohs(pdst));
	return r;
}

void IQFQuadResolverThread::run()
{
	/* data contains:
	* sip: 4, dip: 7, sport: 5, dport: 8
	*/
	struct sockaddr_in sas, sad;
	QStringList resolved = QStringList() << "resolving" << "resolving" << "resolving" << "resolving";
	
	int len = sizeof(struct sockaddr_in);
	int ret;
	
	/* will contain the names */
	char shbuf[NI_MAXHOST];
	char dhbuf [NI_MAXHOST];
	char ssbuf[NI_MAXSERV] = "-";
	char dsbuf[NI_MAXSERV] = "-";
	
	sas.sin_family = sad.sin_family = AF_INET;
	sas.sin_addr.s_addr = ipsrc;
	sad.sin_addr.s_addr = ipdst;
	sas.sin_port = psrc;
	sad.sin_port = pdst;
	
	ret = getnameinfo((const sockaddr *) &sas, len, shbuf, NI_MAXHOST, ssbuf, NI_MAXSERV, 0);
	if(ret)
	{
		/* If there is an error we leave the sip and sport as they are and we 
		* append a string describing the error */
		/* if the ip is 0, it is not useful to resolve */
		if(ipsrc != 0)
		{
		  inet_ntop(AF_INET, (const void *)&ipsrc, shbuf, len);
		  resolved[0] = QString("%1\n[%2]").arg(shbuf).arg(gai_strerror(ret));
		}
		else
		  resolved[0] = QString(shbuf);
		resolved[2] = QString(ssbuf);
	}
	else
	{
		/* add to the string list the original sip and sport */
		resolved[0] = QString(shbuf);
		resolved[2] = QString(ssbuf);
	}
	
	ret = getnameinfo( (const sockaddr *)&sad, len, dhbuf, NI_MAXHOST, dsbuf, NI_MAXSERV, 0);
	if(ret)
	{
	  if(ipdst != 0)
	  {
		inet_ntop(AF_INET, (const void *)&ipdst, dhbuf, len);
		resolved[1] = QString("%1\n[%2]").arg(dhbuf).arg(gai_strerror(ret));
	  }
	  else
	    resolved[1] = QString(dhbuf);
		
	  resolved[3] = QString(dsbuf);
	}
	else
	{
		resolved[1] = QString(dhbuf);
		resolved[3] = QString(dsbuf);
	}
	
	ResolutionEvent *re = new ResolutionEvent(ipsrc, ipdst, psrc, pdst, resolved);
	qApp->postEvent(parent(), re);
}




