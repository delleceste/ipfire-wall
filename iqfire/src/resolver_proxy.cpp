#include "resolver_proxy.h"
#include "iqf_resolver_threads.h"
#include "iqflog.h"
#include "regexps.h"
#include <QtDebug>
#include <QApplication>

IQFResolverProxy* IQFResolverProxy::_instance = NULL;


IQFResolverProxy::IQFResolverProxy(QObject *parent) : QObject(parent)
{
	
}


IQFResolverProxy::~IQFResolverProxy()
{
	
}

IQFResolverProxy* IQFResolverProxy::resolver()
{
	if(_instance == NULL)
		return (_instance = new IQFResolverProxy(QApplication::instance()) );
	else
		return _instance;
}

bool IQFResolverProxy::event(QEvent *e)
{
	if(e->type() == RESOLUTION_EVENT_QUAD && static_cast<ResolutionEvent* >(e))
	{
		ResolutionEvent *re = static_cast<ResolutionEvent* >(e);
		QString key = QString("%1%2%3%4").arg(re->soip).arg(re->deip).arg(re->sop).arg(re->dep);
		emit resolved(key, re->resolved);
// 		qDebug() << "emesso ! risoluzione by event() (QUAD) : " << re->resolved;
		return true;
	}
	else if(e->type() == RESOLUTION_EVENT_SINGLE && static_cast<ResolutionEvent* >(e))
	{
		ResolutionEvent *re = static_cast<ResolutionEvent* >(e);
		QString key = re->singleNumeric;
		QString type = re->singleType;
		emit resolved(key, type, re->singleResolved);
		return true;
	}
	else
		return QObject::event(e);
}

void IQFResolverProxy::resolve(unsigned long sip,
			unsigned long dip, 
   			unsigned short sport,
	  		unsigned short dport)
{
	IQFQuadResolverThread *rt = new IQFQuadResolverThread(this, sip, dip, sport, dport);
	connect(rt, SIGNAL(finished()), this, SLOT(threadFinished()));
	d_threads << rt;
	rt->start();
}

void IQFResolverProxy::resolve(QString &typenum)
{
	QString type, num, ipsre, portsre;
	int pos;
	QStringList captures;
	ipsre = QString(IP_REGEXP);
	ipsre.remove("\\b");
	ipsre = QString("(%1)").arg(ipsre);
	
	portsre = QString(PORT_REGEXP);
	portsre.remove("\\b");
	portsre = QString("(%1)").arg(portsre);
	
	QRegExp ipre(ipsre);
	QRegExp portre(portsre);
	QRegExp re;
	
	if(typenum.contains(ipre))
	  re = ipre;
	else if(typenum.contains(portre))
	  re = portre;

	pos = re.indexIn(typenum);
	captures = re.capturedTexts();
	if(pos >= 0 && captures.size() > 0)
	  num = captures.at(0);
	type = typenum.remove(re);
	
	qDebug() << "type of resolve : " << type;
	qDebug() << "catture " << captures;
	
	IQFSingleResolverThread *rt = new IQFSingleResolverThread(this, num, type);
	connect(rt, SIGNAL(finished()), this, SLOT(threadFinished()));
	d_threads << rt;
	rt->start();
}

void IQFResolverProxy::threadFinished()
{
	int n;
	IQFResolverThread *finishedThread;
	if((finishedThread = qobject_cast<IQFResolverThread *>(sender())))
	{
		n = d_threads.removeAll(finishedThread);
		delete finishedThread;
	}
}

void IQFResolverProxy::waitForRunningThreads()
{
	printf("\e[1;32m* \e[0mresolver proxy: checking if some resolvers are still running...\t");
	if(d_threads.size())
	{
		printf("\e[1;32myes \e[0m[%d]\e[0m\n", d_threads.size());
		Log::log()->forceShowLogs();
		qApp->processEvents();
	}
	else
		printf("no\n");
	for(int i = 0; i < d_threads.size(); i++)
	{
		d_threads[i]->disconnect();
		printf("- waiting for thread %s...\n", d_threads[i]->threadRepresentation().toStdString().c_str());
		Log::log()->appendOk(QString("waiting for thread \"%1\"").arg(d_threads[i]->threadRepresentation()));
		qApp->processEvents();
		d_threads[i]->wait();
	}
}

