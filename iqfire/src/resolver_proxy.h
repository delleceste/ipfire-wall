#ifndef IQF_RESOLVER_PROXY_H
#define IQF_RESOLVER_PROXY_H

#include <QList>
#include <QStringList>
#include <QEvent>
#include "resolution_event.h"

class IQFResolverThread;


class IQFResolverProxy : public QObject
{
	Q_OBJECT
	public:
		static IQFResolverProxy *resolver();
		
		void resolve(unsigned long sip,
			unsigned long dip, 
   			unsigned short sport,
	  		unsigned short dport);
		void resolve(QString &);
		
		void waitForRunningThreads();
		
	protected:
		bool event(QEvent *);
		
	signals:
		void resolved(const QString &key,
     			const QStringList& res);
		void resolved(const QString &key, const QString& type, const QString &resolved);
		
	private:
		IQFResolverProxy(QObject *parent);
		~IQFResolverProxy();
		
		QList<IQFResolverThread *> d_threads;
		
		static IQFResolverProxy* _instance;
		
	private slots:
		void threadFinished();
};

#endif
