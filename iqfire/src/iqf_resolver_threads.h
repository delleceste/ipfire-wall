#ifndef IQF_RESOLVER_THREAD_H
#define IQF_RESOLVER_THREAD_H

#include <QThread>
#include <QStringList>

class IQFResolverThread : public QThread
{
	Q_OBJECT
	public:
		IQFResolverThread(QObject *parent) : QThread(parent) {};
		
		virtual QString threadRepresentation() = 0;
};

class IQFQuadResolverThread : public IQFResolverThread
{
	Q_OBJECT
			
	public:
		IQFQuadResolverThread(QObject *parent, unsigned long sip,
			unsigned long dip, unsigned short sport,
	  		unsigned short dport);
		QString threadRepresentation();
	
	protected:
		void run();
			
	private:
		unsigned long ipsrc, ipdst;
		unsigned short psrc, pdst;
		
		
};

class IQFSingleResolverThread : public IQFResolverThread
{
	Q_OBJECT
			
	public:
		IQFSingleResolverThread(QObject* parent, QString numeric, QString type);
		QString threadRepresentation();
		
		enum ResolverType { RESOLVER_QUAD, RESOLVER_SINGLE };
	
	protected:
		void run();
			
	private:
		QString d_numeric, d_type;
		
};



#endif 

