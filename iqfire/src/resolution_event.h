#ifndef IQF_RESOLUTION_EVENT_H
#define IQF_RESOLUTION_EVENT_H

#include <QEvent>
#include <QStringList>

#define RESOLUTION_EVENT_QUAD (QEvent::Type) 4000
#define RESOLUTION_EVENT_SINGLE (QEvent::Type) 4001


class ResolutionEvent : public QEvent
{
	public:
		ResolutionEvent(unsigned long sip,
			unsigned long dip, 
   			unsigned short sport,
	  		unsigned short dport, 
			const QStringList &res) : QEvent(RESOLUTION_EVENT_QUAD) 
		{
			soip = sip;
			deip = dip;
			sop = sport;
			dep = dport;
			resolved = res;
		}
		
		ResolutionEvent(QString numeric, QString type, QString resolved) : QEvent(RESOLUTION_EVENT_SINGLE)
		{
			singleResolved = resolved;
			singleNumeric = numeric;
			singleType = type;
		}
		
	
		
	unsigned long soip, deip;
	unsigned short sop, dep;
	QStringList resolved;
	QString singleResolved, singleNumeric, singleType;
};


#endif
