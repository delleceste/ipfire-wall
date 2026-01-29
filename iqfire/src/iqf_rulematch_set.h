#ifndef IQF_RULEMATCH_SET_H
#define IQF_RULEMATCH_SET_H

#include <QObject>
#include <QList>
#include <QVector>
#include <QStringList>
#include "ipfire_structs.h"

class QTimer;
class IQFRuleMatchSet;

class IQFRuleMatch : public QObject
{
	Q_OBJECT
	public:
		/** returns, in the following order:
		 * direction, protocol, in interface, source addr, source port,
		 * out interface, destination address, destination port 
		 */
		QStringList stringRepresentation() const;
		IQFRuleMatch(const ipfire_info_t *info);
		
	private:
		
		QTimer *timer;
		
		void setupTimer();
		
		bool operator==(const IQFRuleMatch &other) const;
		bool matches(const IQFRuleMatch &other) const;
		
		unsigned short sport, dport, direction, protocol;
		unsigned int saddr, daddr;
		QString inif, outif, rulename;
		int response;
		
		friend class IQFRuleMatchSet;
		
	private slots:
		void timerElapsed();
		
	signals:
		void removeEntry();
	
};

class IQFRuleMatchSet : QObject
{
	Q_OBJECT
	public:
		IQFRuleMatchSet();

		bool notRecentlyShown(const IQFRuleMatch *other);
		void addEntry(IQFRuleMatch *match);
		
	protected slots:	
		void deleteEntry();
		
	private:
		QList<const IQFRuleMatch *> list;
		
			
};






#endif

