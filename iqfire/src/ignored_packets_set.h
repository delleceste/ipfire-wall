#ifndef IGNORED_PACKETS_SET_H
#define IGNORED_PACKETS_SET_H

#include "ignored_packet.h"
#include <QList>
#include <QObject>

/* A singleton class */
class IgnoredPacketsSet : public QObject
{
	Q_OBJECT
			
	public:
	
		static IgnoredPacketsSet* instance();
		
		QList<IgnoredPacket> list();

		bool alreadyPresent( IgnoredPacket &other);

		void add(IgnoredPacket& newp);
		void add(QList<IgnoredPacket> &newlist);

		IgnoredPacket lastAdded() { return plist[plist.size() - 1]; }

		int remove(IgnoredPacket& toremove) { return plist.removeAll(toremove);  emit setChanged(); }
		bool loadingFailed() { return loading_failed; }
			
	public slots:
		int loadIgnoredPackets();
		int saveIgnoredPackets();
		
	signals:
		void setChanged();
		void ignoredAdded();
	
	private: /* Singleton: the constructor is private */
		
		IgnoredPacketsSet();
		~IgnoredPacketsSet();
	
		static IgnoredPacketsSet *_instance;
			
		QList<IgnoredPacket> plist;
		bool loading_failed;
};
























#endif

