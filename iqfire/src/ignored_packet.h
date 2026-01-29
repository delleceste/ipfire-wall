#ifndef IGNORED_PACKET_H
#define IGNORED_PACKET_H

#include <QString>

class IQFPendingTreeItem;

class IgnoredPacket
{
	public:
		/** Constructs an IgnoredPacket entry from a string */
		IgnoredPacket(QString in);
		IgnoredPacket(const IQFPendingTreeItem *item);
		IgnoredPacket() { }
		/* copy constructor */
		IgnoredPacket(const IgnoredPacket &other);		
		QString toString();
		QString toReadableString();
		
		bool operator==(const IgnoredPacket &other) const;
		
		bool isValid() { return valid; }
		
		short protocol, direction;
		unsigned sip, dip;
		unsigned short sport, dport;
		/* Short and not bool to allow the coversion to/from QString:
		* they indicate if we want to compare the sip, dip, sport, dport
		* respectively. 
		*/
		short ips, ipd, pts, ptd, interface, prot;
		
		bool valid;
		QString iface;
		QString syntax_error;
};


#endif


