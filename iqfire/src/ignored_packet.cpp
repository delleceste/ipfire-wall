#include "ignored_packet.h"
#include "iqf_pending_tree_item.h"
#include <QStringList>
#include <QtDebug>
#include <QMessageBox>

#include <arpa/inet.h> /* for inet_ntoa */

#define MINPORT 	0
#define MAXPORT 	65535

IgnoredPacket::IgnoredPacket(QString in)
{
	QStringList parts;
	ips = ipd = pts = ptd = interface = prot = 1;
	sport = dport = sip = dip = 0;
	iface = "uninitialized";
	
	if(in.count(";") != 11)
	{
		valid = false;
	}
	else
	{
		parts = in.split(";");
		if(parts.size() == 12)
		{
			if(parts[0].contains("IN"))
				direction = IPFI_INPUT;
			else if(parts[0].contains("OUT"))
				direction = IPFI_OUTPUT;
			
			if(parts[1].contains("TCP"))
				protocol = IPPROTO_TCP;
			else if(parts[1].contains("UDP"))
				protocol = IPPROTO_UDP;
			else if(parts[1].contains("ICMP"))
				protocol = IPPROTO_ICMP;
			else if(parts[1].contains("IGMP"))
				protocol = IPPROTO_IGMP;
			else if(parts[1].contains("-"))
				prot = 1;
			
			if(parts[2].contains("0"))
				ips = 0;
			else
				sip = parts[3].toUInt();
			
			if(parts[4].contains("0"))
				ipd = 0;
			else	
				dip = parts[5].toUInt();
			
			
			if(parts[6].contains("0"))
				pts = 0;
			else	
				sport = parts[7].toUShort();
			
			if(parts[8].contains("0"))
				ptd = 0;
			else	
				dport = parts[9].toUShort();
			
			if(parts[10].contains("0"))
				interface = 0;
			else
				iface = parts[11];
			
			valid = true;
			
		}	
		
	}
}

IgnoredPacket::IgnoredPacket(const IQFPendingTreeItem *it)
{
	valid = true;
	syntax_error = "";
	QString s;
	struct in_addr add;
	int i;
	
	pts = ptd = ips = ipd = interface = prot = 1;
	sport = dport = sip = dip = 0;
	iface = "uninitialized";
	
	if(it->text(0).contains("IN"))
		direction = IPFI_INPUT;
	else if(it->text(0).contains("OUT"))
		direction = IPFI_OUTPUT;
			
	if(it->text(1).contains("TCP"))
		protocol = IPPROTO_TCP;
	else if(it->text(1).contains("UDP"))
		protocol = IPPROTO_UDP;
	else if(it->text(1).contains("ICMP"))
		protocol = IPPROTO_ICMP;
	else if(it->text(1).contains("IGMP"))
		protocol = IPPROTO_IGMP;
	else if(it->text(1) == "any" || it->text(1) == "-")
		prot = 0;
			
	for(i = 2; i < 6; i++)
	{
		s = it->text(i);
	
		if( (i % 2 == 0) && !s.isNull() && s.isEmpty() && (s != "any") 
				   && !(s == "") && ( s.count(".") != 3 || s.contains("/") ||
				   (s.count("-") == 1 && s.length() > 1) )	)
		{
			valid = false;
			syntax_error = QString("* The IP address \"%1\" is not well formed.\n"
					"Intervals are not allowed and the IP address must be in the form\n"
					"\"192.168.0.1\" (dotted decimal)\n").arg(s);
		}
		else if( (i % 2 != 0) && !s.isNull() && s.isEmpty() 
					&& ! (s == "") && (s != "any") &&
					( (s.count("-") == 1 && s.length() > 1)))
		{
			valid = false;
			syntax_error = QString("* The port \"%1\" is not well formed.\n"
					"Intervals are not allowed.").arg(s);
		}
	}
	
	s = it->text(2);
	if(s.contains("-") || s == "" || s.isEmpty() || s.isNull() || s == "any")
	{
		ips = 0;
		qDebug() << "any source ip";
	}
	else
	{
		if(inet_pton(AF_INET, s.toStdString().c_str(), &add) <= 0)
		{
			QMessageBox::information(0, "Error in input address as source IP",
					QString("The address \"%1\" is not a valid IPv4 address!").
							arg(s));
		}
		else
			sip = add.s_addr;
	}	
		
	s = it->text(3); /* source port */
	if(s.contains("-") || s == "" || s.isEmpty() || s.isNull() || s == "any")
		pts = 0;
	else
	{
		if(s.toInt() > MAXPORT || s.toInt() < MINPORT)
			QMessageBox::information(0, "Error in the value of the source port",
				QString("The port must be an integer between %1 and %2.").
						arg(MINPORT).arg(MAXPORT));
		else
			sport = htons(s.toUShort());
		
	}	
	
	s = it->text(4); /* dip */
	if(s.contains("-") || s == "" || s.isEmpty() || s.isNull() || s == "any")
		ipd = 0;
	else
	{
		if(inet_pton(AF_INET, s.toStdString().c_str(), &add) <= 0)
		{
			QMessageBox::information(0, "Error in input address as destination IP",
					QString("The address \"%1\" is not a valid IPv4 address!").
							arg(s));
		}
		else
			dip = add.s_addr;
	}	
			
			
	s = it->text(5); /* source port */
	if(s.contains("-") || s == "" || s.isEmpty() || s.isNull() || s == "any")
		ptd = 0;
	else
	{
		if(s.toInt() > MAXPORT || s.toInt() < MINPORT)
			QMessageBox::information(0, "Error in the value of the destination port",
				QString("The port must be an integer between %1 and %2.").
						arg(MINPORT).arg(MAXPORT));
		else
			dport = htons(s.toUShort());
		
	}	
			
	s = it->text(6);
	if(s.contains("-") || s == "" || s.isEmpty() || s.isNull() || s == "any")
		interface = 0;
	else
		iface = s;

}

IgnoredPacket::IgnoredPacket(const IgnoredPacket &other)
{
	direction = other.direction;
	protocol = other.protocol;
	sip = other.sip;
	dip = other.dip;
	sport = other.sport;
	dport = other.dport;
	iface = other.iface;
	prot = other.prot;
	ips = other.ips;
	ipd = other.ipd;
	pts = other.pts;
	ptd = other.ptd;
	interface = other.interface;
//	qDebug() << toReadableString();
}

bool IgnoredPacket::operator==(const IgnoredPacket &other) const
{
// 	if(direction != other.direction)
// 		qDebug() << "direction differs";
// 	if(protocol != other.protocol)
// 		qDebug() << " protocol differs";
// 	if(sip != other.sip)
// 		qDebug() << "sip differs";
// 
// 	if(dip != other.dip)
// 		qDebug() << "dip differs";
// 
// 	if(sport != other.sport)
// 		qDebug() << "sport differs";
// 
// 	if(dport != other.dport)
// 		qDebug() << "dport differs";

	return direction == other.direction && protocol == other.protocol &&
			sip == other.sip && dip == other.dip && sport == other.sport &&
			dport == other.dport && iface == other.iface && ips == other.ips
			&& ipd == other.ipd && pts == other.pts && ptd == other.ptd &&
			interface == other.interface; 
}

QString IgnoredPacket::toString()
{	
	QString s;
	switch(direction)
	{
		case IPFI_INPUT:
			s = "IN;";
			break;
		case IPFI_OUTPUT:
			s = "OUT;";
			break;
		case IPFI_FWD:
			s = "FWD;";
			break;
		default:
			s = "UNSUPPORTED;";
			break;
	}
	switch(protocol)
	{
		case IPPROTO_TCP:
			s += "TCP;";
			break;
		case IPPROTO_UDP:
			s += "UDP;";
			break;
		case IPPROTO_ICMP:
			s += "ICMP;";
			break;
		case IPPROTO_IGMP:
			s += "IGMP;";
			break;
		default:
			s += "UNSUPPORTED;";
			break;
	}
	
	s += QString("%1;%2;%3;%4;%5;%6;%7;%8;%9;%10\n")
			.arg(ips).arg(sip) 
			.arg(ipd).arg(dip)
			.arg(pts).arg(sport)
			.arg(ptd).arg(dport)
			.arg(interface).arg(iface);
	return s;
}

QString IgnoredPacket::toReadableString()
{
	QString ret, addr;
	struct in_addr inaddr;
	
	switch(direction)
	{
		case IPFI_INPUT:
			ret = "IN";
			break;
		case IPFI_OUTPUT:
			ret = "OUT";
			break;
		case IPFI_FWD:
			ret = "FWD";
			break;
		default:
			ret = "UNSUPPORTED";
			break;
	}
	
	ret += ";";
	
	switch(protocol)
	{
		case IPPROTO_TCP:
			ret += "TCP";
			break;
		case IPPROTO_UDP:
			ret += "UDP";
			break;
		case IPPROTO_ICMP:
			ret += "ICMP";
			break;
		case IPPROTO_IGMP:
			ret += "IGMP";
			break;
		default:
			ret += "UNSUPPORTED";
			break;
	}
	ret += ";";
	
	if(ips)
	{
		inaddr.s_addr = sip;
		ret += QString("%1: ").arg(QString(inet_ntoa(inaddr)));
	}
	else
		ret += "{ANY SIP}:";
	
	if(pts)
	{
		ret += QString("%1|->").arg(ntohs(sport));
	}
	else
		ret += "{ANY SPORT}|->";
	
	
	
	if(ipd)
	{
		inaddr.s_addr = dip;
		ret += QString("%1: ").arg(QString(inet_ntoa(inaddr)));
	}
	else
		ret += "{ANY DIP}:";
	
	if(ptd)
	{
		ret += QString("%1| ").arg(ntohs(dport));
	}
	else
		ret += "{ANY DPORT}| ";
	
	if(interface)
		ret += QString("[%1]\n").arg(iface);
	else
		ret += "{ANY INTERFACE}\n";
	
	return ret;
	
}
