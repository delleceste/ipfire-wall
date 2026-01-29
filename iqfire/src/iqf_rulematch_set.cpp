#include "iqf_rulematch_set.h"
#include <QSettings>
#include <QTimer>
#include <QtDebug>
#include <arpa/inet.h> /* for inet_ntoa */

IQFRuleMatch::IQFRuleMatch(const ipfire_info_t *info)
{
	QSettings s;
	protocol = info->protocol;
	direction = info->direction;
	response = info->response;
	inif = outif = "-";
	sport = dport = 0;
	saddr = daddr = 0;
	rulename = QString(info->rulename);
	setObjectName(QString("IQFRuleMatch entry for rule %1").arg(rulename));
	switch(info->direction)
	{
		case IPFI_FWD:
			inif = QString(info->devpar.in_devname);
			outif = QString(info->devpar.out_devname);
		case IPFI_INPUT:
			inif = QString(info->devpar.in_devname);
			break;
		case IPFI_OUTPUT:
			outif = QString(info->devpar.out_devname);
			break;
	}
	switch(info->protocol)
	{
		case IPPROTO_TCP:
			sport = info->transport_header.tcphead.source;
			dport = info->transport_header.tcphead.dest;
			break;
		case IPPROTO_UDP:
			sport = info->transport_header.udphead.source;
			dport = info->transport_header.udphead.dest;
			break;
		case IPPROTO_ICMP:
		case IPPROTO_IGMP:
			sport = dport = 0;
			break;
	}
	saddr = info->iphead.saddr;
	daddr = info->iphead.daddr;
}

void IQFRuleMatch::setupTimer()
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	int timeout = 1000 * s.value("POPUP_PACKET_MATCH_TIMEOUT", 600).toInt();
	timer->setInterval(timeout);
	connect(timer, SIGNAL(timeout()), this, SLOT(timerElapsed()));
	timer->start(timeout);
}

bool IQFRuleMatch::matches(const IQFRuleMatch &other) const
{
	if(other.response != response)
		return false;
	if(other.direction == IPFI_INPUT_PRE || other.direction == IPFI_OUTPUT_POST)
		return false;
	if(protocol != other.protocol)
		return false;
	
	if(direction == IPFI_FWD && other.direction == IPFI_FWD)
	{
		return (protocol == other.protocol) && (direction == other.direction)
				&& 
				((saddr == other.saddr && daddr == other.daddr &&
				sport == other.sport && dport == other.dport &&
				inif == other.inif && outif == other.outif) 
				|| 
				(saddr == other.daddr && daddr == other.saddr &&
				sport == other.dport && dport == other.sport &&
				inif == other.outif && outif == other.inif));
	}
	else if(direction != IPFI_FWD && other.direction != IPFI_FWD)
	{
		if(other.direction == direction) /* both input: must have the same fields */
			return saddr == other.saddr && daddr == other.daddr &&
					sport == other.sport && dport == other.dport &&
					inif == other.inif && outif == other.outif;
		else /* opposite directions: must have fields equals but opposite */
			return saddr == other.daddr && daddr == other.saddr &&
					sport == other.dport && dport == other.sport &&
					inif == other.outif && outif == other.inif;		
	}
	return false;
}

bool IQFRuleMatch::operator==(const IQFRuleMatch &other) const
{
	return response == other.response && saddr == other.saddr && daddr == other.daddr &&
			sport == other.sport && dport == other.dport &&
			inif == other.inif && outif == other.outif && direction == other.direction
			&& protocol == other.protocol;
	
}

void IQFRuleMatch::timerElapsed()
{
// 	qDebug() << "Timer elapsed for " << stringRepresentation();
	 emit removeEntry(); 
}


// IQFRuleMatch::IQFRuleMatch(const IQFRuleMatch &other)
// {
// 	direction = other.direction;
// 	protocol = other.protocol;
// 	saddr = other.saddr;
// 	daddr = other.daddr;
// 	sport = other.sport;
// 	dport = other.dport;
// 	inif = other.inif;
// 	outif = other.outif;
// 	timer = other.timer;
// }

IQFRuleMatchSet::IQFRuleMatchSet()
{
	list.clear();
}

void IQFRuleMatchSet::addEntry(IQFRuleMatch *match)
{
	connect(match, SIGNAL(removeEntry()), this, SLOT(deleteEntry()));
	list.push_back(match);
	match->setupTimer();
// // 	qDebug() << "Aggiungo match: " << match->stringRepresentation();
}

void IQFRuleMatchSet::deleteEntry()
{
	IQFRuleMatch* rm = qobject_cast<IQFRuleMatch*>(sender());
	if(rm != NULL)
	{
// 		qDebug() << "timeout: rimuovo e cancello dalla memoria: " << rm->stringRepresentation();
		list.removeAll(rm);
		rm->deleteLater();
	}
}

bool IQFRuleMatchSet::notRecentlyShown(const IQFRuleMatch *rm)
{
	int i;
	for(i = 0; i < list.size(); i++)
	{
		const IQFRuleMatch *element = list.at(i);
		if(element->matches(*rm))
		{
// // 			qDebug() << "Già visto : " << rm->stringRepresentation();
			return false; /* in list: recently shown */
		}
	}
// // 	qDebug() << "Mai visto : " << rm->stringRepresentation();
	return true; /* not in list: not recently shown */
}

QStringList IQFRuleMatch::stringRepresentation() const
{
	QStringList sr;
	struct in_addr inas, inad;
	
	/* abs for drop rules, which are non positive */
	sr << rulename + QString(" [%1]").arg(abs(response));
	
	switch(direction)
	{
		case IPFI_INPUT:
			sr << "IN";
			break;
		case IPFI_OUTPUT:
			sr << "OUT";
			break;
		case IPFI_FWD:
			sr << "FWD";
			break;
		default:
			sr << "UNSUPPORTED";
			break;
	}
	switch(protocol)
	{
		case IPPROTO_TCP:
			sr << "TCP";
			break;
		case IPPROTO_UDP:
			sr <<  "UDP";
			break;
		case IPPROTO_ICMP:
			sr <<  "ICMP";
			break;
		case IPPROTO_IGMP:
			sr <<  "IGMP";
			break;	
		default:
			sr <<  "UNSUPPORTED";
			break;
	}
	
	inas.s_addr = saddr;
	inad.s_addr = daddr;
	
	if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
		sr << inif << QString(inet_ntoa(inas)) << QString("%1").arg(ntohs(sport)) <<
			outif << QString(inet_ntoa(inad)) << QString("%1").arg(ntohs(dport));
	else
		sr << inif << QString(inet_ntoa(inas)) << "-" <<
				outif << QString(inet_ntoa(inad)) << "-";
	
	if(response > 0)
		sr << QString("ACCEPTED [%1]").arg(response);
	else if(response < 0)
		sr << QString("DROPPED [%1]").arg(response);
	else
		sr << QString("UNKNOWN! [%1]").arg(response);
	return sr;
}



