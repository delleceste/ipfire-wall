#ifndef RULE_STRINGIFIER_H
#define RULE_STRINGIFIER_H

#include <ipfire_structs.h>
#include <QString>

class RuleStringifier
{
	public:
	RuleStringifier(ipfire_rule* r);
	~RuleStringifier() { }	
	
	QString Sip();
	QString Dip();
	QString Sport();
	QString Dport();
	QString Proto();
	QString Name();
	QString Dir();
	QString Syn();
	QString Rst();
	QString Fin();
	QString Psh();
	QString Ack();
	QString Urg();
	QString Owner();
	QString UID();
	QString State();
	QString Notify();
	QString NewPort();
	QString NewIP();
	QString InDev();
	QString OutDev();
	QString mssOption();
        QString ftpSupport();
	
	private:
		QString sip, dip, sp, dp, proto, name, 
  			dir, syn, rst, fin, psh, urg, ack;
		ipfire_rule * r;
};

#endif
