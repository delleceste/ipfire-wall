#include "iqfruletree_item.h"
#include "iqfire.h" /* for ICON_PATH! */
#include "iqfruletree.h"
#include "rule_stringifier.h"
#include "rule_builder.h"
#include "iqfpolicy.h"
#include "iqfrule_adder.h"
#include "iqflog.h"
#include "iqf_message_proxy.h"
#include "iqfwidgets.h"
#include "iqf_utils.h"
#include "colors.h"
#include <QGridLayout>
#include <QMessageBox>
#include <QHeaderView>
#include <QString>
#include <QSettings>
#include <QMenu>
#include <QDropEvent>
#include <QtDebug>
#include <arpa/inet.h>
#include <QBrush>


IQFRuleTreeItem::IQFRuleTreeItem(QTreeWidget* parent)
	:IQFTreeWidgetItem(parent)
{
	memset(&myrule, 0, sizeof(ipfire_rule));
	d_natural = has_rule = has_policy = has_direction = expanded = false;
	_type = FILTER;
	direction = NODIRECTION;
}

IQFRuleTreeItem::IQFRuleTreeItem(QTreeWidgetItem* parent)
	:IQFTreeWidgetItem(parent)
{
	memset(&myrule, 0, sizeof(ipfire_rule));
	_type = FILTER;
	d_natural = has_rule = has_policy = has_direction = expanded = false;
	direction = NODIRECTION;
}

IQFRuleTreeItem::IQFRuleTreeItem(QTreeWidget* parent, ipfire_rule rule)
	:IQFTreeWidgetItem(parent)
{
	memset(&myrule, 0, sizeof(ipfire_rule));
	has_rule = has_policy = has_direction = true;
	_type = FILTER;
	expanded = false;
	direction = rule.direction;
	owner = rule.owner;
	policy = rule.nflags.policy;
	rule.natural ? d_natural = true : d_natural = false;
	memcpy(&myrule, &rule, sizeof(ipfire_rule));
}

IQFRuleTreeItem::IQFRuleTreeItem(QTreeWidget* parent, const QStringList & strings, ipfire_rule rule)
	:IQFTreeWidgetItem(parent, strings)
{
	memset(&myrule, 0, sizeof(ipfire_rule));
	has_rule = has_policy = has_direction = true;
	_type = FILTER;
	expanded = false;
	direction = rule.direction;
	owner = rule.owner;
	policy = rule.nflags.policy;
	rule.natural ? d_natural = true : d_natural = false;
	memcpy(&myrule, &rule, sizeof(ipfire_rule));
}

IQFRuleTreeItem::IQFRuleTreeItem(const QStringList & strings, ipfire_rule rule)
	:IQFTreeWidgetItem(strings)
{
	memset(&myrule, 0, sizeof(ipfire_rule));
	has_rule = has_policy = has_direction = true;
	_type = FILTER;
	expanded = false;
	direction = rule.direction;
	owner = rule.owner;
	policy = rule.nflags.policy;
	rule.natural ? d_natural = true : d_natural = false;
	memcpy(&myrule, &rule, sizeof(ipfire_rule));
}

IQFRuleTreeItem::IQFRuleTreeItem(QTreeWidgetItem* parent, ipfire_rule rule)
	:IQFTreeWidgetItem(parent)
{
	has_rule = has_policy = has_direction = true;
	_type = FILTER;
	direction = rule.direction;
	owner = rule.owner;
	policy = rule.nflags.policy;
	rule.natural ? d_natural = true : d_natural = false;
	expanded = false;
}

IQFRuleTreeItem::IQFRuleTreeItem(QTreeWidgetItem* parent, const QStringList & strings, 
			 ipfire_rule rule)
	:IQFTreeWidgetItem(parent, strings), myrule(rule)
{
	has_rule = has_policy = has_direction = true;
	_type = FILTER;
	direction = rule.direction;
	owner = rule.owner;
	policy = rule.nflags.policy;
	expanded = false;
	rule.natural ? d_natural = true : d_natural = false;
}

IQFRuleTreeItem::IQFRuleTreeItem(QTreeWidgetItem* parent, const QStringList & strings) :
  IQFTreeWidgetItem(parent, strings)
{
  has_rule = true;
  memset(&myrule, 0, sizeof(ipfire_rule));
  d_natural = expanded = has_direction = has_policy = false;
  owner = getuid();
}

QString IQFRuleTreeItem::buildItemKey()
{
	QString key = "";
	if(childCount() > 0) 
	{
		key = this->text(0);
		QTreeWidgetItem *it = this->parent();
		/* build the key for the QSettings to identify the item 
		* in the tree.
		*/
		while(it != NULL)
		{
			key += "/" + it->text(0);
			it = it->parent();
		}
	}
	return key;
}

bool IQFRuleTreeItem::wasExpanded()
{
	QSettings s;
	bool ret = false;
	QString key = buildItemKey();
	
	if(key != "")
		ret = s.value(key, false).toBool();
	
	return ret;
}

void IQFRuleTreeItem::setAndStoreExpanded(bool expanded)
{
	QSettings s;
	QString key = buildItemKey();
	if(key != "")
		s.setValue(buildItemKey(), expanded);
	setExpanded(expanded);
}

void IQFRuleTreeItem::determineTypeFromRule()
{
	if(hasRule())
	{
		qDebug() << "hasRule()::determineTypeFromRule()"
				<< myrule.nat<< myrule.snat<<  myrule.direction;
		if(myrule.nat && !myrule.snat && myrule.direction == IPFI_OUTPUT)
			_type = IQFRuleTreeItem::OUTDNAT;
		else if(myrule.nat && !myrule.snat && myrule.direction == IPFI_INPUT_PRE)
			_type = IQFRuleTreeItem::DNAT;
		else if(myrule.nat && myrule.snat && myrule.direction == IPFI_OUTPUT_POST)
			_type = IQFRuleTreeItem::SNAT;
		else if(myrule.masquerade && myrule.direction == IPFI_OUTPUT_POST)
			_type = IQFRuleTreeItem::MASQ;
		else if(!myrule.nat)
			_type= FILTER;
	}
	else
		qDebug() << "has_rule must be set to true for :determineTypeFromRule()"
				" to work!";
}

/* given the tree widget item, fills in an ipfire_rule with the values taken from the columns.
 * NOTE: the owner, the direction and the policy are taken from the tree widget item properties.
 */
void IQFRuleTreeItem::toRule(ipfire_rule *rule)
{
	RuleBuilder rb;
	/* initialize the parameter passed to zeros */
	memset(rule, 0, sizeof(ipfire_rule));
	if(!hasRule())
	{
		QMessageBox::information(0, "Error", QString("Trying to build a rule"
		"\nfrom the item \"%1\" which is not of rule type!\n"
		"Contact the author thanks.").arg(text(0)));
		setRuleInvalid();
		return;
	}
// 	else if(!ruleValid())
// 	{
// 	  QMessageBox::information(0, "Error: contact the author please", 
// 		"item with invalid associated rule!");
// 	  setRuleInvalid();
// 	  return;
// 	}
	else if(itemOwner() != getuid())
	{
	  QMessageBox::information(0, "Error: contact the author please", "getuid() != ItemOwner. Contact the author please!");
          setRuleInvalid();
	  return;
	}
	/* fill in the RuleBuilder */
	/* owner, policy and direction are determined by the tree: each new element of the tree 
	 * when created, is associated to an owner, a direction and a policy.
	 */
	rb.setOwner(itemOwner());
	rb.setPolicy(itemPolicy());
	rb.setDirection(itemDirection());
	
	rb.setName(text(0));

	/* Protocol */
	rb.setProtocol(text(1));
	/* source IP */
	rb.setSip(text(2));
	/* Destination IP */
	rb.setDip(text(3));
	/* Fill  in the port only if the protocol il TCP or UDP */
	if(rb.Rule()->ip.protocol == IPPROTO_TCP || rb.Rule()->ip.protocol == IPPROTO_UDP)
	{
		/* Source port */
		rb.setSport(text(4));
		/* Destination port */
		rb.setDport(text(5));
	}
	/* In devname */
	rb.setInDevname(text(6));
	/* Out devname */
	rb.setOutDevname(text(7));
	
	if(rb.Rule()->nflags.policy == ACCEPT && 
		  (rb.Rule()->direction == IPFI_INPUT || rb.Rule()->direction == IPFI_OUTPUT ||
		  rb.Rule()->direction == IPFI_FWD) )
	{
		rb.setState(text(8));
	}
	
	if(rb.Rule()->nflags.policy == ACCEPT || rb.Rule()->nflags.policy == DENIAL)
	{
		rb.setNotify(text(9));
	}
	
	if(rb.Rule()->ip.protocol == IPPROTO_TCP && type() <  IQFRuleTreeItem::NAT) /* TCP flags */
	{
		rb.setFlags(text(10));
	}
	else if(rb.Rule()->ip.protocol == IPPROTO_TCP && type() > IQFRuleTreeItem::NAT)
		rb.setFlags(text(10));

	if(rb.Rule()->ip.protocol == IPPROTO_TCP && type() <  IQFRuleTreeItem::NAT)
	  rb.setOptions(text(11));
	
	if((type() == IQFRuleTreeItem::DNAT && rb.Rule()->direction == IPFI_INPUT_PRE) || 
		  (type() == IQFRuleTreeItem::OUTDNAT && rb.Rule()->direction == IPFI_OUTPUT))
	{
		rb.setNatType("DNAT");
		rb.setNewIP(text(8));
		rb.setNewPort(text(9));
	}
	else if(type() == IQFRuleTreeItem::OUTDNAT && rb.Rule()->direction == IPFI_OUTPUT)
	{
		rb.setNatType("OUTDNAT");
		rb.setNewIP(text(8));
		rb.setNewPort(text(9));
	}	
	else if(type() == IQFRuleTreeItem::SNAT && rb.Rule()->direction == IPFI_OUTPUT_POST)
	{
		rb.setNatType("SNAT");
		rb.setNewIP(text(8));
		rb.setNewPort(text(9));
	}	
	else if(type() == IQFRuleTreeItem::MASQ && rb.Rule()->direction == IPFI_OUTPUT_POST)
	{
		rb.setNatType("MASQUERADE");
	}
	if(rb.ruleValid())
	{
		for(int i = 0; i < columnCount(); i++)
			setForeground(i, myBrush());
		setRuleValid();

		/* the rule is valid, copy the ipfire_rule created by the builder into the passed
		 * ipfire_rule*  pointer. The caller will find there its rule
		 */
		memcpy(rule, rb.Rule(), sizeof(ipfire_rule));
		if(isNatural())
		  rule->natural = 1;
		pok("rule %s successfully built in toRule() (iqfruletree_item.cpp)",
		  rule->rulename);
	}
	else
	{
		for(int i = 0; i < columnCount(); i++)
			setForeground(i, QBrush(KRED));
		setRuleInvalid();
		QMessageBox::critical(0, "Error for the developer",
				      "toRule(): bad rule! You should have checked before!");
	}
}

bool IQFRuleTreeItem::checkColumnChanged(int col)
{
	qDebug() << "check column changed" << col;
	IQFUtils* ut = IQFUtils::utils();

	if(!hasRule())
	{
		qDebug() << "! cannot check a column without a rule!";
		return false;
	}
	bool valid = true;
	
	switch(col)
	{
		case 1:
			qDebug() << "1";
			valid = ut->checkProto(text(col));
			if(!valid)
				_invalidReason = "Invalid protocol";
			qDebug() << "2";
			break;
		case 2:
		case 3:
			qDebug() << "3";
			valid = ut->checkGenericIP(text(col));
			if(!valid)
				_invalidReason = "Invalid or incomplete IP address";
			qDebug() << "4";
			break;
		case 4:
		case 5:
			qDebug() << "5";
			valid = ut->checkPortOrInterval(text(col));
			if(!valid)
				_invalidReason = "Invalid or incomplete port";
			qDebug() << "6";
			break;
		case 6:
		case 7:
			qDebug() << "7";
			valid = ut->checkDev(text(col));
			if(type() == IQFRuleTreeItem::MASQ && (text(7).compare("any",
			   Qt::CaseInsensitive)== 0 || (text(7).contains("-") &&
				text(7).count("-") == 1) ) )
				valid = false;
			if(!valid)
				_invalidReason = "In Masquerade rules the output interface "
					"must be defined";
			qDebug() << "8";
			break;
		case 8:
			qDebug() << "9";
			if(this->type() > IQFRuleTreeItem::NAT)
			{
				valid = ut->checkIP(text(col));
				if(!valid)
					_invalidReason = "Invalid or incomplete new IP address<br/>";
				valid = checkNatRequirements();
				if(!valid)
					_invalidReason += " Error in NAT entry.<br/>";
			}
			else 
				valid = ut->checkState(text(col));
			qDebug() << "10";
			break;
		case 9:
			qDebug() << "11";
			if(this->type() > IQFRuleTreeItem::NAT)
			{
				valid = ut->checkPort(text(col));
				valid = checkNatRequirements();
				if(!valid)
					_invalidReason += " Error in NAT entry.";
			}
			else
				valid = ut->checkNotify(text(col));
			break;
			qDebug() << "12";	
		case 11: /* mss */
		      valid = ut->checkMssOption(text(col));
		      if(!valid)
			_invalidReason += QString("Invalid syntax in MSS option: \"%1\"").arg(text(col));
		      if(valid && !(text(1) == "tcp" || text(1) == "TCP"))
		      {
			qDebug() << "regola valida ma proto: " << text(1);
			valid = false;
			_invalidReason += "MSS option can be specified only in tcp protocol rules";
		      }
		  break;
	}
	
	if(!valid)
	{
		setForeground(col, QBrush(KRED));
		setSelected(false);
		qDebug() << "the field is not valid: " << text(col) << "(" << _invalidReason << ")";
	}
	else
		setForeground(col, myBrush());
	
	setItemValid(valid);
	qDebug() << "fuori da check column chanvged!";
	return valid;
}

bool IQFRuleTreeItem::checkNatRequirements()
{
	RuleBuilder rb;
	bool valid = true;
	switch(type())
	{
		case IQFRuleTreeItem::SNAT:
		case IQFRuleTreeItem::DNAT:
		case IQFRuleTreeItem::OUTDNAT:
			rb.setNewIP(text(8));
			rb.setNewPort(text(9));
			if((rb.Rule()->nflags.newaddr | rb.Rule()->nflags.newport) == 0)
				valid = false;
			break;
		case IQFRuleTreeItem::MASQ:
			rb.setOutDevname(text(7));
			if(rb.Rule()->nflags.outdev == 0)
				valid = false;
			if(text(8) != "-" || text(9) != "-")
			{
			   valid = false;
			   _invalidReason += "Masquerade rules do not want a new address or a new port!<br/>";
			}
			break;
		default:
			qDebug() << "! IQFRuleTreeItem::checkNatRequirements():"
				" is this really a nat rule :o ??";
			break;
	}
	setItemValid(valid);
	return valid;
}

void IQFRuleTreeItem::rebuildRule()
{
  printf("in rebuildRule()\n");
	if(itemOwner() != getuid())
		qDebug() << "! cannot rebuildRule(): item owner ! getuid";
	if(!hasRule())
		qDebug() << "! cannot rebuildRule(): i do not have a rule!";
	
	if(hasRule() && itemOwner() == getuid())
	{
	  printf("chiamo \e[1;31mtoRule\e[0m dentro rebuildRule()\e[0m\n");
		toRule(&myrule);
	}
	else if(itemOwner() != getuid())
	  perr("item owner is different from getuid()");
	
	if(!ruleValid())
	  printf("\e[1;31m* \e[0m item invalid\e[0m\n");

	printf("\e[1;33mfuori da rebuildRUle\e[0m\n");
}

IQFRuleTreeItem::~IQFRuleTreeItem()
{
	
}

void IQFRuleTreeItem::setItemRule(const ipfire_rule& other)
{
      memcpy(&myrule, &other, sizeof(myrule));
}



