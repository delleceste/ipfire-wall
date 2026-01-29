#include "iqfire.h" /* for ICON_PATH! */
#include "iqfruletree.h"
#include "iqfruletree_item.h"
#include "rule_stringifier.h"
#include "rule_builder.h"
#include "iqfpolicy.h"
#include "iqfrule_adder.h"
#include "iqflog.h"
#include "iqf_message_proxy.h"
#include "iqfwidgets.h"
#include "iqf_utils.h"
#include "colors.h"
#include "iqf_item_delegate.h"
#include "rule_comparator.h"
#include <naturalRuleHash.h>
#include <naturalRuleItemRemover.h>

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
#include <QSettings>

IQFRuleTree *IQFRuleTree::natTree = NULL;
IQFRuleTree *IQFRuleTree::policyTree = NULL;

IQFRuleTree::IQFRuleTree(QWidget* parent, int typ) : IQFTreeWidget(parent),
	type(typ)
{
	policy = Policy::instance();
	QGridLayout *lo = new QGridLayout(parent);
	lo->setSpacing(0);
	lo->addWidget(this,0 ,0);
	//setAcceptDrops(true);
	setDragEnabled(true);
	//setDropIndicatorShown(true);
	setSelectionMode(QAbstractItemView::SingleSelection);
	setDragDropMode(QAbstractItemView::InternalMove);
	
	setMouseTracking(true);
	
	connect(this, SIGNAL(itemCollapsed(QTreeWidgetItem *)), this, SLOT(setCollapsed(QTreeWidgetItem *)));
	connect(this, SIGNAL(itemExpanded(QTreeWidgetItem *)), this, SLOT(setExpanded(QTreeWidgetItem *)));

	connect(this, SIGNAL(itemEntered(QTreeWidgetItem *, int)), this, SLOT(emitInfo(QTreeWidgetItem *, int)));
	connect(this, SIGNAL(itemClicked(QTreeWidgetItem *, int)), this, SLOT(emitInfoFromClick(QTreeWidgetItem *, int)));
	
	
	populateTree();
	
	IQFLineEditIPItemDelegate* id = new IQFLineEditIPItemDelegate(this);
	setItemDelegateForColumn(2, id);
	setItemDelegateForColumn(3, id);
	IQFComboBoxProtoItemDelegate *cbid = new IQFComboBoxProtoItemDelegate(this);
	setItemDelegateForColumn(1, cbid);
	IQFLineEditPortItemDelegate* pid = new IQFLineEditPortItemDelegate(this);
	setItemDelegateForColumn(4, pid);
	setItemDelegateForColumn(5, pid);
	if(type != TRANSLATION)
	{
	  IQFComboBoxYesNoItemDelegate *ynd = new IQFComboBoxYesNoItemDelegate(this);
	  setItemDelegateForColumn(8, ynd);
	  setItemDelegateForColumn(9, ynd);
	}
	else
	{
	  setItemDelegateForColumn(8, id); /* New IP Addr */
	  setItemDelegateForColumn(9, pid); /* New Port */
	}
	IQFLineEditGenericStringItemDelegate *gsid = new IQFLineEditGenericStringItemDelegate(this);
	setItemDelegateForColumn(0, gsid);
	
	/* connect() signals and slots (iqf_tree_widget.h ) */
	enableConnections();
	if(type == TRANSLATION)
		natTree = this;
	else
		policyTree = this;
}

IQFRuleTree::~IQFRuleTree()
{
	
}

void IQFRuleTree::emitHelpFromClick(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(col);
	QString h;
	h = buildHelpHtml(it);
	emit helpChanged(h);
}

void IQFRuleTree::emitHelp(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(col);
	/* If the user selects an item, the help and info will show
	 * the information relative to the selected item.
	 */
	if(selectedItems().size() == 0)	
	{
		QString h = buildHelpHtml(it);
		emit helpChanged(h);
	}
}

void IQFRuleTree::treeItemClicked(QTreeWidgetItem *it, int col)
{
	emitInfoFromClick(it, col);
}

void IQFRuleTree::itemColumnChanged(QTreeWidgetItem *it, int col)
{
	printf("\e[1;33mIQFRuleTree::itemColumnChanged, in column %d: (\e[0m",
	       col);
	for(int i = 0; i < it->columnCount(); i++)
		printf("\e[1;36m%s\e[0m|", it->text(i).toStdString().c_str());
	printf(")\e[0m\n");
	IQFRuleTreeItem *tit = dynamic_cast<IQFRuleTreeItem * >(it);
	if(tit != NULL && tit->hasRule() )
	{
		/* if the check fails, we mark the rule as not valid.
		* Note that we never set the rule as valid anymore.
		* This is done because when the user applies or saves
		* the rule, bad rules must be checked.
		*/
		if(!tit->checkColumnChanged(col))
			tit->setRuleInvalid();
		else 
		{	
			/* no problems in the parsing of the item, 
			* rebuild the rule to update the info textBrowser 
			*/
			tit->rebuildRule();
			if(tit->ruleValid())
			  printf("itemColumnChanged: item valid dopo rebuildRUle\n");
			else
			  printf("\e[1;31mItem invalid doop rebuildRule()\e[0m\n");
		}
	}
	else
		qDebug() << "! dynamic_cast error in IQFRuleTree::itemColumnChanged()";
		
}

void IQFRuleTree::emitInfoFromClick(QTreeWidgetItem *it, int col)
{			
	QString tmp = buildInfoHtml(it, col);
	QString i = IQFMessageProxy::msgproxy()->insertInfoIntoHtmlHeader(tmp);
	emit infoChanged(i);
}

void IQFRuleTree::emitInfo(QTreeWidgetItem *it, int col)
{
	if(selectedItems().size() == 0)
	{		
		QString tmp = buildInfoHtml(it, col);
		QString i = IQFMessageProxy::msgproxy()->insertInfoIntoHtmlHeader(tmp);
		emit infoChanged(i);
	}
}

void IQFRuleTree::setExpanded(QTreeWidgetItem *item)
{
	((IQFRuleTreeItem *)item)->setAndStoreExpanded(true); 
}
		
void IQFRuleTree::setCollapsed(QTreeWidgetItem *item)
{
	((IQFRuleTreeItem *)item)->setAndStoreExpanded(false);
	/* when we collapse an item, deselect an eventually selected child */
	for(int i = 0; i < item->childCount(); i++)
		if(item->child(i)->isSelected())
			item->child(i)->setSelected(false); 
}

QString IQFRuleTree::buildHelpHtml(QTreeWidgetItem *it)
{
	QString h;
	IQFRuleTreeItem *iqfit = dynamic_cast<IQFRuleTreeItem *>(it);
	if(!iqfit)
	  return "cannot cast item";
	switch(iqfit->type())
	{
		case IQFRuleTreeItem::OWNER:
			h = IQFMessageProxy::msgproxy()->getHelp("rule_owner");
			break;
		case IQFRuleTreeItem::DIRECTION:
			h = IQFMessageProxy::msgproxy()->getHelp("rule_direction");
			break;
		case IQFRuleTreeItem::POLICY:
			h = IQFMessageProxy::msgproxy()->getHelp("rule_policy");
		default:
			h = IQFMessageProxy::msgproxy()->getHelp("rule_item");
			break;
	}
	return h;
}




void IQFRuleTree::showEvent(QShowEvent *e)
{
	QTreeWidget::showEvent(e);
}

void IQFRuleTree::hideEvent(QHideEvent* e)
{
	QTreeWidget::hideEvent(e);
}


		
void IQFRuleTree::expandItems()
{
	int i;
	QList<QTreeWidgetItem *> items = findItems("*", Qt::MatchRecursive|Qt::MatchWildcard);
	if(items.size() > 0)
	{
		for(i = 0; i < items.size(); i++)
		{
			IQFTreeWidgetItem *twi = dynamic_cast<IQFTreeWidgetItem *>(items[i]);
			IQFRuleTreeItem *it = dynamic_cast<IQFRuleTreeItem *>(twi);
			if(twi == NULL || it == NULL)
				printf("\e[1;31m! dynamic cast failed for IQFRuleTree::expandItems()\n"
						"while converting to IQFTreeWidgetItem * or\n"
						"IQFRuleTreeItem *\nContact the author");
			else
			{
				if(it->childCount() > 0 && it->wasExpanded())
					it->setExpanded(true);
				else 
					it->setExpanded(false);
			}
		}
	}
}
		
void IQFRuleTree::setIQFItemExpanded(QTreeWidgetItem *item)
{
	IQFRuleTreeItem *iqfit = (IQFRuleTreeItem *)(item);
	if(iqfit)
		iqfit->setAndStoreExpanded(true);
	else
		qDebug() << "IQFRuleTree::setIQFItemExpanded(QTreeWidgetItem *item): item NULL!";
}
		
void IQFRuleTree::setIQFItemCollapsed(QTreeWidgetItem *item)
{
	IQFRuleTreeItem *iqfit = (IQFRuleTreeItem *)(item);
	if(iqfit)
		iqfit->setAndStoreExpanded(false);
	else
		qDebug() << "IQFRuleTree::setIQFItemCollapsed(QTreeWidgetItem *item): item NULL!";
}
		
void IQFRuleTree::dropEvent(QDropEvent *e)
{
	int startindex, stopindex;
	IQFRuleTreeItem *startit = (IQFRuleTreeItem *) (selectedItems()[0]);
	IQFRuleTreeItem* stopit = (IQFRuleTreeItem *) (itemAt(e->pos()) );
	IQFRuleTreeItem* tomove = NULL;
	startindex = startit->parent()->indexOfChild(startit);
	stopindex = stopit->parent()->indexOfChild(stopit);
// 	qDebug() << "Indice di start: " << startindex << ", di stop: " << stopindex;
	if(stopit != NULL && startit != NULL)
	{
		if(moveIsPossible(startit, stopit))
		{
			/* take the child we want to move */
            tomove = static_cast<IQFRuleTreeItem *> (startit->parent()->takeChild(startindex));
			if(tomove != NULL)
			{
				if( !((IQFRuleTreeItem *) stopit)->hasRule())
					stopit->insertChild(0, tomove);
				else
					stopit->parent()->insertChild(stopindex, tomove);
				
				/* It is not possible to drag and drop between different directions
				 * or owners, but it is possible to change the rule between
				 * a DENIAL or ACCEPT policy.
				 */
                int parentPolicy = (static_cast<IQFRuleTreeItem *>
                                    (tomove->parent()))->itemPolicy();
                if(tomove->ItemRule().nflags.policy != parentPolicy)
                {
                    tomove->ItemRuleRef().nflags.policy = parentPolicy;
					qDebug() << "The rule has changed the policy";
				}
			}
			else
				qDebug() << "tomove is null!";
			
		}
	}
	return;
	
	
}

bool IQFRuleTree::moveIsPossible(IQFRuleTreeItem *i1, IQFRuleTreeItem *i2)
{
	/* We can move rules just if they have the same direction
	 * and the same owner. This avoids mixing rules designed
	 * for differend directions, which can be dangerous and 
	 * misleading.
	 * Obviously, the rules involved must belong to the same owner.
	 */
// 	qDebug() << "direction1: " << i1->ItemRule().direction << " d2: " << i2->ItemRule().direction;
// 	qDebug() << "i1" << i1->itemDirection() << "i2:" << i2->itemDirection();
	if(i1->itemDirection() == i2->itemDirection() &&
		 i1->itemOwner() == i2->itemOwner())
	{
		return true;
	}
	else
	{
		qDebug() << "Directions differ: you cannot drag and drop between different directions!";
		return false;
	}
}
		
QStringList IQFRuleTree::buildHeaderFromRule(ipfire_rule *r)
{
	QStringList l;
	QString flags;
	QString options;
	RuleStringifier rs(r);
	l << rs.Name() << rs.Proto() << rs.Sip() << rs.Dip() << rs.Sport() << rs.Dport() << rs.InDev() << 
			rs.OutDev() << rs.State() << rs.Notify();
	
	if(r->ip.protocol == IPPROTO_TCP)
		flags = QString("%1 %2 %3 %4 %5 %6").arg(rs.Syn()).arg(rs.Ack()).arg(rs.Fin()).
			arg(rs.Psh()).arg(rs.Rst()).arg(rs.Urg());
	else
		flags = "-";
	  
	l << flags << rs.mssOption() + rs.ftpSupport();

	return l;
}

QStringList IQFRuleTree::buildNatHeaderFromRule(ipfire_rule *r)
{
	qDebug() << "buildNatHeader froma rule " << r->rulename;
	QStringList l;
	QString flags;
	RuleStringifier rs(r);
	
	l << rs.Name() << rs.Proto() << rs.Sip() << rs.Dip() 
			<< rs.Sport() << rs.Dport() <<rs.InDev() << rs.OutDev()
			<< rs.NewIP()  << rs.NewPort();
	
	if(r->ip.protocol == IPPROTO_TCP)
		flags = QString("%1 %2 %3 %4 %5 %6").arg(rs.Syn()).arg(rs.Ack()).arg(rs.Fin()).
				arg(rs.Psh()).arg(rs.Rst()).arg(rs.Urg());
	else
		flags = "-";
	
	l << flags;
	qDebug() << "buildNatHeader froma rule " << l;
	return l;
}

void IQFRuleTree::mousePressEvent(QMouseEvent *e)
{
	if(e->button() == Qt::RightButton)
	{
		IQFRuleTreeItem *item = (IQFRuleTreeItem *) itemAt(e->pos());
		/* Select the item right clicked */
		if(item != NULL)
		{
			QList<QTreeWidgetItem *> treeitemlist = findItems("*", Qt::MatchRecursive|Qt::MatchWildcard);
			if(treeitemlist.size() != 0) /* An item is already selected */
			{
				for(int i = 0; i < treeitemlist.size(); i++)
					if(treeitemlist[i]->isSelected())
						treeitemlist[i]->setSelected(false);
			}
			item->setSelected(true);
		
			QMenu *menu = new QMenu(this);
			if(item->itemOwner() == getuid() &&  (item->type() > IQFRuleTreeItem::NAT 
				|| item->type() == IQFRuleTreeItem::DIRECTION || item->type() ==
				IQFRuleTreeItem::FILTER) && !item->isNatural() )
			{
				menu->addAction("Add rule", this, SLOT(addRule()));
				if(item->hasRule() )
				{
					menu->addAction("Modify rule", this, SLOT(modifyRule() ));
					menu->addAction("Delete rule", this, SLOT(deleteRule()));
					menu->addSeparator();
					menu->addAction("Copy item", this, SLOT(copySelectedItem()));
				}
				
				if(d_copyItemTexts.size())
				  menu->addAction("Paste item", this, SLOT(pasteItem()));
			}
			else if(item->isNatural() && item->itemOwner() == getuid())
			{
			  menu->addAction("Natural rules...", this, SLOT(slotShowNaturalLanguage()));
			  if(item->itemOwner() == getuid() && (item->type() > IQFRuleTreeItem::NAT 
				|| item->type() == IQFRuleTreeItem::DIRECTION || item->type() ==
				IQFRuleTreeItem::FILTER) )
			    menu->addAction("Add rule classically...", this, SLOT(addRule()));
			    menu->addSeparator();
			    menu->addAction("Copy item", this, SLOT(copySelectedItem()));
			    if(d_copyItemTexts.size())
			      menu->addAction("Paste item", this, SLOT(pasteItem()));
			}
			
			menu->exec(e->globalPos());		
		}
	}
	else /* another button */
		QTreeWidget::mousePressEvent(e);
	
}

void IQFRuleTree::addCancel()
{
	emit blockInterface(false);
}

void IQFRuleTree::applyModifyRule()
{
	QList<QTreeWidgetItem *> itlist = selectedItems();
	IQFRuleAdder *radder = qobject_cast<IQFRuleAdder*>(sender());
	ipfire_rule modrule;
	emit blockInterface(false);
	int index;
	if(itlist.size() != 1 || radder == NULL)
		return;
	IQFRuleTreeItem *newitem, *item = (IQFRuleTreeItem *) itlist[0];
	modrule = radder->Rule();
	modrule.owner = getuid();
	if(item->type() > IQFRuleTreeItem::NAT)
		newitem = new IQFRuleTreeItem(buildNatHeaderFromRule(&modrule),
				modrule);
	else
		newitem = new IQFRuleTreeItem(buildHeaderFromRule(&modrule),modrule);
		
	newitem->setPolicy(modrule.nflags.policy);
	newitem->setOwner(getuid());
	newitem->setDirection(modrule.direction);
	newitem->setHasRule(true);
	newitem->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEditable | Qt::ItemIsDragEnabled | Qt::ItemIsEnabled);
	newitem->determineTypeFromRule();
	if(item->hasRule())
	{
		/* We add a rule after having selected a rule: the item 
		* will be the child of the parent of the selected item,
		* not of the item itself */
		/* Do not use the associated rule position: the rule.position
		* represents the position inside the per-policy vector, not
		* the position inside the in/out/fwd parts.
		*/
		if(itlist[0]->parent() != NULL)
		{
			index = itlist[0]->parent()->indexOfChild(itlist[0]);
			itlist[0]->parent()->insertChild(index, newitem);
		}
		item->setSelected(false);
		delete item;
		newitem->setSelected(true);
		emitInfoFromClick(newitem, 0);
	}
	/* radder is the sender(): do not delete here */
}

void IQFRuleTree::applyAddRule()
{
	QList<QTreeWidgetItem *> itlist = selectedItems();
	IQFRuleAdder *radder = qobject_cast<IQFRuleAdder*>(sender());
	ipfire_rule newrule;
	/* re enable the interface */
	emit blockInterface(false);
	if(itlist.size() != 1 || radder == NULL)
		return;
	IQFRuleTreeItem *newitem, *item = (IQFRuleTreeItem *) itlist[0];
	
	newrule = radder->Rule();
	newrule.owner = getuid();
	if(item->type() > IQFRuleTreeItem::NAT)
		newitem = new IQFRuleTreeItem(buildNatHeaderFromRule(&newrule),newrule);
	else
		newitem = new IQFRuleTreeItem(buildHeaderFromRule(&newrule),newrule);
	newitem->setPolicy(newrule.nflags.policy);
	newitem->setOwner(getuid());
	newitem->setDirection(newrule.direction);
	newitem->setHasRule(true);
	newitem->setFlags(Qt::ItemIsSelectable |Qt::ItemIsEditable | Qt::ItemIsDragEnabled |Qt::ItemIsEnabled);
	newitem->determineTypeFromRule();
	
	if(item->hasRule())
	{
		/* We add a rule after having selected a rule: the item 
		* will be the child of the parent of the selected item,
		* not of the item itself */
		/* Do not use the associated rule position: the rule.position
		* represents the position inside the per-policy vector, not
		* the position inside the in/out/fwd parts.
		*/	
		if(itlist[0]->parent() != NULL)
			itlist[0]->parent()->insertChild(itlist[0]->parent()
					->indexOfChild(itlist[0]) + 1, newitem);
	}
	else
	{
	/* The new item is inserted as a top level one. */
		item->insertChild(0, newitem);
	}
	item->setSelected(false);
	newitem->setExpanded(true);
	newitem->setSelected(true);
	emitInfoFromClick(newitem, 0);
	/* radder is the sender(): do not delete here */
}

void IQFRuleTree::undoChanges()
{
	populateTree();
}

void IQFRuleTree::addRule()
{
	QList<QTreeWidgetItem *> itlist = selectedItems();
	IQFRuleAdder *radder;

	if(itlist.size() != 1)
	{
		QMessageBox::information(this, "Error", 
			QString("The size of the selected item is %1, should be 1!").arg(itlist.size()));
		return;
	}
	/* disable interaction with the tree and signal the 
	* mainwindow that the user is modifying/adding a rule
	*/
	emit blockInterface(true);
	IQFRuleTreeItem *item = (IQFRuleTreeItem *) itlist[0];
	radder = new IQFRuleAdder(this, item, IQFRuleAdder::Add);
	connect(radder, SIGNAL(applyOk()), this, SLOT(applyAddRule()));
	connect(radder, SIGNAL(applyCancel()), this, SLOT(addCancel()));
	radder->show();
	
}

void IQFRuleTree::modifyRule()
{
	QList<QTreeWidgetItem *> itlist = selectedItems();
	IQFRuleAdder *radder;
	if(itlist.size() != 1)
	{
		QMessageBox::information(this, "Error", 
					 QString("The size of the selected item is %1, should be 1!").arg(itlist.size()));
		return;
	}
	emit blockInterface(true); /* the mainwindow will disable something */
	IQFRuleTreeItem  *item = (IQFRuleTreeItem *) itlist[0];
	radder = new IQFRuleAdder(this, item, IQFRuleAdder::Modify);
	connect(radder, SIGNAL(applyOk()), this, SLOT(applyModifyRule()));
	connect(radder, SIGNAL(applyCancel()), this, SLOT(addCancel()));
	radder->setWindowTitle("Modify a rule");
	radder->show();
	
}

void IQFRuleTree::deleteRule()
{
	QList<QTreeWidgetItem *> itlist = selectedItems();
	if(itlist.size() != 1)
	{
		QMessageBox::information(this, "Error", 
			QString("The size of the selected item is %1, should be 1!").arg(itlist.size()));
		return;
	}
	IQFRuleTreeItem *item = dynamic_cast<IQFRuleTreeItem *>(itlist[0]);
	if(item->hasRule())
	{
		delete item;
	}
}

void IQFRuleTree::removeNaturalItems()
{
  NaturalRuleItemRemover remover(this);
  remover.removeNaturalRules();
}

void IQFRuleTree::applyRules()
{
	int i;
	Policy* policy = Policy::instance();
	ipfire_rule newrule;
	ipfire_rule nullRule;
	NaturalRuleHash *ruleHash = NaturalRuleHash::naturalRuleHashMap();
	memset(&nullRule, 0, sizeof(nullRule));
	memset(&newrule, 0, sizeof(newrule));
	QVector<ipfire_rule> new_acc_rules, new_den_rules, new_transl_rules;
	/* clear the item list before beginning */
	itemlist.clear();
	/* Since the user can move the items in the tree, we must parse the 
	* whole tree to get all the rules in their up to date order.
	*/
	QString wild = QString("*");
	QList<QTreeWidgetItem *> treeitemlist = findItems(wild, Qt::MatchRecursive|Qt::MatchWildcard);

	IQFRuleTreeItem *iqfitem;

	switch(type)
	{
	  case TRANSLATION:
	    ruleHash->clearNatMap();
	    break;
	  default:
	    ruleHash->clearFilterMap();
	    break;
	}
	for(i = 0; i < treeitemlist.size(); i++)
	{
		iqfitem = dynamic_cast<IQFRuleTreeItem *> (treeitemlist[i]);
		if(iqfitem != NULL && iqfitem->hasRule() && 
		  iqfitem->ItemRule().owner == getuid() && !iqfitem->ruleValid())
		{
			if(!iqfitem->reviseForErrors())
			{
				QMessageBox::information(this, "iqFirewall", QString
					("The rule \"%1\" contains errors in %2 columns.\n"
							"Correct them before clicking on \"Apply\" again").arg
							(iqfitem->text(0)).arg(iqfitem->columnsWithErrors().size()));
				return;
			}
		}
	}
	
	for(i = 0; i < treeitemlist.size(); i++)
	{
		iqfitem = dynamic_cast<IQFRuleTreeItem *> (treeitemlist[i]);
		if(iqfitem == NULL)
		{
			printf("! cannot dynamic_cast to IQFRuleTreeItem* "
					"in IQFRuleTree::applyRules()");
			continue; /* proceed to the next */
		}
		
		/* Only the rules owned by the user can be saved */
		qDebug() << iqfitem->text(0) << iqfitem->text(1) << iqfitem->text(2) << "rulevalid:" << iqfitem->ruleValid() <<
		  "has rule" << iqfitem->hasRule() << "item owner: ";
		if(iqfitem->ruleValid() && iqfitem->hasRule() && iqfitem->ItemRule().owner == getuid())
		{
		  if(iqfitem->isNatural()) /* save natural sentence */
		  {
		    ipfire_rule r = iqfitem->ItemRule();
		    ruleHash->addNaturalRule(&r, iqfitem->associatedNaturalSentence());
		  }
		  printf("ottengo regola con toRule()\n");
		  qDebug() << iqfitem->text(0) << iqfitem->text(1) << iqfitem->text(2);
			iqfitem->toRule(&newrule); /* just to check if it is valid */
			if(memcmp(&nullRule, &newrule, sizeof(newrule)))
			{
			  printf("memcmp() ok, non sembra nulla\n");
				/* The tree will not allow to change the policy and the direction */
				switch(iqfitem->ItemRule().nflags.policy) /* ^ */
				{
					case DENIAL:
						new_den_rules.push_back(newrule);
						break;
					
					case ACCEPT:
						new_acc_rules.push_back(newrule);
						break;
						
					case TRANSLATION:
						if(getuid() == 0) /* another check if the user is root */
						{
							new_transl_rules.push_back(newrule);
						}
						else
							qDebug() << "We should not be here! saveFilterRules(): case TRANSLATION";
						break;
					default:
						qDebug() << "Invalid policy " << iqfitem->ItemRule().nflags.policy;
						break;
				}
			}
			else
				Log::log()->appendFailed(QString("The rule \"%1\" "
					"could not be added because there is a "
						"syntax error in its fields").arg(iqfitem->text(0) ));
		}
	}
	
	/* We have now built the three vectors with the new rules 
	 * Tell the policy instance to set the current vectors 
	 * and update the kernel rules 
	 */
	if(type != TRANSLATION) /* Commit the denial and permission rules only if
				   we are a tree widget of type ACCEPT or DENIAL */
	{
		policy->setDenialRules(new_den_rules);
		policy->updateDenialRules();
		policy->setAcceptRules(new_acc_rules);
		policy->updateAcceptRules(); 
	}
	else if(type == TRANSLATION)
	{
		if(getuid() == 0)
		{
			
			policy->setTranslationRules(new_transl_rules);
			policy->updateTranslationRules();
		}
	}
	
	populateTree();
}

bool IQFRuleTree::itemSelected()
{	
	int i;
	QList<QTreeWidgetItem *> treeitemlist;
	if(IQFRuleTree::natTree != NULL)
	{
		treeitemlist = IQFRuleTree::natTree->findItems("*",
				Qt::MatchRecursive|Qt::MatchWildcard);
		for(i = 0; i < treeitemlist.size(); i++)
			if(treeitemlist[i]->isSelected())
				return natTree->isVisible();
	}
	if(IQFRuleTree::policyTree != NULL)
	{
		treeitemlist = IQFRuleTree::policyTree->findItems("*",
				Qt::MatchRecursive|Qt::MatchWildcard);
		for(i = 0; i < treeitemlist.size(); i++)
			if(treeitemlist[i]->isSelected())
				return policyTree->isVisible();
	}
	
	return false;
}

void IQFRuleTree::saveTreeState(int a , int b, int c)
{
	Q_UNUSED(a);
	Q_UNUSED(b);
	Q_UNUSED(c);
	QByteArray ba = header()->saveState();
	QSettings s;
	s.setValue("TREE_HEADER_STATE", ba);
}

void IQFRuleTree::addNaturalItem(const uid_t owner, const int policy, const int direction, const QStringList& itemStrings, 
	const QString& naturalSentence)
{
  ipfire_rule rule;
  bool inserted = false;
  int childIndex;
  IQFRuleTreeItem *item = NULL;
  QSettings s;
  
  if(owner != getuid())
  {
    QMessageBox::information(this, "Error: owner mismatch", QString("You are user %1, while rule has owner %2.").arg(getuid()).
      arg(owner));
    return;
  }
  
  item = new IQFRuleTreeItem(itemStrings, rule);
  
  item->setHasRule(true);
  item->setOwner(owner);
  item->setDirection(direction);
  item->setPolicy(policy);
  item->setFlags(Qt::ItemIsSelectable  |  Qt::ItemIsEnabled);
  item->setIsNatural(true);
  NaturalSentence ns(naturalSentence);
  item->setAssociatedNaturalSentence(ns);
  printf("setting associated natural sentence \"%s\" a item \"%s\"\n", 
    qstoc(ns), qstoc(item->text(0)));
  /* toRule(): given the tree widget item, fills in an ipfire_rule with the values taken from the columns.
    * NOTE: the owner, the direction and the policy are taken from the tree widget item properties.
    */
  item->toRule(&rule); /* but does not set myrule inside item */
  rule.natural = 1;
  item->setItemRule(rule); /* so set it now */
  item->determineTypeFromRule();
  QColor itemColor(KDARKBLUE);
  itemColor.setAlpha(127);
  
  if(policy == DENIAL)
  {
    if(direction == IPFI_INPUT)
    {
      if(!itemRuleAlreadyInTree(deninitem, item))
      {
	childIndex = deninitem->childCount();
	deninitem->insertChild(childIndex, item);
	item->setIcon(0, QIcon(ICON_PATH + "new_natural_rule.png"));
	item->colourItem(itemColor);
	inserted = true;
      }
    }
    else if(direction == IPFI_OUTPUT)
    {
      if(!itemRuleAlreadyInTree(denoutitem, item))
      {
       childIndex = denoutitem->childCount();
       denoutitem->insertChild(childIndex, item);
	item->setIcon(0, QIcon(ICON_PATH + "new_natural_rule.png"));
	item->colourItem(itemColor);
	inserted = true;
      }
    }
    else if(direction == IPFI_FWD)
    {
     if(!itemRuleAlreadyInTree(denfwditem, item))
      {
       childIndex = denfwditem->childCount();
       denfwditem->insertChild(childIndex, item);
	item->setIcon(0, QIcon(ICON_PATH + "new_natural_rule.png"));
	item->colourItem(itemColor);
	inserted = true;
      }
    }
  }
  else if(policy == ACCEPT)
  {
     if(direction == IPFI_INPUT)
    {
      if(!itemRuleAlreadyInTree(accinitem, item))
      {
	childIndex = accinitem->childCount();
	accinitem->insertChild(childIndex, item);
	item->setIcon(0, QIcon(ICON_PATH + "new_natural_rule.png"));
	item->colourItem(itemColor);
	inserted = true;
      }
    }
    else if(direction == IPFI_OUTPUT)
    {
       if(!itemRuleAlreadyInTree(accoutitem, item))
      {
       childIndex = accoutitem->childCount();
       accoutitem->insertChild(childIndex, item);
	item->setIcon(0, QIcon(ICON_PATH + "new_natural_rule.png"));
	item->colourItem(itemColor);
	inserted = true;
      }
    }
    else if(direction == IPFI_FWD)
    {
       if(!itemRuleAlreadyInTree(accfwditem, item))
      {
       childIndex = accfwditem->childCount();
       accfwditem->insertChild(childIndex, item);
	item->setIcon(0, QIcon(ICON_PATH + "new_natural_rule.png"));
	item->colourItem(itemColor);
	inserted = true;
      }
    }
  }
  
 if(!inserted)
   delete item;
 else
 {
   if(item->parent())
    item->parent()->setExpanded(true);
 }
  
}

bool IQFRuleTree::itemRuleAlreadyInTree(IQFRuleTreeItem* parent, IQFRuleTreeItem* item)
{
  ipfire_rule r1;
  ipfire_rule r2;
  int i;
  for(i = 0; i < parent->childCount(); i++)
  {
    QTreeWidgetItem *it = parent->child(i);
    IQFRuleTreeItem* rti = dynamic_cast<IQFRuleTreeItem *>(it);
    if(rti)
    {
      r1 = rti->ItemRule();
      r2 = item->ItemRule();
      RuleComparator comp(&r1, &r2);
      if(comp.rulesEqual())
      {
	pinfo("rule %s already present", r2.rulename);
	return true;
      }
    }
  }
  if(i < parent->childCount())
    pok("Rule \"%s\" added from natural language", r2.rulename);
  return false;
}

/* saves selected item text fields into d_copyItemText for future paste and item creation 
 */
void IQFRuleTree::copySelectedItem()
{
  QList<QTreeWidgetItem *> selected = selectedItems();
  if(selected.size() == 1)
  {
    d_copyItemTexts.clear();
    for(int i = 0; i < selected.first()->columnCount(); i++)
      d_copyItemTexts << selected.first()->text(i);
  }
}

bool IQFRuleTree::pastePossible()
{
  if(d_copyItemTexts.size())
  {
    /* find selected items */
    QList<QTreeWidgetItem *> selected = selectedItems();
    if(selected.size() == 1)
    {
      IQFRuleTreeItem *rti = dynamic_cast<IQFRuleTreeItem *>(selected.first());
      if(rti->itemOwner() == getuid())
	return true;
    }
  }
  return false;
}

void IQFRuleTree::pasteItem()
{
  if(d_copyItemTexts.size())
  {
    /* find selected items */
    QList<QTreeWidgetItem *> selected = selectedItems();
    if(selected.size() == 1)
    {
      IQFRuleTreeItem *rti = dynamic_cast<IQFRuleTreeItem *>(selected.first());
      /* must be able to convert */
      if(rti != NULL) 
      {
	QTreeWidgetItem *parent;
	if(rti->hasRule())
	  parent = rti->parent();
	else 
	  parent = rti;
	/* now cast parent: it must be an IQFRuleTreeItem too */
	IQFRuleTreeItem *parent_rti = dynamic_cast<IQFRuleTreeItem *>(parent);
	
	if(rti->itemOwner() == getuid() && parent_rti)
	{
	  ipfire_rule tempRule;
	  IQFRuleTreeItem *newItem = new IQFRuleTreeItem(parent, d_copyItemTexts);
	  newItem->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEditable | Qt::ItemIsDragEnabled |  Qt::ItemIsEnabled);
	  newItem->setPolicy(rti->itemPolicy());
	  newItem->setOwner(getuid());
	  newItem->setDirection(rti->itemDirection());
	  newItem->setHasRule(true);
	  newItem->toRule(&tempRule);
	  newItem->setItemRule(tempRule);
	  /* set the new item type */
	  newItem->setType(parent_rti->type());
	  qDebug() << "pasted item" << rti->itemPolicy() << getuid() << rti->itemDirection() << newItem->type();
	}
      }
    }
  }
}



