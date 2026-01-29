#include "iqf_pending_rules.h"
#include "iqf_pending_tree.h"
#include "iqflog.h"
#include "iqfpolicy.h"
#include "iqfire.h"
#include <QtDebug>
#include <QGridLayout>


WPendingRules::WPendingRules(QWidget *p) :  QWidget(p)
{
	QSettings s; /* for ICON_PATH */
	QGridLayout *lo = new QGridLayout(this);
	ignTree = new IQFPendingTree(this);
	ignTree->setObjectName("Ignored tree widget");
	pbAccept = new IQFPushButton(this);
	pbAccept->setText("Accept");
	pbAccept->setObjectName("pbPendingAccept");
	pbBlock = new IQFPushButton(this);
	pbBlock->setText("Block");
	pbBlock->setObjectName("pbPendingBlock");
	pbDelete = new IQFPushButton(this);
	pbDelete->setText("Remove");
	pbDelete->setObjectName("pbPendingRemove");
	
	lo->setSpacing(4);
	lo->setMargin(4);
	lo->addWidget(ignTree, 0, 0, 6, 6);
	lo->addWidget(pbAccept, 6, 3, 1, 1);
	lo->addWidget(pbBlock, 6, 4, 1, 1);
	lo->addWidget(pbDelete, 6, 5, 1, 1);
	
	pbAccept->setIcon(QIcon(ICON_PATH + "ok_green.png"));
	pbBlock->setIcon(QIcon(ICON_PATH + "stop.png"));
	pbDelete->setIcon(QIcon(ICON_PATH + "user-trash.png"));
	
	/* By default, resolve services */
	resolve_enabled = s.value("NOTIFIER_RESOLVE_ENABLE", true).toBool();
	
	connect(pbAccept, SIGNAL(clicked()), this, SLOT(acceptRule()));
	connect(pbBlock, SIGNAL(clicked()), this, SLOT(blockRule()));
	connect(pbDelete, SIGNAL(clicked()), this, SLOT(removeItem()));
	
	reloadTree();
}



WPendingRules::~WPendingRules()
{
// 	printf("\e[1;32m*\e[0m saving ignored packets list...\t");
// 	fflush(stdout);
// 	if(IgnoredPacketsSet::instance()->saveIgnoredPackets() < 0)
// 		printf("\e[1;31mfailed\e[0m.\n");
// 	else
// 		printf("\e[1;32mOk\e[0m.\n");
}

void WPendingRules::reloadTree()
{
	int i;
	ignTree->clear();
	IgnoredPacketsSet *ign_set = IgnoredPacketsSet::instance();
	QList<IgnoredPacket> ignoredList = ign_set->list();
	
	for(i = 0; i < ignoredList.size(); i++)
	{	
// 		qDebug() << "aggiungo ignorato: " << ignoredList[i].toReadableString();
		
		IQFPendingTreeItem* item = ignTree->addItem(ignoredList[i], resolve_enabled);
		connect(item, SIGNAL(itemResolved()), ignTree, SLOT(anItemWasResolved()));
		Q_UNUSED(item);
	}

}

void WPendingRules::addItem()
{
// 	qDebug() << "Aadding a single ignored";
	IgnoredPacket newign = IgnoredPacketsSet::instance()->lastAdded();
	IQFPendingTreeItem* item = new IQFPendingTreeItem(ignTree, newign, resolve_enabled);
	Q_UNUSED(item);
}

void WPendingRules::acceptRule()
{
	QList<QTreeWidgetItem *> selected_items = ignTree->selectedItems();
	QList<QTreeWidgetItem *>::iterator i;
	ipfire_rule newrule;
	
	if(selected_items.size() == 0)
	{
		QMessageBox::information(this, "Warning", "You can select at least one element");
	}
	else
	{
		i = selected_items.begin();
		while(i != selected_items.end())
		{
			IQFPendingTreeItem *pip = (IQFPendingTreeItem *) *i;
			
			/* This must be called because an IgnoredPacket does not know about
			* its policy up to now!
			*/
			pip->setPolicy(ACCEPT);
			newrule = pip->itemToRule();
			if(pip->ruleValid()) /* the RuleBuilder called by itemToRule succeeded */
			{
				if(pip->hasIgnoredPacket())
				{
					IgnoredPacket igp = pip->ignoredPacket();
					IgnoredPacketsSet* ips =  IgnoredPacketsSet::instance();
					/* Remove the ignored packet from the packet set */
					ips->remove(igp);
				}
				else
					Log::log()->appendFailed(QString("The item selected (%1) has no ignored packet."
							"Contact the author. Thank you.").arg((*i)->text(7)));
				
				
				
				Policy *iqpolicy = Policy::instance();
				iqpolicy->appendRule(newrule);
				iqpolicy->notifyRulesChanged();
				
				Log::log()->appendOk(QString("A new rule with name \"%1\"\n"
						"has been added from the list of connections\n"
						"waiting for authorization").arg((*i)->text(7)));
			}
			else
				qDebug() << "not added " << pip->text(0) << pip->text(1) <<
					pip->text(2) << pip->text(3) << ": rule not valid";
			i++;
		}
		/* Remove the items from the tree */
		i = selected_items.begin();
		while(i != selected_items.end())
		{
			IQFPendingTreeItem *pip = (IQFPendingTreeItem *) *i;
			if(pip->ruleValid())
				ignTree->deleteItem(pip);
			i++;
		}
	}
}

void WPendingRules::blockRule()
{
	qDebug() << "da implementare";
	
	// mi raccomando, usare la deleteItem()!!!
	// ignTree->deleteItem(pip);
}

void WPendingRules::removeItem()
{
	QList<QTreeWidgetItem *> selected_items = ignTree->selectedItems();
	QList<QTreeWidgetItem *>::iterator i;
	if(selected_items.size() == 0)
	{
		QMessageBox::information(this, "Warning", "You can select at least one element");
	}
	else
	{
		i = selected_items.begin();
		while(i != selected_items.end())
		{
			IQFPendingTreeItem *pip = (IQFPendingTreeItem *) *i;
			if(pip->hasIgnoredPacket())
			{
				IgnoredPacket igp = pip->ignoredPacket();
				IgnoredPacketsSet* ips =  IgnoredPacketsSet::instance();
				/* Remove the ignored packet from the packet set */
				ips->remove(igp);
			}
			else
				Log::log()->appendFailed(QString("The item selected (%1) has no ignored packet."
					"Contact the author. Thank you.").arg((*i)->text(7)));
			i++;
		}
		/* Remove the items from the tree */
		i = selected_items.begin();
		while(i != selected_items.end())
		{
			IQFPendingTreeItem *pip = (IQFPendingTreeItem *) *i;
			ignTree->deleteItem(pip);
			i++;
		}
	}
}













