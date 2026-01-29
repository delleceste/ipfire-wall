#ifndef IQFRULETREE_H
#define IQFRULETREE_H

#include <QTreeWidget>
#include "iqf_tree_item.h"
#include "iqf_tree_widget.h"
#include "iqfruletree_item.h"
#include <ipfire_structs.h>

class IQFRuleTree;
class Policy;


class IQFRuleTree : public IQFTreeWidget
{
	Q_OBJECT
			
	public:
		
	IQFRuleTree(QWidget* parent, int type);
	~IQFRuleTree();
	
	void setDenialRules(QVector<ipfire_rule> denial_rules)
		{ v_den = denial_rules; }
	void setAcceptRules(QVector<ipfire_rule> acc_rules)
		{ v_acc = acc_rules; }
	void setTranslationRules(QVector<ipfire_rule> tr_rules)
		{ v_tr = tr_rules; }
	
	int Type() { return type; }
	
	static bool itemSelected();
	
	public slots:
		void undoChanges();
		void applyRules();
		void setExpanded(QTreeWidgetItem *item);
		void setCollapsed(QTreeWidgetItem *item);
		void populateTree();
		void emitHelp(QTreeWidgetItem *, int);
		void emitInfo(QTreeWidgetItem *, int);
		void emitInfoFromClick(QTreeWidgetItem *it, int col);
		void emitHelpFromClick(QTreeWidgetItem *it, int col);
		void setIQFItemExpanded(QTreeWidgetItem *item);
		void setIQFItemCollapsed(QTreeWidgetItem *item);
		
		/* a new natural item to add to the tree */
		void addNaturalItem(const uid_t, const int, const int, const QStringList&, const QString&);
		/* remove natural items */
		void removeNaturalItems();
		
		void slotShowNaturalLanguage() { emit showNaturalLanguage(); }
		
	protected:
		void showEvent(QShowEvent *e);
		void hideEvent(QHideEvent *e);
		
		void dropEvent(QDropEvent *e);
		bool moveIsPossible(IQFRuleTreeItem *i1, IQFRuleTreeItem *i2);
		void mousePressEvent(QMouseEvent *);
		
	protected slots:
// 		void itemDoubleClicked(QTreeWidgetItem *it, int col);
		void itemColumnChanged(QTreeWidgetItem *it, int col);
		void treeItemClicked(QTreeWidgetItem *, int);
		void saveTreeState(int, int, int);
		void copySelectedItem();
		void pasteItem();
			
	signals:
		void acceptRulesChanged(QVector<ipfire_rule> acc_rules);
		void denialRulesChanged(QVector<ipfire_rule> denial_rules);
		void translationRulesChanged(QVector<ipfire_rule> tr_rules);
		
		void helpChanged(QString s);
		void infoChanged(QString s);
		
		void blockInterface(bool block);
		void showNaturalLanguage();
	
	private slots:
		void addRule();
		void modifyRule();
		void deleteRule();
		void applyAddRule();
		void applyModifyRule();
		void addCancel();
		
	private:
		QVector<ipfire_rule> v_den, v_acc, v_tr;
		Policy *policy;
		int type;
		
		QString buildHelpHtml(QTreeWidgetItem *iqfit);
		QString buildInfoHtml(QTreeWidgetItem *iqfit, int col);
		QStringList buildHeaderFromRule(ipfire_rule* r);
		QStringList buildNatHeaderFromRule(ipfire_rule* r);
		
		/* Stores the pointers to the new items.
		 * For convenience,  populateTree only adds the items 
		 * containing a rule.
		 */
		QVector<IQFRuleTreeItem*> itemlist;
		
		void expandItems();
		bool pastePossible();
		
		static IQFRuleTree *natTree, *policyTree;
		
		/* need to be class members because used by addNaturalItem():
		 * they are the normal user reference top level items
		 */
		IQFRuleTreeItem *accoutitem, *accfwditem, *accinitem;
		IQFRuleTreeItem *denoutitem, *denfwditem, *deninitem;
		QStringList d_copyItemTexts;
		bool itemRuleAlreadyInTree(IQFRuleTreeItem* parent, IQFRuleTreeItem* item);
};

#endif




