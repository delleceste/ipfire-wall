#ifndef IQFRULE_ADDER_H
#define IQFRULE_ADDER_H

#include <QDialog>
#include "iqfwidgets.h"
#include "iqfruletree_item.h"
#include <ui_iqfrule_adder.h>
#include <ipfire_structs.h>

class IQFRuleTreeItem;
class QMouseEvent;


class IQFRuleAdder : public QDialog
{
	Q_OBJECT
	public:
		/** The constructor accepts the parent widget and the 
		 * IQFRuleTreeItem selected to add a rule after or to 
		 * modify the assciated rule.
		 * If ruleitem is NULL, then the user adds a new
		 * rule from scratch, that is without right-clicking
		 * on the tree item.
		 */
		IQFRuleAdder(QWidget *parent, IQFRuleTreeItem* ruleitem, int act);
		IQFRuleAdder(QWidget *parent, IQFRuleTreeItem* ruleitem, int act,
			    int _pol, int _dir, int _typ);
		~IQFRuleAdder();
		
		/** Returns the rule filled in by the user in the form */
		ipfire_rule Rule() { return rule; }
		void setAction(int a) { adder_action = a; }
		int action() { return adder_action; }
		
		enum adderAction { Modify, Add };
		
		void fixDirection(int direction);
		void fixPolicy(int policy);
		void fixNatType(QString type);
		
		
		
	protected:
		void mouseReleaseEvent(QMouseEvent *e);
		void closeEvent(QCloseEvent *e);
		
	signals:
		void applyOk();
		void applyCancel();
		
	protected slots:
		void apply();
		void cancel(); 
		void previousPage();
		void nextPage();
		
		void showTCPFlags();
		void hideTCPFlags();
		void showIPOptions();
		void hideIPOptions();
		void outdevEnabled(bool en);
		void indevEnabled(bool en);
		void dportNotChecked(bool);
		void sportNotChecked(bool);
		
		void rebuildSummary();
		void rebuildSummary(const QString &s);
		
		void checkFTPSupportOnUI(bool);
		
		void showIPSList(bool);
		void showIPDList(bool);
		void showPSList(bool);
		void showPDList(bool);
		
		void setupComboConnections();
		void removeSipFromList();
		void removeDipFromList();
		void removeSportFromList();
		void removeDportFromList();
		void applySipList();
		void applyDipList();
		void applySportList();
		void applyDportList();
		
		
	private:
		Ui::RuleAdder ui;
		ipfire_rule rule; /* the rule associated to the item, if an item is passed */
		void readRuleAndFill();
		void setupForm();
		void setupHelp();
		void setupInfo();
		void setupCombos();
		
		void setupUiLogic(); /* in iqfrule_adder_help.cpp */
		
		void buildConnectionsForSummary();
		int buildRuleFromForm();
		IQFRuleTreeItem *item;
		int adder_action;
		int _policy, _direction, _type;
		QPalette defaultLineEditPalette;
		bool _ruleValid;
};







#endif





