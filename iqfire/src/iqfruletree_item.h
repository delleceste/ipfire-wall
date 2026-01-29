#ifndef IQF_RULETREE_ITEM
#define IQF_RULETREE_ITEM

#include <QTreeWidget>
#include "iqf_tree_item.h"
#include "iqf_tree_widget.h"
#include <ipfire_structs.h>
#include <NaturalSentence.h>

class IQFRuleTree;
class Policy;
class IQFTextBrowser;

class IQFRuleTreeItem : public IQFTreeWidgetItem
{
	public:
		
	/* NAT is for folders, SNAT, DNAT, OUTDNAT, MASQ for rules
		* N.B: xNAT elements MUST follow NAT
	*/
		enum types { OWNER, POLICY, DIRECTION, FILTER, NAT, SNAT, DNAT, OUTDNAT, MASQ  };
		
		IQFRuleTreeItem(QTreeWidgetItem* parent, ipfire_rule rule);
		IQFRuleTreeItem(QTreeWidgetItem* parent, const QStringList & strings, ipfire_rule rule);
		IQFRuleTreeItem(QTreeWidget* parent, ipfire_rule rule);
		IQFRuleTreeItem(QTreeWidget* parent);
		IQFRuleTreeItem(QTreeWidgetItem* parent);
		IQFRuleTreeItem(QTreeWidget* parent, const QStringList & strings, ipfire_rule rule);
		IQFRuleTreeItem(const QStringList & strings, ipfire_rule rule);
		IQFRuleTreeItem(QTreeWidgetItem* parent, const QStringList & strings);
		
		~IQFRuleTreeItem();
	
	/** returns the rule associated to this element.
		 * Returns NULL if the element does not have 
		 * a rule associated. This happens if the item is a `folder'
	 */
		ipfire_rule ItemRule() { return myrule; }
        ipfire_rule &ItemRuleRef() { return myrule; }
		void setItemRule(const ipfire_rule& other);
		void rebuildRule();
		void setPolicy(int p) { policy = p; has_policy = true; }
		void setDirection(int d) { direction = d; has_direction = true; }
		void setOwner(uid_t o) { owner = o; }
		void setHasRule(bool has) { has_rule = has; }
		void setIsNatural(bool natural) { d_natural = natural; }
		void setAssociatedNaturalSentence(NaturalSentence &ns) { d_naturalSentence = ns; }
		NaturalSentence associatedNaturalSentence() { return d_naturalSentence; }
	
	/* Each item has to save the following three parameters
		* because in top level items we do not have a rule
		* associated that stores such parameters.
	*/
		int itemPolicy() { return policy; }
		int itemDirection() { return direction; }
		uid_t itemOwner() { return owner; }
	
		bool hasRule() { return has_rule; }
		bool hasDirection() { return has_direction; }
		bool hasPolicy() { return has_policy; }
		bool isNatural() { return d_natural; }
	
		void setItemExpanded(bool exp) { expanded = exp; }
	
		int type() { return _type; }
		void setType(int t) { _type = t; }
	
		/* has rule must be set for this to work */
		void determineTypeFromRule();
	
	/* reading the contents of the treeWidgetItem, it builds and returns 
		* a rule. This is used when the user modifies the fields of an
		* existing rule inside the tree.
	*/
		void toRule(ipfire_rule* ruleToBuild);
	
		bool wasExpanded();
		void setAndStoreExpanded(bool expanded);
	
		void setIconPath(QString icon) { sicon = icon; }
		QString iconPath() { return sicon; }

	/** checks if a determined column contains an error 
		 *  it is implemented here: in IQFRuleTreeItem this is pure 
		 * virtual
	 */
		bool checkColumnChanged(int col);
		
		bool checkNatRequirements();
	
	private:
		ipfire_rule myrule;
		uid_t owner;
		int direction, policy, _type;
		bool has_rule, has_direction, has_policy, expanded; /* true if the element has a rule associated */
		QString buildItemKey();
		QString sicon;
		bool d_natural;
		NaturalSentence d_naturalSentence;
};

#endif

