#include "naturalRuleItemRemover.h"

NaturalRuleItemRemover::NaturalRuleItemRemover(IQFRuleTree *tree)
{
  d_tree = tree;
}

void NaturalRuleItemRemover::removeNaturalRules()
{
   QList<QTreeWidgetItem *>items = d_tree->findItems("*", Qt::MatchWildcard|Qt::MatchRecursive);
   foreach(QTreeWidgetItem *item, items)
   {
     IQFRuleTreeItem *rti = dynamic_cast<IQFRuleTreeItem* >(item);
     if(rti != NULL)
     {
       if(rti->hasRule() && rti->isNatural())
	 delete rti;
     }
   }
}

