#ifndef NATURAL_RULE_REMOVER_H
#define NATUARL_RULE_REMOVER_H

#include <iqfruletree.h>
#include <iqfruletree_item.h>

class NaturalRuleItemRemover 
{
  public:
    NaturalRuleItemRemover(IQFRuleTree *tree);
    void removeNaturalRules();
    
  private:
    IQFRuleTree *d_tree;
};

#endif
