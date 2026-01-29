#ifndef RULE_HASH_CALCULATOR
#define RULE_HASH_CALCULATOR

#include <ipfire_structs.h>
#include <QString>

class RuleHashCalculator
{
  public:
    RuleHashCalculator(const ipfire_rule *r);
    
    QString hash() { return d_hash; }
    
  private:
    QString d_hash;
  
};

#endif
