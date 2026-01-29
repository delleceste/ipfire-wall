#include <ipfire_structs.h>

class RuleComparator
{
  public:
    RuleComparator(const ipfire_rule *r1, const ipfire_rule *r2);
    bool rulesEqual() { return d_equal; }
    
  private:
    bool d_equal;
};
