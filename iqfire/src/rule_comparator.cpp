#include "rule_comparator.h"
#include <string.h>

RuleComparator::RuleComparator(const ipfire_rule *r1, const ipfire_rule *r2)
{
  /* see ipfire_structs.h: ipfire_rule */
  int len = sizeof(deviceparams) + sizeof(ipparams) +
                sizeof(transparams) + sizeof(icmp_params) +
                sizeof(netflags) + sizeof(meanings) +
                sizeof(u8) + sizeof(u32) + sizeof(u16);
		
  if(memcmp(r1, r2, len) == 0)
    d_equal = true;
  else
    d_equal = false;
}