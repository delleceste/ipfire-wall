#include "ruleHashCalculator.h"
#include <ipfire_structs.h>

RuleHashCalculator::RuleHashCalculator(const ipfire_rule *r)
{
  QString hash;
  hash = QString("%1%2").arg(r->devpar.in_devname).arg(r->devpar.out_devname);
  for(int i = 0; i < MAXMULTILEN && r->ip.ipsrc[i] != 0; i++)
    hash += QString("%1").arg(r->ip.ipsrc[i]);
  for(int i = 0; i < MAXMULTILEN && r->ip.ipdst[i] != 0; i++)
    hash += QString("%1").arg(r->ip.ipdst[i]);
  for(int i = 0; i < MAXMULTILEN && r->tp.sport[i] != 0; i++)
    hash += QString("%1").arg(r->tp.sport[i]);
  for(int i = 0; i < MAXMULTILEN && r->tp.dport[i] != 0; i++)
    hash += QString("%1").arg(r->tp.dport[i]);
  hash += QString("%1%2%3%4%5%6%7").arg(r->ip.protocol).arg(r->tp.syn).arg(r->tp.fin).arg(r->tp.urg).
    arg(r->tp.psh).arg(r->tp.ack).arg(r->tp.rst);
  hash += QString("%1%2%3%4").arg(r->parmean.samean).arg(r->parmean.damean).arg(r->parmean.spmean).arg(r->parmean.dpmean);
  hash += QString("%1%2%3%4").arg(r->direction).arg(r->nat).arg(r->snat).arg(r->state);
  hash += QString("%1%2").arg(r->newaddr).arg(r->newport);
  hash += QString("%1%2%3%4%5").arg(r->nflags.policy).arg(r->nflags.src_addr).arg(r->nflags.dst_addr).arg(r->nflags.src_port).
    arg(r->nflags.dst_port);
    
  d_hash = hash;
}
