#ifndef TABLE_INTERPRETER_H
#define TABLE_INTERPRETER_H

#include <ipfire_structs.h>
#include <QStringList>

class TableInterpreter
{
  public:
    TableInterpreter(struct state_info *s) { si = s; }
    TableInterpreter(struct dnat_info *d) { dni = d; }
    TableInterpreter(struct snat_info *s) { sni = s; }
    
    QStringList stateToList();
    QStringList snatToList();
    QStringList dnatToList();
    
  private:
    QString fromAddr(unsigned sa);
    QString fromPort(unsigned short pt, unsigned short proto);
    QString fromDir(short dir);
    QString fromProto(short proto);
    QString fromState(struct state_t st);
    
    QString timeoutDHMS(unsigned int to);
    
    struct state_info *si;
    struct dnat_info *dni;
    struct snat_info *sni;
};

#endif

