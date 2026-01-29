#ifndef MACHINE_TEXT_H
#define MACHINE_TEXT_H

#include <QString>
#include <QList>
#include "MachineSentence.h"

class MachineText : public QString
{
  public:
    MachineText();
    
     QList<MachineSentence> machineSentences();
   
     void addSentence(MachineSentence ms);
    
  private:
    QString d_machineText;
    QList<MachineSentence> d_machineSentences;
};

#endif

