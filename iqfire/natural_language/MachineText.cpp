#include "includes/MachineText.h"

MachineText::MachineText()
{
  
}

QList<MachineSentence> MachineText::machineSentences()
{
  return d_machineSentences;
}

void MachineText::addSentence(MachineSentence ms) 
{
  d_machineSentences.push_back(ms); 
  append(QString("%1\n").arg(ms));
}
