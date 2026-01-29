#include "includes/MachineSentence.h"
#include <macros.h>
#include <QtDebug>

 MachineSentence:: MachineSentence() : QString()
 {
   
 }

void MachineSentence::mapNaturalToMachine(const NaturalWord& natural, const MachineWord &machine)
{ 
  d_naturalMachineMap.insert(natural, machine); 
}

void MachineSentence::addWord(MachineWord mw, int position)
{ 
  d_words.push_back(mw); 
  d_positionForWord.insert(position, mw);
  pinfo("adding machine word \"%s\" to machine sentence \"%s\"", qstoc(mw), qstoc((*this)));
  clear();
  foreach(int i, d_positionForWord.keys())
    append(d_positionForWord.value(i) + " ");
}

QList<MachineWord> MachineSentence::elements()
{
  return d_positionForWord.values(); 
}










