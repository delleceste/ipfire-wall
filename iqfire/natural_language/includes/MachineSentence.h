#ifndef MACHINE_SENTENCE_H
#define MACHINE_SENTENCE_H

#include <QStringList>
#include <QMap>

#include "NaturalWord.h"
#include "MachineWord.h"
#include "NaturalSentence.h"

class MachineSentence : public QString
{
  public:
    MachineSentence();
    
    /** extract the machine word from the machine-natural map */
    QString machineWordForNatural(const NaturalWord& natural) { return d_naturalMachineMap.value(natural); }
    
    /** extract the natural word(s) corresponding to the machine one */
    QString naturalWordForMachine(const MachineWord &machine) { return d_naturalMachineMap.key(machine); }
    
    NaturalSentence associatedNaturalSentence() { return d_assocNaturalSentence; }
    void setAssociatedNaturalSentence(NaturalSentence &ns) { d_assocNaturalSentence = ns; }
    
    /** insert into the map */
    void mapNaturalToMachine(const NaturalWord& natural, const MachineWord &machine);
    
    void addWord(MachineWord mw, int position);
    
    /** returns a list of MachineWords. This is the list of the elements of the sentence, with 
     * each machine word separate.
     */
    QList<MachineWord> elements();
    
  protected:
    
  private:
    QMap<NaturalWord, MachineWord> d_naturalMachineMap;
    QMap<int, MachineWord> d_positionForWord;
    QList<MachineWord> d_words; 
    NaturalSentence d_assocNaturalSentence;
    
};





#endif

