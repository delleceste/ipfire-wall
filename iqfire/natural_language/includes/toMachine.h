#ifndef NATURAL_TO_MACHINE_CONVERTER
#define NATURAL_TO_MACHINE_CONVERTER

#include "NaturalSentence.h"
#include "NaturalText.h"
#include "MachineText.h"
#include "dictionary.h"

/** This class is responsible of the conversion of a NaturalText 
 *  to a MachineText. Constructed with a NaturalText as first 
 *  argument, and a QObject as second argument, it is enough to 
 *  call convertToMachine to transform the NaturalText into the
 *  machine text.
 *  This is a QObject to communicate with the user through signals.
 *  It is mostly useful to signal syntax errors in the NaturalText
 *  or elsewhere.
 */
class NaturalTextToMachine : public QObject
{
Q_OBJECT
  public:
    NaturalTextToMachine(NaturalText *nt, QObject *parent, bool strictCheck);
    
    MachineText *machineText() { return d_machineText; }
    NaturalText *naturalText() { return d_naturalText; }
    
    bool convertToMachine();
    bool conversionFailed() { return d_conversionFailed; }
    QString lastErrorMessage() { return d_errmsg; }
    
    void setStrictCheck(bool strict) { d_strictCheck = strict; }
    bool strictCheck() { return d_strictCheck; }
    
  signals:
    void progress(int, int, const QString&);
  
  protected:
    
  private:
    
    NaturalText *d_naturalText;
    MachineText *d_machineText;
    Dictionary* d_dictionary;
    bool d_conversionFailed;
    QString d_errmsg;
    bool d_strictCheck;
};

#endif