#ifndef NATURAL_CUSTOM_PROCESSOR_H
#define NATURAL_CUSTOM_PROCESSOR_H

#include <QString>
#include "NaturalSentence.h"

/** This class must be reimplemented if you want to modify the natural 
 * text before any processing is made, or just after it is split into
 * sentences.
 * In particular, you must reimplement preProcess() and processSeparateSentences()
 * methods.
 */

class NaturalCustomProcessor
{
  public:
    NaturalCustomProcessor() {};
    
    void setLanguage(QString lang) { d_language = lang; }
    
    /** this is called before any operation is done on the 
     *  natural text by the text processing method: startProcessing()
     *
     *  @param txt the NaturalText constituting the NaturalText object. Passed by reference.
     */
    virtual bool preProcess(QString &) = 0;
    
    /** This is called just after the natural text has been split into sentences.
     *  @param sentences a list of NaturalSentence(s) passed by reference, so modifiable by
     *  the implementer.
     */
    virtual bool processSeparateSentences(QList<NaturalSentence>& ) = 0;
    
    /** the name of this Service processor (a kind of description, optional ) */
    QString objectName() { return d_objectName; }
    
    /** sets the object name of the custom processor */
    void setObjectName(QString s) { d_objectName = s; }
  
    protected:
      QString d_language, d_objectName;
    
};

#endif
