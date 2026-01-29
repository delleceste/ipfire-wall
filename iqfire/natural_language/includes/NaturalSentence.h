#ifndef NATURAL_SENTENCE_H
#define NATURAL_SENTENCE_H

#include <QString>
#include <QStringList>
#include <QPair>
#include "dictionary.h"

class NaturalSentence : public QString
{
  public:
    NaturalSentence(QString s = QString());
    
    bool containsVerb();
    bool onlyContainsVerb();
    
    /** when a dictionary word is found, mark the portion of sentence 
     * already read.
     */
    void setPortionRead(int start, int end);
    
    /** See if the position was already matched before */
    bool alreadyRead(int position, int length);
    
  protected:
    
  private:
    Dictionary * d_dictionary;
    QList<QPair<int, int> > d_portionsRead;
    
};



#endif 