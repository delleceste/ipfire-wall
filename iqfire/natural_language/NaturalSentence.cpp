#include "includes/NaturalSentence.h"
#include <QList>

NaturalSentence::NaturalSentence(QString s ) : QString(s)
{
  d_dictionary = Dictionary::instance();
}

bool NaturalSentence::containsVerb()
{
  QList<NaturalWord> verbs = d_dictionary->verbs();
  foreach(NaturalWord s, verbs)
  {
    if(contains(s, Qt::CaseInsensitive))
      return true;
  }
  return false;
}

bool NaturalSentence::onlyContainsVerb()
{
  QList<NaturalWord> verbs = d_dictionary->verbs();
  QString copy = *this;
  foreach(NaturalWord s, verbs)
  {
    /* look for the verb and some other characters around */
    QRegExp re("[\\(\\).,;:\\s-]*" + s + "[\\(\\).,;:\\s-]*");
    if(copy.remove(re) == QString())
      return true;
  }
  return false;
}

void NaturalSentence::setPortionRead(int start, int end)
{
  QPair<int, int> portion;
  portion.first = start;
  portion.second = end;
  d_portionsRead << portion;
}
 
 bool NaturalSentence::alreadyRead(int position, int wordLength)
 { 
   int i;
   if(d_portionsRead.size() == 0)
     return false;
   for(i = 0; i < d_portionsRead.size(); i++)
   {
     /* example: NaturalWords from dictionary { the word, word is complicated} 
      * sentence:  "the word is complicated" 
      * The dictionary is ordered by length of elements: first the longer elements: {word is complicated, the word }
      * and so `word is complicated' is found first.
      * Also `the word' would then match, if we did not check the intersection of the second word with the first.
      * The question is: position is not enough: we must also check against position + word length (minus 1 !)
      */
     if(!( (position + wordLength - 1  < d_portionsRead.at(i).first) || (position > d_portionsRead.at(i).second)))
      return true;
   }
   return false;
 }




