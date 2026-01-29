#include "includes/NaturalWord.h"

NaturalWord::NaturalWord(QString s) : QString(s)
{
  
}

bool NaturalWord::operator>(const NaturalWord& w2) const
{
  return length() > w2.length();
}

bool NaturalWord::operator<(const NaturalWord& w2) const
{
  return length() < w2.length();
}

 bool NaturalWord::operator!= (const NaturalWord &w2) const
 {
   return QString(*this) != QString(w2);
 }
