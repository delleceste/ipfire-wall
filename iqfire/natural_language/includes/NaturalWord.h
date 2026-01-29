#ifndef NATURAL_WORD_H
#define NATURAL_WORD_H

#include <QString>

class NaturalWord : public QString
{
  public:
    NaturalWord(QString s = QString());
    bool operator>(const NaturalWord& w2) const;
    bool operator<(const NaturalWord& w2) const;
    bool operator!= (const NaturalWord &w2) const;
};


#endif
