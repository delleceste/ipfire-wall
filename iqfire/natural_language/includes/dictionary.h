#ifndef DICTIONARY_H
#define DICTIONARY_H

#include <QMultiMap>
#include <QString>
#include <QRegExp>
#include "NaturalWord.h"

class Dictionary
{
  public:
    static Dictionary* instance();
   
    
     QMultiMap<QString, NaturalWord> verbsMap() { return d_verbsMap; }
     QMultiMap<QString, NaturalWord> namesMap() { return d_namesMap; }
     QMultiMap<QString, QString> regexpMap() { return d_regexpMap; }
     
     bool isVerb(const QString& s);
     QList<NaturalWord> words() { return d_words; }
     QList<NaturalWord> verbs() { return d_verbs; }
     QList<NaturalWord> names() { return d_names; }
     QList<QString> regularExpressions() { return d_regexps; }
     
     QMap<QString, QString> regexpDefsMap() { return d_regexpDefsMap; }
      
     QString language() { return d_lang; }
     
     void reload();
    
  private:
     Dictionary();
     
    void loadNames();
    void loadVerbs();
    void loadRegExps();
    void loadRegExpDefs();
    
    void init();
    
    QMultiMap<QString, NaturalWord> d_verbsMap, d_namesMap;
    QMultiMap<QString, QString> d_regexpMap;
    QString d_lang;
    
    static Dictionary *_instance;
    /* sorted NaturalWords. NaturalWords are sorted by length, from the 
     * longer to the shortest. The lists are sorted once at the 
     * beginning, just after maps are populated
     */
    QList<NaturalWord> d_words, d_verbs, d_names;
    QList<QString> d_regexps;
    QMap<QString, QString> d_regexpDefsMap;
};


#endif
