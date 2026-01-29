#ifndef NATURAL_GRAMMAR_H
#define NATURAL_GRAMMAR_H

#include <QRegExp>
#include <QString>
#include <QPair>

#include "NaturalSentence.h"
#include "NaturalWord.h"
#include "MachineWord.h"

class Rule
{
  public:
    Rule(QString word, QString ruleForWord, QString translation, QString suggestion, const QString& syntaxFileName);
    Rule();
    
    QString word() { return d_word; }
    QRegExp rule() const { return d_rule; }
    QString interpretation() { return d_interpretation; }
    QString suggestion() { return d_suggestion; }
    
    QList<MachineWord> applyToSentence(NaturalSentence &ns, int startPos = 0);
    QList<QPair<int, int> > portionsOfNaturalSentenceRead() { return d_portionsRead; }
    
    QString lastError() { return d_lastError; }
    bool error() { return d_error; }
    
    /** \brief the syntax file name the rule was taken from
     * 
     * @return the syntax file name that contains the rule
     */
    QString syntaxFile() { return d_syntaxFile; }
    
   
  private:
    QString d_word, d_interpretation, d_suggestion;
    QRegExp d_rule;
    QString d_lastError;
    bool d_error;
    QList<QPair<int, int> > d_portionsRead;
    QString d_syntaxFile;
    
    /* Takes a string s, if s contains "$_REGEXP", then looks up into
     * the dictionary to substitute the pattern in place of "$_REGEXP"
     */
    bool patternSubstitution(QString &s);
};

class Grammar
{
  public:
    static Grammar* instance();
    
    bool error() { return d_error; }
    QString lastError() { return d_lastError; }
    
    Rule ruleForNaturalWord(NaturalWord nw) { return d_rulesMap.value(nw); }
    bool wordHasRule(QString word) { return d_rulesMap.contains(word); }
    
    /** @return the list of Rules ordered with first the rules having
     * longer regular expressions in the d_rule field. This is made possible
     * by the greaterThan method used to compare entries in the list of 
     * rules. Who wants to utilize the returned list, probably desires to 
     * receive them ordered from the one containing the more complex regexp
     * to the less complex. In this way, comparison with the natural sentence
     * is made starting with the more complex search patterns.
     * NOTE: to evaluate if this is really desired or useful.
     *
     * Example: given the natural sentence: "allow from A to B"
     * and rule1: QRegExp("from [A-Z]"), rule2: QRegExp("from [A-Z] to [A-Z]")
     * if not ordered, we would try both and then decide which best matches.
     * If ordered, normally the more complex (rule2) fits first and best.
     */
    QList<Rule> rulesForNaturalWord(NaturalWord w);
    
    QStringList suggestionsForRule(QString rule_keyword);
    QString htmlFormattedSuggestionsForRule(QString rule_kw);
    
    QList<NaturalWord> wordsWithRule();
    void reload();
    
  private:  
    Grammar();
    /* returns the list of keywords recognized in the syntaxFile in input */
    QList<NaturalWord>  loadRules(const QString &syntaxFile);
    void init();
    
    QString d_lang;
    
    /* used by rulesForNaturalWord(), represents the operator 
     * used by qSort inside rulesForNaturalWord().
     * Given two rules, returns true if r1 has an associated regexp
     * longer than the r2's.
     */
   static bool greaterThan(const Rule& r1, const Rule& r2);
  
   static Grammar *_instance;
   bool d_error;
   QString d_lastError;
   QMultiMap<QString, Rule> d_rulesMap;
   QList<NaturalWord> d_wordList;
};

#endif
