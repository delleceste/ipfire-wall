#include "includes/grammar.h"
#include "includes/dictionary.h"
#include "includes/macros.h"

#include <QStringList>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QSettings>
#include <QtDebug>

Grammar *Grammar::_instance = NULL;

Rule::Rule()
{
  d_word = d_interpretation = d_suggestion = d_interpretation = QString();
  d_error = false;
}

Rule::Rule(QString word, QString ruleForWord, QString translation, QString suggestion, const QString& syntaxFile)
{
  d_error = false;
  d_word = word;
  d_syntaxFile = syntaxFile;
  if(!patternSubstitution(d_word))
    d_error = true;
    
  ruleForWord.replace(QRegExp("\\s+"), "\\s+");
  
  if(patternSubstitution(ruleForWord))
  {
    d_rule.setPattern(ruleForWord);
    d_rule.setCaseSensitivity(Qt::CaseInsensitive);
  }
  else 
    d_error = true;
  d_interpretation = translation;
  d_suggestion = suggestion;
  
  if(d_error)
    perr("Error building Rule for word \"%s\": pattern substitution error (missing\n"
      "pattern in the dictionary).", qstoc(word));
}

bool Rule::patternSubstitution(QString& s)
{
  int pos = 0;
  QString copy = s;
  if(copy.contains(QRegExp("\\$_REGEXP\\{\\w+\\}")))
  {
    Dictionary* dictionary = Dictionary::instance();
    QRegExp re("\\$_REGEXP\\{(\\w+)\\}");
    pos = re.indexIn(copy, pos);
    while(pos >= 0)
    {
      QStringList captured = re.capturedTexts();
      pos += re.matchedLength();
      if(captured.size() > 0)
      {
	if(dictionary->regexpMap().contains(captured.at(1)))
	{
	  QString assocRegexp = dictionary->regexpMap().value(captured.at(1));
	  pinfo("regexp [regola] associata alla chiave \e[1;35m%s\e[0m:\n\t\e[0;35m\"%s\"\e[0m\n",
	      qstoc(captured.at(1)), qstoc(assocRegexp));
	  /* substitution in QString s passed by reference */
	  s.replace(QRegExp(QString("\\$_REGEXP\\{%1\\}").arg(captured.at(1))), assocRegexp);
	  d_error = false;
	}
	else
	{
	  perr("Pattern substitution error for word \"%s\". No key named \"%s\" in dictionary", 
		qstoc(copy), qstoc(captured.at(1)));
	  d_error = true;
	  return false;
	}
      }
      pos = re.indexIn(copy, pos);
    }
   
  }
  else
    pinfo("string %s does not contain $_REGEXP{} patterns", qstoc(copy));
  return true;
}

/* For each match of the rule keyword into the NaturalSentence ns
 * a new MachineWord is created with the corresponding interpretation.
 * For each MachineWord added to the returned QList, a QPair<int, int>
 * is added to a list indicating the map of the MachineWord into the
 * NaturalSentence. Users of applyToSentence will have to peek from the
 * Rule object the QPairs indicating the portions of the NaturalSentence
 * ns read by this method.
 */
QList<MachineWord> Rule::applyToSentence(NaturalSentence &ns, int startFrom)
{
  QList<MachineWord> mwords;
  d_lastError = "No error";
  d_error = false;
  int length, startPos = 0;
  startPos = d_rule.indexIn(ns, startFrom);
  if(startPos < 0)
  {
      pwarn("The natural sentence \"%s\" is not syntactically correct:", qstoc(ns));
      pwarn("Rule: %s\n", qstoc(suggestion()));
      d_lastError = QString(suggestion());
      d_error = true;
  }
  while(startPos >= 0)
  {
    QStringList list = d_rule.capturedTexts();
    length = d_rule.matchedLength();
    MachineWord mw(d_interpretation);
    
    for(int i = 1; i < list.size(); i++)
    {
	mw.replace(QString("$%1").arg(i), list.at(i));
	pinfo("Interpretation \"%s\" for argument %d (delimiters %d/%d - len %d)\n", qstoc(mw), i, startPos, startPos + length -1, length);
    }
    mwords << mw;
    QPair<int, int> delimiters;
    delimiters.first = startPos;
    delimiters.second = startPos + length -1;
    d_portionsRead << delimiters;

    startPos += length;
    /* update start pos, looking for another word */
    startPos = d_rule.indexIn(ns, startPos);
  } /* while */
  
  return mwords;
}

Grammar* Grammar::instance()
{
  if(_instance == NULL)
    _instance = new Grammar();
  return _instance;
}

void Grammar::reload()
{
   d_wordList.clear();
   init();
}

Grammar::Grammar()
{
 init();
}

bool Grammar::greaterThan(const Rule& r1, const Rule& r2)
 {
    return r1.rule().pattern().length() > r2.rule().pattern().length();
 }

QList<Rule> Grammar::rulesForNaturalWord(NaturalWord w)
{
  /* must order the list of rules starting with those having longer regexps */
  QList<Rule> rules = d_rulesMap.values(w);
//   (Grammar::*)(const Rule&, const Rule&) lt = this->lessThan;
  qSort(rules.begin(), rules.end(), Grammar::greaterThan);
  return rules;
}

void Grammar::init()
{
  QSettings s;
  QStringList dirfilters;
  QStringList allFiles, syntaxFiles;
  QList<NaturalWord> naturalWordListForFile;
  
  /* we organize syntax porcessing following a hierarchy on the syntaxN.txt files on the dictionary folder.
   * i.e. if in the dictionary folder there are three syntax files, syntax.txt, syntax3.txt and syntax5.txt,
   * then the rules are taken from the three files, in sorting order.
   */
  d_lang = s.value("NATURAL_LANGUAGE", "italiano").toString();
  QString dictPath = s.value(QString("DICT_PATH"), QString("dictionary")).toString();
  dictPath += QString("/%1").arg(d_lang);
  QDir dictDir(dictPath);
  dirfilters << "*.txt"; /* look for txt files */
  allFiles = dictDir.entryList(dirfilters);
  foreach(QString file, allFiles)
  {
    if(file.contains(QRegExp("\\bsyntax(?:\\d){0,2}\\.txt\\b")))
      syntaxFiles << file;
  }
  /* sort the syntax files from syntax1.txt to syntaxN.txt.. */
  qSort(syntaxFiles.begin(), syntaxFiles.end());
  d_wordList.clear();
  foreach(QString syntaxFile, syntaxFiles)
  {
    naturalWordListForFile = loadRules(syntaxFile);
    qSort(naturalWordListForFile.begin(), naturalWordListForFile.end(), qGreater<NaturalWord>());
    d_wordList += naturalWordListForFile;
  }
//   QList<QString> list = d_rulesMap.uniqueKeys();
//   foreach(QString s, list)
//     d_wordList << NaturalWord(s);
//   qSort(d_wordList.begin(), d_wordList.end(), qGreater<NaturalWord>());
}

QList<NaturalWord> Grammar::loadRules(const QString &syntaxFile)
{
  QSettings s;
  QList<NaturalWord>  keywords;
  d_lang = s.value("NATURAL_LANGUAGE", "italiano").toString();
  QString grammarPath = s.value(QString("DICT_PATH"), QString("dictionary")).toString();
  grammarPath += QString("/%1/%2").arg(d_lang).arg(syntaxFile);
  QFile file(grammarPath);
  QStringList ruleList;
  QString line;
  QString completeText;
  d_lastError = "No error";
  d_error = false;
  int ruleno = 0;
  
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
      pok("loading grammar syntax rules from \"%s\"...", qstoc(grammarPath));
     QTextStream in(&file);
     while (!in.atEnd()) 
     {
       line = in.readLine();
       if(!line.startsWith('#') && line.length() > 3) /* comment */
       {
	 completeText += line;
	 if(!line.endsWith("{ENDRULE}"))
	   perr("line \"%s\" is not a comment and does not end with the keyword \"{ENDRULE}\"", qstoc(line));
       }
     }
     file.close();
     
     /* remove newlines from the text */
     completeText.remove("\n"); /* the configuration file can contain arbitrary \n */
     /* the rule separator is the keyword {ENDRULE} */
     ruleList = completeText.split("{ENDRULE}", QString::SkipEmptyParts);
    
     foreach (QString rule, ruleList)
     {
	 ruleno++;
	 QStringList parts = rule.split("::", QString::SkipEmptyParts);
	 QString help;
	 if(parts.size() >= 3)
	 {
	   if(parts.size() >= 4)
	     help = parts.at(3);
	   else
	     help = "Help unavailable.";
	   Rule r(parts.at(0), parts.at(1), parts.at(2), help, syntaxFile);
	   if(!r.error())
	   {
	      /* take r->word() because Rule constructor performs pattern
	       * substitution of $_REGEXP patterns also in key words
	       */
	      NaturalWord nw(r.word());
	      if(d_rulesMap.contains(nw))
	      {
		d_error = true;
		d_lastError = QString("Grammar::loadRules(): duplicated keyword \"%1\". Syntax file \"%2\". This might cause interpretation errors").
		  arg(nw).arg(syntaxFile);
		perr("Grammar::loadRules(): duplicated keyword \"%s\" syntax file \"%s\"", qstoc(nw), qstoc(syntaxFile));
	      }
	      d_rulesMap.insert(nw, r);
	      keywords << nw;
	   }
	   else
	   {
	      perr("Error in rule  \"%s\": cannot add it!", qstoc(rule));
	      d_error = true;
	      d_lastError = "Error building a rule. Not added into the list: " +
		r.lastError();
	   }
	 }
	 else
	 {
	   d_error = true;
	   d_lastError = QString("Error in file \"%1\", line %2: malformed rule: \"%3\"\n"
	    "expected three \"::\" separators").arg(grammarPath).arg(ruleno).arg(rule);
	   perr("Error in file \"%s\", rule %d: malformed rule: \"%s\"\n"
	    "expected three \"::\" separators", qstoc(grammarPath), ruleno, qstoc(rule));
	 }
	 
       }
  }
  else
    perr("Error opening file \"%s\" for reading.", qstoc(grammarPath));
  
  return keywords;
}

QList<NaturalWord> Grammar::wordsWithRule() 
{
  return d_wordList;
}

QStringList Grammar::suggestionsForRule(QString rule_keyword)
{
  QStringList suggestions;
  QList<Rule> rules = rulesForNaturalWord(rule_keyword);
  foreach(Rule r, rules)
    suggestions << r.suggestion();
  return suggestions;
}

QString Grammar::htmlFormattedSuggestionsForRule(QString rule_kw)
{
  QString suggestion;
  QStringList suggestions = suggestionsForRule(rule_kw);
  foreach(QString s, suggestions)
    suggestion += QString("<li>%1</li>\n").arg(s);
  return suggestion;
}



