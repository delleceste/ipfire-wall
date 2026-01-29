#include <QFile>
#include <QTextStream>
#include <QString>
#include <QList>
#include <QSettings>
#include <QApplication>
#include <QDateTime>

#include "includes/NaturalText.h"
#include <macros.h>
#include "includes/NaturalCustomProcessor.h"
#include "includes/naturalMessageEvents.h"

NaturalText::NaturalText(QString text, QObject *parent) : QObject(parent)
{
  errmsg = "No error";
  d_error = false;
  d_naturalCustomProc = NULL;
  d_text = text.toLower();
  dictionary = Dictionary::instance();
  d_lang = dictionary->language();
}

void NaturalText::startProcessing()
{
  message(QString("natural text processing started on <strong>%1</strong>").arg(QDateTime::currentDateTime().toString()));
  /* if a custom processor was set, then call preProcess first of all */
  if(d_naturalCustomProc)
    d_naturalCustomProc->preProcess(d_text); /* d_text by reference */
    
//     /* to help cleanUnwantedText.. 
//     * The user might start its list with:
//     * 1. open the port 22 <- prepending `\n` will remove also `1.'
//     * 2. close the port 25
//     */
//   d_text.prepend("\n");
  
  preSubstitutions();
  
  clearUnwantedText();
  
  d_sentences = separateSentences();
  
  if(d_naturalCustomProc)
  {
    pok("invoking natural sentences' custom processor \"%s\"", qstoc(d_naturalCustomProc->objectName()));
    message(QString("NaturalText: invoking natural sentences' custom processor \"%1\"").arg(d_naturalCustomProc->objectName()));
    d_naturalCustomProc->processSeparateSentences(d_sentences);
  }
  
  if(d_error)
  {
    perr("An error occurred in NaturalText-::startProcessing(): %s", qstoc(errmsg));
    error(QString("NaturalText: an error occurred in NaturalText `startProcessing()': %1").arg(errmsg));
    emit error("NaturalText: error separating sentences", errmsg);
  }
}

QList<NaturalSentence> NaturalText::separateSentences()
{
  errmsg = "No error";
  d_error = false;
  QList<NaturalSentence> ret;
  QList<int> verbIndexes;
  int verbPos, from, matchedLen;
  
  /* assume that for each verb there is a sentence */
  QList<NaturalWord> verbs = dictionary->verbs();
  
  if(verbs.size() > 0)
  {
    foreach(QString s, verbs)
    {
      from = 0;
      verbPos = 0; /* initialize */
      /* replace spaces with space regexp */
      s.replace(QRegExp("\\s+"), "\\s+");
      s = "\\b" + s + "\\b";
      QRegExp verbRe(s);
      verbRe.setCaseSensitivity(Qt::CaseInsensitive);
      verbPos = verbRe.indexIn(d_text, from);
      while(verbPos >= 0)
      {
	matchedLen = verbRe.matchedLength();
	pok("verb pos %d per %s in \"%s\"", verbPos, qstoc(s), qstoc(d_text));
	if(verbPos >= 0 && portionNotRead(verbPos, matchedLen))
	{
	  d_verbsPositionMap.insert(verbPos, s);
	  setPortionRead(verbPos, matchedLen);
	}
	else if(!portionNotRead(verbPos, matchedLen))
	  pinfo("portion already read: %d-%d for %s", verbPos, verbPos + matchedLen, qstoc(s));
	from = verbPos + matchedLen;
	verbPos = verbRe.indexIn(d_text, from);
      }
    }
    verbIndexes = d_verbsPositionMap.keys();
    if(verbIndexes.size() > 0)
    {
      qDebug() << "\nverb indexes PRIMA Di push fornt e back: " << verbIndexes;
      if(verbIndexes.first() != 0)
	verbIndexes.push_front(0);
      /* the end of the text */
      //   if(verbIndexes.last() != d_text.length() - d_verbsPositionMap[verbIndexes.last()].length())
	verbIndexes.push_back(d_text.length());

      qDebug() << "\nverb indexes: " << verbIndexes;
      int j;
      for(int i = 0; i < verbIndexes.size() - 1; i++)
      {
	  NaturalSentence ns;
	for(j = verbIndexes[i]; j < verbIndexes[i + 1]; j++)
	    ns += d_text[j];
	if(ns.onlyContainsVerb())
	{
	  errmsg = "NaturalText: verbs at the beginning of the sentence please: sentence: " + ns;
	  d_error = true;
	  error(errmsg);
	}
	else if(!ns.containsVerb())
	  pwarn("Missing verb in the sentence: \"%s\"", qstoc(ns));
	else if(ns.size() && ns.containsVerb())
	  ret << ns;
	else
	  warning(QString("0 size sentence between indexes %1 and %2").arg(verbIndexes[i]).arg(verbIndexes[i + 1]));
      }
    } /* if verbIndexes.size() > 0 */
  } /* if(verbs.size() > 0) */
  
  return ret;
}

void NaturalText::setPortionRead(int start, int len)
{
  QPair<int, int> portion;
  portion.first = start;
  portion.second = start + len - 1;
  d_portionsRead.push_back(portion);
}

bool NaturalText::portionNotRead(int start, int len)
{
  int i;
  int end = start + len - 1;
  QPair<int, int> portion;
  for(i = 0; i < d_portionsRead.size(); i++)
  {
    portion = d_portionsRead.at(i);
    if(! ((end < portion.first) || (start > portion.second)))
      return false; /* portion already read */
  }
  return true; /* portion not read */
}

void NaturalText::clearUnwantedText()
{
  QSettings s;
  QStringList regexps;
  QString regexpPath = s.value(QString("DICT_PATH"), QString("dictionary")).toString();
  regexpPath += QString("/%1/unwanted_regexp.txt").arg(d_lang);
  QFile file(regexpPath);
  
  QString regexp;
  
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
     message(QString("loading expressions to remove from \"%1\" list...").arg(regexpPath));
     QTextStream in(&file);
     while (!in.atEnd()) 
     {
       regexp = in.readLine();
       if(!regexp.startsWith('#') && regexp != "\n") /* comment */
	  regexps << regexp;
     }
     int cnt = 0;
     foreach(QString re, regexps)
     {
       cnt++;
       printf("prima di pre subst: %s\n", qstoc(d_text));
       re = QString("\\b%1\\b").arg(re);
       re.replace(QRegExp("\\s+"), "\\s+");
       pok("sostituisco (pre substitute) regexp: \"%s\"\n", qstoc(re));
       QRegExp rexp(re);
       rexp.setCaseSensitivity(Qt::CaseInsensitive);
       d_text = d_text.remove(rexp);
       printf("dopo di pre subst: %s\n", qstoc(d_text));
     }
  }
  else
  {
    perr("Error loading regular expressions for text removal. File: \"%s\"", qstoc(regexpPath));
    error(QString("Error loading regular expressions for text removal. File: \"%1\"").arg(regexpPath));
  }
}

void NaturalText::preSubstitutions()
{
  QSettings s;
  int lineno = 0;
  QString preSostPath = s.value(QString("DICT_PATH"), "dictionary").toString();
  preSostPath += QString("/%1/pre_sostitutions.txt").arg(d_lang);
  QFile file(preSostPath);
  QString line;
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
     message(QString("loading expressions to remove from \"%1\" list...").arg(preSostPath));
     QTextStream in(&file);
     while (!in.atEnd()) 
     {
       lineno++;
       line = in.readLine();
       if(!line.startsWith('#') && line.length() > 4) /* comment */
       {
	  QStringList parts = line.split("::", QString::SkipEmptyParts);
	  if(parts.size() == 2)
	  {
	    QString words = parts.first();
	    QString value = parts.last();
	    QStringList wordList = words.split(";;", QString::SkipEmptyParts);
	    /* populate the map */
	    foreach(QString s, wordList)
	    {
	      QString sregexp = QString("\\b%1\\b").arg(s);
	      sregexp.replace(QRegExp("\\s+"), "\\s+");
	      d_substitutionsMap.insert(NaturalWord(sregexp), NaturalWord(value));
	    }
	  }
	  else
	  {
	    perr("preSubstitutions in NaturalText: line %d malformed: \"%s\".\nFile affected: \"%s\"",
		  lineno, qstoc(line), qstoc(preSostPath));
	    error(QString("preSubstitutions in NaturalText: line %1 malformed: \"%2\".\nFile affected: \"%3\"").arg(lineno).arg(line).arg(preSostPath));
	    d_error = true;
	  }
       } 
     }
     QList<NaturalWord> orderedWords = d_substitutionsMap.keys();
     qSort(orderedWords.begin(), orderedWords.end(), qGreater<NaturalWord>());
     foreach(NaturalWord w, orderedWords)
     {
       if(d_text.contains(QRegExp(w)))
       {
	 d_text.replace(QRegExp(w), d_substitutionsMap.value(w));
	 pinfo("substituting \"%s\" with \"%s\"", qstoc(w), qstoc(d_substitutionsMap.value(w)));
       }
     }
  file.close();
  }
}

void NaturalText::setCustomProcessor(NaturalCustomProcessor *ncp)
{
  if(ncp != NULL)
  {
    d_naturalCustomProc = ncp; 
    /* set our language, of course */
    d_naturalCustomProc->setLanguage(d_lang);
  }
}

/* The following emits a warning event to the parent, if parent is set */
void NaturalText::warning(QString message)
{
  if(parent())
  {
    WarningMessageEvent *wme = new WarningMessageEvent(message);
    qApp->postEvent(parent(), wme);
  }
}
  
/* The following emits an error event to the parent, if parent is set */
void NaturalText::error(QString err)
{
  if(parent())
  {
    ErrorMessageEvent *eme = new ErrorMessageEvent(err);
    qApp->postEvent(parent(), eme);
  }
}

/* The following emits a message event to the parent, if parent is set */
void NaturalText::message(QString msg)
{
  if(parent())
  {
    OkMessageEvent *okme = new OkMessageEvent(msg);
    qApp->postEvent(parent(), okme);
  }
}

