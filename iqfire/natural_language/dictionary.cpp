#include "includes/dictionary.h"
#include "includes/macros.h"
#include <QFile>
#include <QTextStream>
#include <QStringList>
#include <QSettings>
#include <QtDebug>

Dictionary *Dictionary::_instance = NULL;

Dictionary *Dictionary::instance()
{
  if(_instance == NULL)
  {
      _instance = new Dictionary();
  }
  return _instance;
}

Dictionary::Dictionary()
{
  init();
}

void Dictionary::init()
{
  QSettings s;
  d_lang = s.value("NATURAL_LANGUAGE", "italiano").toString(); 
  loadRegExpDefs();
  loadNames();
  loadVerbs();
  loadRegExps();
  d_words = d_verbsMap.values() + d_namesMap.values();
  qSort(d_words.begin(), d_words.end(), qGreater<NaturalWord>());
  d_names = d_namesMap.values();
  qSort(d_names.begin(), d_names.end(), qGreater<NaturalWord>());
  d_verbs = d_verbsMap.values();
  qSort( d_verbs.begin(), d_verbs.end(), qGreater<NaturalWord>());
  d_regexps = d_regexpMap.values();
}

void Dictionary::reload()
{
  d_words.clear();
  d_verbsMap.clear();
  d_names.clear();
  d_namesMap.clear();
  d_verbs.clear();
  d_verbsMap.clear();
  d_regexpMap.clear();
  d_regexps.clear();
  init();
}

void Dictionary::loadRegExpDefs()
{
  QSettings s;
  QString regexpsDefsPath = s.value(QString("DICT_PATH"), "dictionary").toString();
  regexpsDefsPath += QString("/%1/regexps.def").arg(d_lang);
  QFile file(regexpsDefsPath);
  
  QString regexp_dictionary;
  QString tmp;
  
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
    pinfo("loading regexp definitions from \"%s\"...", qstoc(regexpsDefsPath));
     QTextStream in(&file);
     QString textWithoutComments;
     while (!in.atEnd()) 
     {
       tmp = in.readLine();
       if(!tmp.startsWith('#')) /* comment or a valid line: at least a::b */
	 textWithoutComments += tmp;
     }
     /* remove \n " */
     textWithoutComments.remove('\n');
     /* split by {ENDREGEXP} */
     QStringList rexpsdefs = textWithoutComments.split("{ENDREGEXP}", QString::SkipEmptyParts);
     
     foreach(QString definition, rexpsdefs)
     {
	QStringList keyDefPair = definition.split("::", QString::SkipEmptyParts);
	 if(keyDefPair.size() == 2)
	 {
	   d_regexpDefsMap.insert(keyDefPair.last(), keyDefPair.first());
	 }
	 else
	   perr("bad line \"%s\" in Regexp definitions file: \"%s\"", qstoc(tmp), qstoc(regexpsDefsPath));
     }
     file.close();
  }
  else
  {
    perr("Error opening regexp map file \"%s\"", qstoc(regexpsDefsPath));
  }
}

void Dictionary::loadNames()
{
  QSettings s;
  QString dictPath = s.value(QString("DICT_PATH"), "dictionary").toString();
  dictPath += QString("/%1/names.txt").arg(d_lang);
  QFile file(dictPath);
  QString dictionary;
  QString tmp;
  
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
     pok("loading names from \"%s\" dictionary...", qstoc(dictPath));
     QTextStream in(&file);
     while (!in.atEnd()) 
     {
       tmp = in.readLine();
       if(!tmp.startsWith('#') && tmp != "\n") /* comment */
	dictionary += tmp;
     }
     /* remove unneeded \n" */
     dictionary.remove('\n');
     /* separate entries */
     QStringList entries = dictionary.split("{ENDRULE}", QString::SkipEmptyParts);
     if(entries.size() > 0)
     {
       foreach(QString s, entries)
       {
	 QStringList namesKey = s.split("::", QString::SkipEmptyParts);
	 if(namesKey.size() < 2)
	 {
	   perr("Unexpected number of separators in string \"%s\", file \"%s\" '::'", qstoc(s), qstoc(dictPath));
	   return;
	 }
	 else
	 {	
	   QStringList valuesForKey = namesKey.first().split(";;", QString::SkipEmptyParts);
	   if(valuesForKey.size() > 0)
	   {
	     foreach(QString s, valuesForKey)
	     {
	       NaturalWord nw(s);
		  d_namesMap.insert(namesKey.last(), nw);
	     }
	   }
	 }
       }
     }
    file.close();
  }
  else
  {
    perr("Failed to open names dictionary file \"%s\"", qstoc(dictPath)); 
  }
}

void Dictionary::loadVerbs()
{
  QSettings s;
  QString dictPath = s.value(QString("DICT_PATH"), "dictionary").toString();
  dictPath += QString("/%1/verbs.txt").arg(d_lang);
  QFile file(dictPath);
  
  QString dictionary;
  QString tmp;
  
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
      pok("loading verbs from \"%s\" dictionary...", qstoc(dictPath));
     QTextStream in(&file);
     while (!in.atEnd()) 
     {
       tmp = in.readLine();
       if(!tmp.startsWith('#') && tmp != "\n") /* comment */
         dictionary += tmp;
     }
     /* remove unneeded \n" */
     dictionary.remove('\n');
     /* separate entries */
     QStringList entries = dictionary.split("{ENDRULE}", QString::SkipEmptyParts);
     if(entries.size() > 0)
     {
       foreach(QString s, entries)
       {
	 QStringList namesKey = s.split("::", QString::SkipEmptyParts);
	 if(namesKey.size() < 2)
	 {
	   perr("Unexpected number of separators in string \"%s\", file \"%s\" '::'", qstoc(s), qstoc(dictPath));
	   return;
	 }
	 else
	 {	
	    QStringList valuesForKey;
	    if(namesKey.first().contains(";;")) /* list of keywords separated by a couple of ;; */
	      valuesForKey = namesKey.first().split(";;", QString::SkipEmptyParts);
	    else /* just one keyword */
	      valuesForKey << namesKey.first();
	    
	   if(valuesForKey.size() > 0)
	   {
	     foreach(QString s, valuesForKey)
	     {
		  NaturalWord nw(s);
		  d_verbsMap.insert(namesKey.at(1), nw);
	     }
	   }
	 }
       }
     }
    file.close();
  }
  else
  {
    perr("Failed to open verbs dictionary file \"%s\"", qstoc(dictPath));
  }
}

void Dictionary::loadRegExps()
{
  QSettings s;
  QString regexpsPath = s.value(QString("DICT_PATH"),  "dictionary").toString();
  regexpsPath += QString("/%1/regexps.txt").arg(d_lang);
  QFile file(regexpsPath);
  int pos;
  QString regexp_dictionary;
  QString tmp;
  
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
    pok("loading regexps from \"%s\" dictionary...", qstoc(regexpsPath));
     QTextStream in(&file);
     while (!in.atEnd()) 
     {
       tmp = in.readLine();
       if(!tmp.startsWith('#') &&  tmp.length() > 16) /* comment or valid line (at least a::b{ENDREGEXP} ) */
         regexp_dictionary += tmp;
     }
     
     /* separate entries */
     QStringList entries = regexp_dictionary.split("{ENDREGEXP}", QString::SkipEmptyParts);
     if(entries.size() > 0)
     {
       foreach(QString s, entries)
       {
	 QStringList regexpKey = s.split("::", QString::SkipEmptyParts);
	 if(regexpKey.size() < 2)
	 {
	   perr("Unexpected number of separators in string \"%s\", file \"%s\" '::'", qstoc(s), qstoc(regexpsPath));
	   return;
	 }
	 else
	 {
	   pos = 0;
		QString regexp = regexpKey.first();
		QString key = regexpKey.last();
		if(regexp.contains(QRegExp("\\$_REGEXP\\{\\w+\\}")))
		{
			QRegExp re("\\$_REGEXP\\{(\\w+)\\}");
			
			pos = re.indexIn(regexp, pos);
			while(pos >= 0)
			{
				QStringList captured = re.capturedTexts();
				pos += (re.matchedLength());
				if(captured.size() > 0)
				{
					if(d_regexpDefsMap.contains(captured.at(1)))
					{
					  QString assocRegexp = d_regexpDefsMap.value(captured.at(1));
					  pinfo("dictionary.cpp: regexp associata alla chiave \e[1;35m%s\e[0m:\n\t\e[0;35m\"%s\"\e[0m\n", qstoc(captured.at(1)), qstoc(assocRegexp));
					  regexp.replace(QRegExp(QString("\\$_REGEXP\\{%1\\}").arg(captured.at(1))), assocRegexp);
					}
					else
					{
					  perr("The regexp definitions do not contain the key \"%s\". Cannot continue.",
						qstoc(captured.at(1)));
					  break;
					}
				}
				pos = re.indexIn(regexp, pos);
			}
		}
		d_regexpMap.insert(key, regexp);
	 }
       }
     }
    file.close(); 
  }
  else
  {
    perr("Failed to open regexps dictionary file \"%s\"", qstoc(regexpsPath)); 
  }
}

