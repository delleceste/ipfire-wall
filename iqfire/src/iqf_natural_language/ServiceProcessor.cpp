#include "ServiceProcessor.h"
#include <macros.h>
#include <NaturalWord.h>
#include <QMap>
#include <QSettings>
#include <QFile>
#include <QTextStream>
#include <QtDebug>

ServiceProcessor::ServiceProcessor() : NaturalCustomProcessor()
{
  setObjectName("iqfire natural language service processor");
}

QString ServiceProcessor::serviceDescription(const NaturalWord& serviceName)
{
  return d_serviceDescriptionMap.value(serviceName);
}

bool ServiceProcessor::gatherLinesFromFile()
{
  QSettings s;
  d_filename = s.value(QString("DICT_PATH"), "dictionary").toString();
  d_filename += QString("/%1/services.txt").arg(d_language);
  QFile file(d_filename);
  QString line;
  
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
     pinfo("loading service expressions to substitute from \"%s\" list...", qstoc(d_filename));
     QTextStream in(&file);
     while (!in.atEnd()) /* gather all lines */
     {
       line = in.readLine();
       if(!line.startsWith('#') && line != "\n") /* comment */
	  d_linesFromFile << line;
     }
     file.close();
     return true;
   }
   else
   {
    perr("failed to open file \"%s\" for reading!", qstoc(d_filename));
    return false;
   }
}

bool ServiceProcessor::fillMaps()
{
  foreach(QString line, d_linesFromFile)
  {
    printf("ServiceProcessor::fillMaps(): processo la linea %s\n", qstoc(line));
    QStringList parts = line.split("::", QString::SkipEmptyParts);
    /* a line contains: list of natural words::substitution pattern::description */
    if(parts.size() == 3)
    {
      QString words = parts.first();
      QString value = parts.at(1);
      QStringList wordList = words.split(";;", QString::SkipEmptyParts);
      /* couple natural word/description */
      d_serviceDescriptionMap.insert(wordList.first(), parts.last());
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
      perr("processing sentences in ServiceProcessor: line malformed: \"%s\".\nFile affected: \"%s\"",
	     qstoc(line), qstoc(d_filename));
      return false;
    }
  }
  return true;
}

bool ServiceProcessor::processSeparateSentences(QList<NaturalSentence>& sentences)
{
  int sentencePosition = 0;
   /* gather lines from services.txt file and fill maps */
  if(!gatherLinesFromFile())
    return false;
  if(!fillMaps())
    return false;
    
   printf("\e[0;4;33mprocessSeparateSentences(d_sentences);\e[0m\n");
  /* reading file ok, lines in d_linesFromFile */ 

    /* ok gathered all lines and mapped. No syntax errors. Proceed with 
    * sorting and substitutions.
    */
    QList<NaturalWord> orderedWords = d_substitutionsMap.keys();
    qSort(orderedWords.begin(), orderedWords.end(), qGreater<NaturalWord>());
    qDebug() << "orderedWords: " << orderedWords;
    qDebug() << "sentences: " << sentences;
    for(int i = 0; i < sentences.size(); i++)
    {
      foreach(NaturalWord w, orderedWords)
      {
	if(sentences[i].contains(QRegExp(w)))
	{
	printf("%s contains %s\n", qstoc(sentences[i]), qstoc(w));
	  /* well, we have work to do */
	  QString substitution = d_substitutionsMap.value(w);
	  if(substitution.contains(QRegExp("\\{.*\\}")))
	  {
	     int pos = 0;
	     int stepcnt = 0;
	     QRegExp re("\\{.*\\}");
	     re.setMinimal(true);
	     NaturalSentence savedSentence = sentences[i];
	     pos = re.indexIn(substitution, pos);
	     while(pos >= 0)
	     {
		QStringList captured = re.capturedTexts();
		pos += (re.matchedLength());
		qDebug() << "captured: " << captured;
		if(captured.size() > 0 && stepcnt == 0) /* now modify first */
		{
		  QString capture = captured.at(0);
		  sentences[i].replace(QRegExp(w), capture.remove("{").remove("}"));
		}
		else if(captured.size() > 0 && stepcnt > 0)
		{
		  NaturalSentence newSentence = savedSentence;
		  QString capture = captured.at(0);
		  newSentence.replace(QRegExp(w), capture.remove("{").remove("}"));
		  sentences.insert(sentencePosition + stepcnt, newSentence);
		}
		pos = re.indexIn(substitution, pos);  
		stepcnt++;
	      }
	  }
	  else
	  {
	  
	  }
	}
	else
	  printf("%s DONT contains %s\n", qstoc(sentences[i]), qstoc(w));
      }
      sentencePosition++;
    }
    return true;
}

