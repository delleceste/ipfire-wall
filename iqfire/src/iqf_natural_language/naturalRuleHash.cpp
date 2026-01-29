#include "naturalRuleHash.h"
#include "ruleHashCalculator.h"
#include <macros.h>
#include <QDir>
#include <iqflog.h>
#include <QFile>
#include <QTextStream>

NaturalRuleHash* NaturalRuleHash::_instance = NULL;

NaturalRuleHash*NaturalRuleHash::naturalRuleHashMap()
{
  if(_instance == NULL)
  {
    _instance = new NaturalRuleHash();
  }
  return _instance;
}

NaturalRuleHash::NaturalRuleHash()
{	
  QString filename = QDir::home().absolutePath() + "/.IPFIRE/natural_rules.hash";
  QFile file;
  file.setFileName(filename);
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
    QTextStream in(&file);
    QString line = in.readLine();
    while (!line.isNull())
    {
         QStringList elems = line.split("::");
	 if(elems.size() == 2)
	   d_map.insert(elems.at(0), elems.at(1));
         line = in.readLine();
    }
    file.close();
  }
  else
    Log::log()->appendFailed(QString("NaturalRuleHash::NaturalRuleHash(): failed to open file \"%1\" for writing").arg(filename));
}

QString NaturalRuleHash::naturalSentenceForRule(const ipfire_rule *r)
{
  RuleHashCalculator rhc(r);
  QString hash = rhc.hash();
  if(r->nat && d_natMap.contains(hash))
    return d_natMap.value(hash);
  else if(!r->nat && d_map.contains(hash))
    return d_map.value(hash);
  else
    return QString("Sentence not found for key hash %1").arg(hash);
}

NaturalRuleHash::~NaturalRuleHash()
{
  
}	
	
void NaturalRuleHash::addNaturalRule(const ipfire_rule *r, const QString &naturalSentence)
{
  RuleHashCalculator rhc(r);
  QString hash = rhc.hash();
  qDebug() << "adding naturla sentence " << naturalSentence << "to rule with nat " << r->nat;
  if(r->nat)
    d_natMap.insert(hash, naturalSentence);
  else
    d_map.insert(hash, naturalSentence);
}

void NaturalRuleHash::save()
{
  QString filename = QDir::home().absolutePath() + "/.IPFIRE/natural_rules.hash";
  QFile file;
  file.setFileName(filename);
  if(file.open(QIODevice::WriteOnly | QIODevice::Text))
  {
    QTextStream out(&file);
    QMapIterator<QString, QString> i(d_map);
    qDebug() << "saving hashes " << d_map.size();
    while(i.hasNext())
    {
      i.next();
      qDebug() << "salvo la riga" <<  i.key() <<  "::" << i.value() << "\n";
      out << i.key() << "::" << i.value() << "\n";
    }
    QMapIterator<QString, QString> inat(d_natMap);
    while(inat.hasNext())
    {
      inat.next();
      qDebug() << "salvo la riga nat" <<  inat.key() <<  "::" << inat.value() << "\n";
      out << inat.key() << "::" << inat.value() << "\n";
    }
    file.close();
  }
  else
    Log::log()->appendFailed(QString("NaturalRuleHash::NaturalRuleHash(): failed to open file \"%1\" for writing").arg(filename));
}



