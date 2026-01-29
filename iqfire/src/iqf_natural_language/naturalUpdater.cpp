#include "naturalUpdater.h"
#include <QSettings>
#include <QDate>
#include <QtDebug>
#include <QDir>
#include <macros.h>
#include <QFile>
#include <QTextStream>
#include <dictionary.h>
#include <iqflog.h>

NaturalUpdater::NaturalUpdater(QObject *parent) : QHttp(parent)
{
  QSettings s;
  QStringList dirfilters, allFiles, syntaxFiles;
  d_dictPath = s.value("DICT_PATH", "/usr/share/iqfire/natural_language/dictionary").toString();
  /* language of the dictionary */
  QString lang = s.value("NATURAL_LANGUAGE", "italiano").toString();
  if(!d_dictPath.endsWith('/'))
    d_dictPath += '/';
  d_dictPath += lang;
  connect(this, SIGNAL(requestFinished(int, bool)), this, SLOT(slotRequestFinished(int, bool)));
  d_remotePath = QString("/iqfire/natural_language/dictionaries/%1").arg(s.value("NATURAL_LANGUAGE", "italiano").toString());
  QDir dictDir(d_dictPath);
  dirfilters << "*.txt"; /* look for txt files */
  allFiles = dictDir.entryList(dirfilters);
  foreach(QString file, allFiles)
  {
    if(file.contains(QRegExp("\\bsyntax(?:\\d){0,2}\\.txt\\b")))
      syntaxFiles << file;
  }
  /* re create allFiles, starting with syntax files and then all the other needed files */
  d_dictFileList = syntaxFiles;
  d_dictFileList << "names.txt" << "regexps.def" << "pre_sostitutions.txt" << "regexps.txt" <<  
    "unwanted_regexp.txt" << "verbs.txt" << "version.txt";
}

void NaturalUpdater::update()
{
  QSettings s;
  /* setup proxy settings if required */
  if(s.value("PROXY_ENABLED", false).toBool())
  {
	setProxy(s.value("PROXY_HOST", "").toString(),
	s.value("PROXY_PORT", 8080).toInt(),
	s.value("PROXY_USER", "").toString(),
	s.value("PROXY_PASSWORD", "").toString());
  }
  d_hostID = setHost("www.giacomos.it");
  d_getVerID = get(d_remotePath + "/version.txt");
  pok("getting version from the remote host \"%s\", path: \"%s\"", "www.giacomos.it", qstoc(d_remotePath));
}

int NaturalUpdater::getLocalDictVersion(const QString& dictPath)
{
  int version = 0;
  bool ok;
  QString filename = dictPath + "/version.txt";
  QFile f(filename);
  if(f.open(QIODevice::ReadOnly | QIODevice::Text))
  {
    QString line;
    QTextStream in(&f);
    while (!in.atEnd()) 
    {
       line = in.readLine(); 
    }
    version = line.toInt(&ok);
    if(!ok)
      Log::log()->appendFailed(QString("Failed to obtain version number for natural language dictionary "
       "from file \"%1\". File contents are \"%2\"").arg( line).arg( filename));
    f.close();
  }
  else
    Log::log()->appendFailed(QString("Failed to open file \"%1\" for reading natural language dictionary version").
      arg(filename));
  return version;
}

void NaturalUpdater::slotRequestFinished(int id, bool err)
{
  QSettings s;
  QByteArray ba;
  QString txt, msg, language;
  int installedVersion, remoteVersion;
  
  if(err)
  {
    perr("error in request: %s", qstoc(errorString()));
    QString errmsg = errorString();
    emit error(errmsg);
    perr("clearing pending http requests");
    clearPendingRequests();
    return;
  }
    
  if(id == d_getVerID)
  {
     ba = readAll();
     txt = QString(ba);
     bool ok;
     remoteVersion = txt.toInt(&ok);
     installedVersion = getLocalDictVersion(d_dictPath);
     if(!ok)
     {
      if(txt.contains("404"))
      {
	QString errmsg = "Page not found on the server.";
	perr("page not found in the server:\n\"%s\"", qstoc(txt));
	emit error(errmsg);
      }
      else
      {
	QString errmsg = "Error reading version info.";
	perr("error reading version info from response:\n\"%s\"", qstoc(txt));
	emit error(errmsg);
      }
      remoteVersion = 0;
     }
     else if(remoteVersion > installedVersion)
     {
	
      
	pok("version %d available for dictionaries update: current version is %d", txt.toInt(), installedVersion);
       
       foreach(QString file, d_dictFileList)
       {
	 pstep("downloading dictionary \"%s\" module", qstoc(file));
	 msg = QString("downloading module \"%1\"").arg(file);
	 emit step(msg);
	 d_httpIdMap[get(d_remotePath + QString("/") + file)] = file;
       }
     }
     else
     {
       pok("no updates needed for natural language dictionaries: current version: %d, latest version: %d", installedVersion, txt.toInt());
       QString msg = QString("No updates available (current version: %1)").arg(installedVersion);
       emit updateFinished(msg);
       emit updateFinished(installedVersion);
     }
  }
  else if(d_httpIdMap.contains(id))
  {
    ba = readAll();
    txt = QString(ba);
    QString fname = d_dictPath + QString("/") + d_httpIdMap.value(id);
    if(save(txt, fname))
      pok("saved \"%s\" in \"%s\"", qstoc(d_httpIdMap.value(id)), qstoc(d_dictPath));
    else
    {
      perr("failed to save \"%s\" in \"%s\"", qstoc(d_httpIdMap.value(id)), qstoc(fname));
      perr("clearing pending http requests");
      clearPendingRequests();
    }

    if(d_dictFileList.size() > 0 && (d_httpIdMap.value(id) == d_dictFileList.last()))
    {
      finalizeUpdate();
      QString msg = QString("Successfully updated dictionaries to version %1").arg(getLocalDictVersion(d_dictPath));
      pok("reloading dictionary from directory \"%s\"", qstoc(d_dictPath));
      Dictionary::instance()->reload();
      emit updateFinished(msg);
      emit updateFinished(installedVersion);
    }
  }
}

void NaturalUpdater::finalizeUpdate()
{
  QSettings s;
  s.setValue("LAST_NATURAL_UPDATE", QDate::currentDate());
}

bool NaturalUpdater::save(const QString& text, const QString& filename)
{
  QFile file(filename);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
  {
    QString err = QString("error opening file \"%1\" for writing (%2)").arg(filename).arg(errorString());
    emit error(err);
    return false;
  }
  else
  {
    QTextStream out(&file);
    out << text;
    file.close();
  }
  return true;
}





