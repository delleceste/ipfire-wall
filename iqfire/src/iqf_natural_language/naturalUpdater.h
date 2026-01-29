#ifndef NATURAL_UPDATER_H
#define NATURAL_UPDATER_H

#include <QObject>
#include <QHttp>
#include <QString>
#include <QTimer>
#include <QMap>

class NaturalUpdater : public QHttp
{
  Q_OBJECT
  public:
    NaturalUpdater(QObject *parent);
    
  signals:
    void error(const QString &);
    void step(const QString &);
    void updateFinished(const QString& lastMessage);
    void updateFinished(int version);
    
  public slots:
    void update();
    
  private slots:
    void slotRequestFinished(int, bool);
  
  private:
    void finalizeUpdate();
    int getLocalDictVersion(const QString& dictPath);
    bool save(const QString& text, const QString& filename);
    int d_hostID, d_getVerID, d_getRegexpDefsID, d_getRegexpsID;
    int d_getSyntaxID, d_getServicesID, d_getNamesID;
    int d_getUnwantedID, d_getPreSostitutionsID, d_getVerbsID;
    QString d_remotePath, d_dictPath;
    QMap<int, QString> d_httpIdMap;
    QStringList d_dictFileList;
};

#endif
