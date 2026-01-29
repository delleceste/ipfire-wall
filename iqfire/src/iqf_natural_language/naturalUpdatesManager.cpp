#include "naturalUpdatesManager.h"
#include <QSettings>
#include <QString>
#include <QDate>
#include <QTimer>
#include <QObject>

NaturalUpdatesManager::NaturalUpdatesManager(IQFIREmainwin *mainWin) : QObject(mainWin)
{
   QSettings s;
   d_updWidget = new NaturalUpdaterWidget(mainWin);
   d_updater = new NaturalUpdater(mainWin);
   
   connect(d_updater, SIGNAL(error(const QString &)), d_updWidget, SLOT(error(const QString &)));
   connect(d_updater, SIGNAL(step(const QString &)), d_updWidget, SLOT(message(const QString &)));
   connect(d_updater, SIGNAL(dataReadProgress(int, int)), d_updWidget, SLOT(dataReadProgress(int, int)));
   connect(d_updater, SIGNAL(updateFinished(const QString&)), d_updWidget, SLOT(scheduleHide(const QString&)));
   connect(d_updater, SIGNAL(updateFinished(int)), this, SLOT(updateFinished(int)));
   
   
   if(!s.contains("LAST_NATURAL_UPDATE")) /* first time run */
      s.setValue("LAST_NATURAL_UPDATE", QDate::currentDate());
    d_timer = new QTimer(this);
    d_interval = s.value("NATURAL_UPDATES_INTERVAL", 1).toInt() * 24 * 3600 * 1000;
    d_timer->setInterval(d_interval);
    connect(d_timer, SIGNAL(timeout()), this, SLOT(update()));
    
    if(s.value("NATURAL_UPDATES_ENABLE", true).toBool())
    {
      pinfo("natural language update manager enabled: is it time to update?");
      QDate lastUpdate = s.value("LAST_NATURAL_UPDATE").toDate();
      int updateInterval = s.value("NATURAL_UPDATES_INTERVAL", 1).toInt();
      QDate today = QDate::currentDate();
      qDebug() << "(lastUpdate.daysTo(today)" << lastUpdate.daysTo(today);
      qDebug() << "updateInterval" << updateInterval;
      if(lastUpdate.daysTo(today) >= updateInterval) /* time to update */
      {
	QTimer::singleShot(240000, this, SLOT(update()));
      }
      else
	pinfo("not time to update: last update was made on %s and interval is set to %d days", qstoc(lastUpdate.toString()), updateInterval);
      /* then look for updates every timer timeout */
      d_timer->start();
    }
}


void NaturalUpdatesManager::updateFinished(int version)
{ 
  emit updatedToVersion(version); 
}

void NaturalUpdatesManager::setInterval(int interval)
{
  QSettings s;
  d_interval = interval * 24 * 3600 * 1000;
  s.setValue("NATURAL_UPDATES_INTERVAL", interval);
  if(d_timer->isActive())
  {
    d_timer->start(d_interval);
  }
}

void NaturalUpdatesManager::enable(bool en)
{
  if(en && !d_timer->isActive())
    d_timer->start(d_interval);
  else if(!en && d_timer->isActive())
    d_timer->stop();
}

void NaturalUpdatesManager::update()
{
  pok("showing and positioning");
  IQFSysTray *trayIcon = qobject_cast<IQFSysTray *>(parent()->findChild<IQFSysTray *>());
  if(trayIcon)
  {
    QPoint trayIconPos = trayIcon->geometry().topLeft();
    d_updWidget->showAndPositionAt(trayIconPos);
  }
  else
    qDebug() << "cannot cast to IQFSysTray or object not found in " << parent();
  d_updater->update();
}







