#ifndef NATURAL_UPDATES_MANAGER_H
#define NATURAL_UPDATES_MANAGER_H

#include <QObject>
#include <naturalUpdaterWidget.h>
#include <naturalUpdater.h>
#include <iqfire.h>
#include <iqfsystray.h>

class QTimer;

class NaturalUpdatesManager : public QObject
{
   Q_OBJECT
   
  public:
    
    NaturalUpdatesManager(IQFIREmainwin *parent);
    int interval() { return d_interval; }
    
  public slots:
    void setInterval(int days);
    void enable(bool en);
    void update();
    void updateFinished(int ver);
    
  signals:
    void updatedToVersion(int);
    
  private:
    QTimer *d_timer;
    int d_interval;
    
    NaturalUpdaterWidget *d_updWidget;
    NaturalUpdater *d_updater;
    
};







#endif


