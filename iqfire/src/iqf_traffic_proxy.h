#ifndef IQF_TRAFFIC_PROXY_H
#define IQF_TRAFFIC_PROXY_H

#include <QObject>
#include <QMap>
#include <QStringList>
#include <QPair>

class QTimer;

class IQFTrafficProxy : public QObject
{
  Q_OBJECT
  public:
  
    static IQFTrafficProxy* trafproxy(QObject *parent = NULL);
    
    void setup();
    
    const QPair<double, double> bytesForInterface(QString ifnam) const;
    int ifaceNo() { return d_ifaceNo; }
    bool valid() { return d_valid; }
    int interval() { return d_interval; }
    
   signals:
    void configured(const QString &ifname);
    void deconfigured(const QString &ifname);
    void updateAvailable();
    
   public slots:
   
    void changeInterval(int i);
   
   private slots:
    void readProc();
    
   private:
   
    IQFTrafficProxy(QObject *parent);
//     ~IQFTrafficProxy();
    
    static IQFTrafficProxy* _instance;
    
    int countIfaces();
    
    bool d_valid;
    int d_interval, d_ifaceNo;
    QMap<QString, double> inmap, outmap;
    QMap<QString, unsigned long long> prev_inmap;
    QMap<QString, unsigned long long> prev_outmap;
    QTimer *timer;
    QStringList ifaces;
};



#endif

