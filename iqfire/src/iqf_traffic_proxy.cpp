#include "iqf_traffic_proxy.h"
#include "iqflog.h"
#include <QTimer>
#include <QSettings>
#include <QStringList>
#include <QFile>
#include <QTextStream>
#include <QRegExp>

IQFTrafficProxy* IQFTrafficProxy::_instance = NULL;

IQFTrafficProxy::IQFTrafficProxy(QObject *parent) : QObject(parent)
{
  d_valid = false;
  d_ifaceNo = 0;
  timer = NULL;
}

void IQFTrafficProxy::setup()
{
  QSettings s;
  d_ifaceNo = countIfaces();
  if(d_ifaceNo > 0)
  {
    timer = new QTimer(this);
    timer->setSingleShot(false);
    d_interval = s.value("TRAFFIC_UPDATE_INTERVAL", 1000).toInt();
    timer->setInterval(d_interval);
    connect(timer, SIGNAL(timeout()), this, SLOT(readProc()));
    timer->start();
    foreach (QString ifacenam, ifaces)
    {
      emit configured(ifacenam);
    }
  }
}

int IQFTrafficProxy::countIfaces()
{
  QSettings s;
  int ret = 0;
  QString procfile = s.value("PROC_NET_DEV", QString("/proc/net/dev")).toString();
  QFile file(procfile);
  QStringList splitted;
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
    Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
	  "Check the settings and verify that the proc file name is correct\n"
	  "and that you have the permission to read it.").arg(procfile));
   }
   QTextStream in(&file);
   QString line = in.readLine();
   QString iface;	
    while(!line.isNull())
    {
      line = in.readLine();
      if(line.contains(":"))
      {
	splitted = line.split(':');
	iface = splitted.first().remove(QRegExp("\\s+"));
// 	qDebug() << "Aggiunto a ifaces: " << iface;
	ifaces << iface;
	ret++;
      }
    }
    file.close();
    return ret;
}


// IQFTrafficProxy::~IQFTrafficProxy()
// {
//   
// }

void IQFTrafficProxy::changeInterval(int newInt)
{
  d_interval = newInt;
  /* update QSettings */
  QSettings s;
  s.setValue("TRAFFIC_UPDATE_INTERVAL", d_interval);
  if(timer != NULL)
  {
    timer->stop();
    timer->setInterval(d_interval);
    timer->start();
  }
}

IQFTrafficProxy* IQFTrafficProxy::trafproxy(QObject *parent)
{
	if(_instance == NULL)
		return (_instance = new IQFTrafficProxy(parent) );
	else
		return _instance;
}

const QPair<double, double>  IQFTrafficProxy::bytesForInterface(QString ifnam) const
{
  double in = inmap[ifnam];
  double out = outmap[ifnam];
  QPair<double, double> ret;
  ret.first = in;
  ret.second = out;
  return ret;
}

void IQFTrafficProxy::readProc()
{
    QSettings s;
    double din = 0, dout = 0;
    unsigned long long drx, dtx;
    QStringList procrow, netdata;
    QString devdata, devname;
    int ifacecnt = 0;
    QString procfile = s.value("PROC_NET_DEV", QString("/proc/net/dev")).toString();
    QFile file(procfile);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
	Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
	  "Check the settings and verify that the proc file name is correct\n"
	  "and that you have the permission to read it.").arg(procfile));
	  inmap.clear();
	  outmap.clear();
	return;
    }
    QTextStream in(&file);
    QString line = in.readLine();
	
    while(!line.isNull())
    {
	if(line.contains(":"))
	{
	  procrow = line.split(':', QString::SkipEmptyParts);
	  devname = procrow.first();
// 	  if(devname.isNull() == 0)
// 	    continue;
	  devname = devname.remove(QRegExp("\\s+"));
	  /* a new row? Tell the interested people */
	  if(!ifaces.contains(devname))
	  {
	    qDebug() << devname << "non gia` presente, lo aggiungo";
	    emit configured(devname);
	    ifaces << devname;
	  }
	  devdata = procrow.last();
	  netdata = devdata.split(QRegExp("\\s+"), QString::SkipEmptyParts);
	  if(netdata.size() > 9)
	  {
	    drx = netdata[0].toULongLong();
	    dtx = netdata[8].toULongLong();
// 	    qDebug() << netdata;
// 	    if(devname == "eth0")
// 	      qDebug() << "rx: " << drx << "tx: " << dtx;
	    /* din, dout = difference, in bytes, between the actual /proc/dev read and the 
	     * previous read, stored in the prev_xxmap QMap, divided by the number of seconds
	     * elapsed between the reads.
	     */
	    if(prev_inmap[devname] == 0) /* first time */
	      din = 0.0;
	    else
	      din = (double) (drx - prev_inmap[devname])/(double) (d_interval) * 1000.0;
	    if(prev_outmap[devname] == 0)
	      dout = 0.0;
	    else
	      dout = (double) (dtx - prev_outmap[devname])/(double)d_interval * 1000.0;
	    prev_inmap[devname] = drx;
	    prev_outmap[devname] = dtx;
	    inmap[devname] = din;
	    outmap[devname] = dout;
	  }
	}
	line = in.readLine();
    }
    emit updateAvailable();
    file.close();
}



