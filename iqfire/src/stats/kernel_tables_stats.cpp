#include "kernel_tables_stats.h"
#include <iqfwidgets.h>
#include <QString>
#include <QGridLayout>
#include <QSettings>
#include <QLabel>
#include <QTimer>
#include <QDateTime>
#include <colors.h>
#include <ipfire_structs.h>
#include <macros.h>
#include <iqfnetlink.h>

#define SECS (1000)

KernelTablesStats::KernelTablesStats(QWidget *parent) : QWidget(parent)
{
  int ret;
  QSettings s;
  QLabel *spinLabel;
  QLabel *pollLabel;
  QLabel *bufferLabel;
  memset(&tables_sizes, 0, sizeof(tables_sizes));
  QDateTime now = QDateTime::currentDateTime();
  QDateTime firstRefreshTime;
  
  /* timeout in minutes */
  d_refreshTimeout = s.value("KTABLES_POLL_TIMEOUT", 20).toInt() * SECS;
  /* poll timeout in seconds */
  d_pollTimeout = s.value("KERNEL_TABLES_POLLING_PERIOD", 10).toInt() * SECS;
  d_refreshEnabled = s.value("KTABLES_STATS_ENABLED", false).toBool();
  QGridLayout *lo = new QGridLayout(parent);
  d_cbEnable = new IQFCheckBox(this);
  d_cbEnable->setText("Enable monitoring");
  d_cbEnable->setToolTip("This option is saved and restored at next program startup");
  d_cbEnable->setObjectName("kmemEnableMonitoring");
  spinLabel = new QLabel(this);
  spinLabel->setText("Plot Refresh interval [sec]");
  
  d_sbPlotRefreshInterval = new IQFSpinBox(this);
  d_sbPlotRefreshInterval->setMinimum(1); /* two seconds */
  d_sbPlotRefreshInterval->setMaximum(300); /* five hours maximum */
  d_sbPlotRefreshInterval->setValue(s.value("KTABLES_POLL_TIMEOUT", 20).toUInt());
  d_sbPlotRefreshInterval->setToolTip("This value is saved and restored at next program startup");
  d_sbPlotRefreshInterval->setObjectName("kmemPlotRefreshInterval");
  firstRefreshTime.addSecs(d_sbPlotRefreshInterval->value() * 60);
  
  bufferLabel = new QLabel(this);
  bufferLabel->setText("Buffer size [hours]");
  d_sbBuffer = new IQFSpinBox(this);
  d_sbBuffer->setMinimum(1); /* 1 hour at least */
  d_sbBuffer->setMaximum(48); /* 48 hours */
  d_sbBuffer->setObjectName("kmemBufsiz");
  d_sbBuffer->setValue(s.value("KTABLES_STATS_PLOT_BUFFER", 24).toUInt());
  d_sbBuffer->setToolTip("This value (in hours) is saved and restored at next program startup");
  
  pollLabel = new QLabel(this);
  pollLabel->setText("Kernel tables polling period [s.]");
  d_rbMean = new IQFRadioButton(this);
  d_rbMean->setObjectName("kmemMeanPeriod");
  d_rbMean->setText("Mean in period");
  d_rbMean->setToolTip("This setting is saved and restored at next startup");
  d_rbPeak= new IQFRadioButton(this);
  d_rbPeak->setObjectName("kmemPeakPeriod");
  d_rbPeak->setText("Peak in period");
  d_rbPeak->setToolTip("This setting is saved and restored at next startup");
  
  d_sbPoll = new IQFSpinBox(this);
  d_sbPoll->setObjectName("kmemPollRefreshInterval");
  /* initialize polling settings */
  d_sbPoll->setMinimum(1);
  d_sbPoll->setMaximum(300);
  d_sbPoll->setValue(d_pollTimeout/SECS);
  d_rbMean->setChecked(s.value("KERNEL_TABLES_MEAN_PERIOD", false).toBool());
  d_rbPeak->setChecked(!s.value("KERNEL_TABLES_MEAN_PERIOD", false).toBool());
  
  /* plot */
  d_plot = new KernelStatsPlot(QwtText("Kernel memory usage over time"), this);
  d_plot->setTimeScaleDrawEnabled(true);
  d_plot->enableTrackerText(true);
  d_plot->setAxisScale(QwtPlot::xBottom, now.toTime_t(), firstRefreshTime.toTime_t());
// //    d_plot->setAxisAutoScale(QwtPlot::xBottom);
  /* plot refresh timer */
  d_refreshTimer = new QTimer(this);
  d_refreshTimer->setInterval(d_refreshTimeout);
  d_refreshTimer->setSingleShot(false);
  
  /* poll refresh timer */
  d_pollTimer = new QTimer(this);
  d_pollTimer->setInterval(d_pollTimeout);
  d_pollTimer->setSingleShot(false);
  
  /* add objects to layout */
  lo->addWidget(d_plot, 0, 0, 8, 10);
  lo->addWidget(pollLabel, 8, 4, 1, 2);
  lo->addWidget(d_sbPoll, 8, 6, 1, 1);
  lo->addWidget(d_rbPeak, 8, 7, 1, 1);
  lo->addWidget(d_rbMean, 8, 8, 1, 1);
  lo->addWidget(bufferLabel, 9, 0, 1, 2);
  lo->addWidget(d_sbBuffer, 9, 2, 1, 1);
  lo->addWidget(spinLabel, 9, 4, 1, 2);
  lo->addWidget(d_sbPlotRefreshInterval, 9, 6, 1, 1);
  lo->addWidget(d_cbEnable, 9, 8, 1, 1);
 
    
  QwtLegend *legend = new QwtLegend(d_plot);
  d_plot->insertLegend(legend, QwtPlot::BottomLegend);
 
  
  QFont f("", 8);
  d_plot->setAxisFont(QwtPlot::xBottom, f);
  d_plot->setAxisFont(QwtPlot::yLeft, f);
  d_plot->setAxisTitle(QwtPlot::yLeft, QwtText("KiloBytes"));
  d_plot->enableTrackerText(false);
  
  /* curves */
  d_stateCrv = new EPlotCurve(this, QwtText("state"));
  d_snatCrv = new EPlotCurve(this, QwtText("source nat"));
  d_dnatCrv = new EPlotCurve(this, QwtText("dest. nat"));
  d_loginfoCrv = new EPlotCurve(this, QwtText("log info"));
  d_totCrv = new EPlotCurve(this, QwtText("total"));
  
  /* setup curve colors */
  QColor cg(KDARKGREEN);
  QColor cb(KDARKBLUE);
  QColor cv(KVERYDARKVIOLET);
  QColor cr(KDARKRED);
  QColor cc(KDARKMAROON);
  
  cg.setAlpha(127);
  cb.setAlpha(127);
  cv.setAlpha(127);
  cr.setAlpha(127);
  cc.setAlpha(127);
  
  /* curves' pens */
  d_stateCrv->setPen(QPen(cb));
  d_snatCrv->setPen(QPen(cr));
  d_dnatCrv->setPen(QPen(cv));
  d_loginfoCrv->setPen(QPen(cc));
  d_totCrv->setPen(QPen(cg));
  //d_totCrv->setPen(QPen(QBrush(cg), 1, Qt::DotLine ));
  
  /* attach curves to plot */
  d_plot->addCurve("StateCurve", d_stateCrv);
  d_plot->addCurve("SnatCurve", d_snatCrv);
  d_plot->addCurve("DnatCurve", d_dnatCrv);
  d_plot->addCurve("LoginfoCurve", d_loginfoCrv);
  d_plot->addCurve("TotCurve", d_totCrv);
  
  /* after curve creation and adding, set their style according to stats mode: mean or peak */
  if(d_rbMean->isChecked())
    d_plot->setCurvesStyle(QwtPlotCurve::Steps);
  
  /* call this after add curve! */
  /* buffer size = number_of_hours * 60 / number_of_minutes (in one hour) */
  d_bufsiz = d_sbBuffer->value() * 3600 / d_sbPlotRefreshInterval->value();
  d_plot->setDataBufferSize(d_bufsiz);
  pinfo("kernel table plot refresh options: interval: %d (min) bufsiz: %d", d_refreshTimeout/SECS, d_bufsiz);

  
  
  /* connections */
  connect(d_sbBuffer, SIGNAL(valueChanged(int)), this, SLOT(plotDataBufferChanged(int)));
  connect(d_sbPlotRefreshInterval, SIGNAL(valueChanged(int)), this, SLOT(plotRefreshIntervalChanged(int)));
  connect(d_refreshTimer, SIGNAL(timeout()), this, SLOT(plotRefresh()));
  connect(d_pollTimer, SIGNAL(timeout()), this, SLOT(pollRefresh()));
  connect(d_cbEnable, SIGNAL(toggled(bool)), this, SLOT(enableRefresh(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), d_sbBuffer, SLOT(setEnabled(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), d_sbPlotRefreshInterval, SLOT(setEnabled(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), bufferLabel, SLOT(setEnabled(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), spinLabel, SLOT(setEnabled(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), d_sbPoll, SLOT(setEnabled(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), d_rbMean, SLOT(setEnabled(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), d_rbPeak, SLOT(setEnabled(bool)));
  connect(d_cbEnable, SIGNAL(toggled(bool)), pollLabel, SLOT(setEnabled(bool)));
  
  connect(d_rbPeak, SIGNAL(toggled(bool)), this, SLOT(peakRBToggled(bool)));
  connect(d_sbPoll, SIGNAL(valueChanged(int)), this, SLOT(pollChanged(int)));
  
  /* this triggers the first refresh */
  d_cbEnable->setChecked(d_refreshEnabled);
  
  ret = getStructSizes();
  
  if(ret < 0 || (d_pollTimeout  >= d_refreshTimeout))
  { 
    d_cbEnable->setChecked(false);
    d_sbBuffer->setEnabled(true);
    d_sbPoll->setEnabled(true);
    d_sbPlotRefreshInterval->setEnabled(true);
    d_plot->setDisabled(true);
    if(ret < 0)
      perr("or failure in obtaining kernel structure sizes");
    else
      perr("kernel polling timeout is greater than or equal of plot refresh timeout. Cannot refresh");
  }
  else
  {
    pok("kernel tables memory usage monitor initialized");
    if(d_refreshEnabled && d_pollTimeout < d_refreshTimeout)
    {
      d_refreshTimer->start();
      d_pollTimer->start();
      pstep("starting kernel tables memory usage refreshes every %d minutes", d_refreshTimeout/SECS);
    }
  }
   d_plot->replot();
}

void KernelTablesStats::plotRefresh()
{
  double kB = 1024;
  double stMem = 0, snMem = 0, dnMem = 0, liMem = 0, totMem;
  uint date = QDateTime::currentDateTime().toTime_t();
  
  if(d_rbPeak->isChecked())
  {
//     qDebug() << "+++++ valori prima del sort (loginfo ): " << d_infoPollBuf;
//     qDebug() << "valori prima del sort (state ): " << d_stPollBuf;
    if(d_stPollBuf.size() > 1)
    {
      qSort(d_stPollBuf.begin(), d_stPollBuf.end());
      stMem = tables_sizes.statesize * d_stPollBuf.last() / kB;
    }
    else if(d_stPollBuf.size() > 0)
      stMem = tables_sizes.statesize * d_stPollBuf.first() /kB;
    
    if(d_sntPollBuf.size() > 1)
    {
      qSort(d_sntPollBuf.begin(), d_sntPollBuf.end());
      snMem = tables_sizes.snatsize * d_sntPollBuf.last() / kB;
    }
    else if(d_sntPollBuf.size()  > 0)
      snMem = tables_sizes.snatsize * d_sntPollBuf.first() / kB;
    
    if(d_dntPollBuf.size() > 1)
    {
      qSort(d_dntPollBuf.begin(), d_dntPollBuf.end());
      dnMem = tables_sizes.dnatsize * d_dntPollBuf.last() / kB;
    }
    else if(d_dntPollBuf.size()  > 0)
      dnMem = tables_sizes.dnatsize * d_dntPollBuf.first() / kB;
    
    if(d_infoPollBuf.size() > 1)
    {
      qSort(d_infoPollBuf.begin(), d_infoPollBuf.end());
      liMem = tables_sizes.loginfosize * d_infoPollBuf.last() / kB;
    }
    else if(d_infoPollBuf.size() > 0)
      liMem = tables_sizes.loginfosize * d_infoPollBuf.first() / kB;
    
//     qDebug() << "valori dopo del sort (loginfo ): " << d_infoPollBuf;
//     qDebug() << "valori dopo del sort (state ): " << d_stPollBuf;
  }
  else /* mean of each buffer */
  {

    if(d_stPollBuf.size() > 0) /* avoid dividing by zero ;-) */
    {
      foreach(uint ui, d_stPollBuf)
	stMem += ui;
      stMem = (tables_sizes.statesize * stMem / d_stPollBuf.size()) / kB;
    }
    
    if(d_sntPollBuf.size() > 0)
    {
      foreach(uint ui, d_sntPollBuf)
	snMem += ui;
      snMem = (tables_sizes.snatsize * snMem / d_sntPollBuf.size()) / kB;
    }
    
    if(d_dntPollBuf.size() > 0)
    {
      foreach(uint ui, d_dntPollBuf)
	dnMem += ui;
      dnMem = (tables_sizes.dnatsize * dnMem / d_dntPollBuf.size()) / kB;
    }
    
    if(d_infoPollBuf.size() > 0)
    {
      foreach(uint ui, d_infoPollBuf)
	liMem += ui;
      liMem = (tables_sizes.loginfosize * liMem / d_infoPollBuf.size()) / kB;
    }
  }

  totMem = stMem + snMem + dnMem + liMem;
  
  if(stMem >= 0 && snMem >= 0 && dnMem >= 0 && liMem >= 0)
  {
    d_plot->appendData("StateCurve", date, stMem);
    d_plot->appendData("SnatCurve", date, snMem);
    d_plot->appendData("DnatCurve", date, dnMem);
    d_plot->appendData("LoginfoCurve", date, liMem);
    d_plot->appendData("TotCurve", date, totMem);
  }
  else
    pwarn("KernelTablesStats::plotRefresh(): data not ready in this moment, maybe poller/plot refresher temporary unaligned");
  
  d_plot->refresh();
  d_stPollBuf.clear();
  d_sntPollBuf.clear();
  d_dntPollBuf.clear();
  d_infoPollBuf.clear();

}

/* fill in polling buffers */
void KernelTablesStats::pollRefresh()
{
  struct ktables_usage ktu;
  IQFNetlinkControl::instance()->GetKtablesUsage(&ktu);
//   printf("+++ buffer polling: state %d snat %d dnat %d log %d\n", ktu.state_tables, ktu.snat_tables, ktu.dnat_tables, ktu.loginfo_tables);
  /* calculate memory usage now! */
  /* state tables */
  if(d_stPollBuf.size() == 0 || (d_stPollBuf.size() > 0 && d_stPollBuf.last() != ktu.state_tables))
    d_stPollBuf.push_back(ktu.state_tables);
  
  /* source nat tables */
  if(d_sntPollBuf.size() == 0 || (d_sntPollBuf.size() > 0 && d_sntPollBuf.last() != ktu.snat_tables))
    d_sntPollBuf.push_back(ktu.snat_tables);
  
  /* dest nat tables */
  if(d_dntPollBuf.size() == 0 || (d_dntPollBuf.size() > 0 && d_dntPollBuf.last() != ktu.dnat_tables))
    d_dntPollBuf.push_back(ktu.dnat_tables);
  
  /* info tables */
  if(d_infoPollBuf.size() == 0 || (d_infoPollBuf.size() > 0 && d_infoPollBuf.last() != ktu.loginfo_tables))
    d_infoPollBuf.push_back(ktu.loginfo_tables);

}

void KernelTablesStats::plotDataBufferChanged(int v )
{
  QSettings s;
  d_bufsiz = v * 3600/ d_sbPlotRefreshInterval->value();
  s.setValue("KTABLES_STATS_PLOT_BUFFER", v);
  printf("\e[1;32msetto il valore del bufsiz su d_plot a %d\e[0m\n", d_bufsiz);
  d_plot->setDataBufferSize(d_bufsiz);
}

void KernelTablesStats::plotRefreshIntervalChanged(int v)
{
  QSettings s;
  s.setValue("KTABLES_POLL_TIMEOUT", v);
  d_refreshTimeout = v * SECS;
  d_refreshTimer->setInterval(d_refreshTimeout);
  pinfo("changed timeout to %d mins (val %d): triggering buffer size change", v, d_refreshTimeout);
  /* buffer size for plot is linked to the plot refresh interval */
  plotDataBufferChanged(d_sbBuffer->value());
}
   
void KernelTablesStats::pollChanged(int v)
{ 
  QSettings s;
  s.setValue("KERNEL_TABLES_POLLING_PERIOD", v);
  d_pollTimeout = v * SECS;
  d_pollTimer->setInterval(d_pollTimeout);
  pinfo("polling period changed to %dsecs", v);
}

void KernelTablesStats::enableRefresh(bool en)
{
  d_refreshEnabled = en;
  QSettings s;
  s.setValue("KTABLES_STATS_ENABLED", en);
  if(en)
  {
    if(!d_pollTimer->isActive())
      d_pollTimer->start();
    if(!d_refreshTimer->isActive())
      d_refreshTimer->start();
    pollRefresh();
    plotRefresh();
  }
  else
  {
    if(d_refreshTimer->isActive())
      d_refreshTimer->stop();
    if(d_pollTimer->isActive())
      d_pollTimer->stop();
  }
}

int  KernelTablesStats::getStructSizes()
{
  return IQFNetlinkControl::instance()->GetKtablesSizes(&tables_sizes);
}

void KernelTablesStats::showEvent(QShowEvent *e)
{
  QWidget::showEvent(e);
}

void KernelTablesStats::peakRBToggled(bool b)
{
  QSettings s;
  s.setValue("KERNEL_TABLES_MEAN_PERIOD", !b);
  /* change the curves style to steps if mean is selected */
  if(!b)
    d_plot->setCurvesStyle(QwtPlotCurve::Steps);
  else
    d_plot->setCurvesStyle(QwtPlotCurve::Lines);
  d_plot->refresh();
}









