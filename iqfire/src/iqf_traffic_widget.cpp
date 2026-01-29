#include "iqf_traffic_widget.h"
#include "iqf_traffic_proxy.h"

#include<QLabel>
#include "iqf_traffic_proxy.h"
#include <QTimer>
#include <QSettings>
#include <QPair>
#include <QVBoxLayout>
#include <QtDebug>
#include <QStackedWidget>
#include <QAction>
#include <QPushButton>
#include <QComboBox>
#include <QMouseEvent>


#include "iqfire.h" /* for ICON_PATH */

IQFTrafficToolBar::IQFTrafficToolBar(const QString &ifnam, const QString& title, QWidget *parent) : 
  QToolBar(title, parent)
{
  d_ifnam = ifnam;
  QSettings s;
  QWidget *w = new QWidget(this);
  QWidget *mainw = new QWidget(this);
  QHBoxLayout *hloMain = new QHBoxLayout(mainw);
  QHBoxLayout *hlo = new QHBoxLayout(w);
  sw = new QStackedWidget(this);
  QPushButton *pb = new QPushButton("Ok", w);
  QPushButton *pbCanc = new QPushButton("Cancel", w);
  connect(pb, SIGNAL(clicked()), this, SLOT(configured()));
  IQFTrafficProxy* tp = IQFTrafficProxy::trafproxy();
  connect(tp, SIGNAL(updateAvailable()), this, SLOT(refresh()));
  d_label = new QLabel("", mainw);
  d_confButton = new QPushButton(QIcon(ICON_PATH + "configure.png"), "", mainw);
  d_confButton->setHidden(true);
  d_confButton->setFlat(true);
  d_confButton->setStyleSheet("QPushButton:flat { border:none; }");
  d_confButton->setMaximumSize(QSize(25,25));
  d_confButton->setToolTip("Configure the measure unit");
  d_label->setFont(QFont("monospace"));
  combo = new QComboBox(w);
  hlo->addWidget(combo);
  hlo->addWidget(pb);
  hlo->addWidget(pbCanc);
  hlo->setMargin(0);
  hlo->setSpacing(1);
  hloMain->addWidget(d_label);
  hloMain->addWidget(d_confButton);
  hloMain->setMargin(0);
  hloMain->setSpacing(1);
  sw->insertWidget(0, mainw);
  sw->insertWidget(1, w);
  combo->addItems(QStringList() << "bit" << "Byte");
  combo->setCurrentIndex(combo->findText(s.value(QString("MEAS_UNIT_FOR_INTERFACE_%1").arg(d_ifnam), "bit").toString()));
  setUnit(combo->currentText());
  
  addWidget(sw);
  connect(d_confButton, SIGNAL(clicked()), this, SLOT(configure()));
  connect(pbCanc,  SIGNAL(clicked()), this, SLOT(configureCanceled()));
  mainw->setMouseTracking(true);
  setVisible(s.value(QString("TB_%1_VISIBLE").arg(d_ifnam), true).toBool());
}

void IQFTrafficToolBar::enterEvent(QEvent *e)
{
  d_confButton->setHidden(false);
  QToolBar::enterEvent(e);
}

void IQFTrafficToolBar::leaveEvent(QEvent *e)
{
  d_confButton->setHidden(true);
  QToolBar::leaveEvent(e);
}



void IQFTrafficToolBar::refresh()
{
  if(!isVisible())
    return;
  char buf[64];
  QPair<double, double> trafPair;
  QString unitRepresentationRx, unitRepresentationTx;
  double rx, tx;
  IQFTrafficProxy* tp = IQFTrafficProxy::trafproxy();
  trafPair = tp->bytesForInterface(d_ifnam);
  rx = convertToUnit(trafPair.first, unitRepresentationRx);
  tx = convertToUnit(trafPair.second, unitRepresentationTx);

  QString txt = QString("%1: Rx: %2 %3 Tx: %4 %5").arg(d_ifnam).
    arg(rx, 5, 'f', 1, QChar(' ')).arg(unitRepresentationRx).arg(tx, 5, 'f', 1, QChar(' ')).arg(unitRepresentationTx);
  d_label->setText(txt);
}

void IQFTrafficToolBar::configure()
{
     sw->setCurrentIndex(1);
}

void IQFTrafficToolBar::configureCanceled()
{
    sw->setCurrentIndex(0);
}

void IQFTrafficToolBar::configured()
{
  QSettings s;
  sw->setCurrentIndex(0);
  s.setValue(QString("MEAS_UNIT_FOR_INTERFACE_%1").arg(d_ifnam), combo->currentText());
  setUnit(combo->currentText());

}

double IQFTrafficToolBar::convertToUnit(double u, QString &unit)
{
  unsigned int k = 1000;
  unsigned int M = 1e6;
  unsigned int G = 1e9;

//   qDebug() << "u: " << u;
  switch(d_unit)
  {
    default:
      unit = " B/s";
      break;
    case BIT:
      u = u * 8;
      unit = " b/s";
      break;
  }
  
  if(u >= k && u < M)
  {
    u = u / (double) k;
    unit.replace(0, 1, 'k');
  }
  else if(u >= M && u < G)
  {
    u = u / (double) M;
    unit.replace(0, 1, 'M');
  }
  else if(u >= G)
  {
    u = u / (double) G;
    unit.replace(0, 1, 'G');
  }
  return u;
}

void IQFTrafficToolBar::setUnit(QString s)
{
  if(s == "Byte")
    d_unit = BYTE;
  else if(s == "bit")
    d_unit = BIT;
}

