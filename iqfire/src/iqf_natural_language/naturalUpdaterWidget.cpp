#include "naturalUpdaterWidget.h"
#include <QGridLayout>
#include <QPalette>
#include <QPushButton>
#include <QToolTip>
#include <QTimer>
#include <macros.h>
#include <colors.h>

NaturalUpdaterWidget::NaturalUpdaterWidget(QWidget *parent) : QWidget(parent)
{
  int width = 300;
  int height = 60;
  setWindowFlags(Qt::ToolTip);
  setAttribute(Qt::WA_QuitOnClose, false);
//   setPalette(QPalette(KCAMEL));
  QFont font("", 8);
  setFont(font);
  QPushButton* pb = new QPushButton(this);
  pb->setText("x");
  pb->setToolTip("Close Natural Updates Indicator");
  QGridLayout *lo = new QGridLayout(this);
  QLabel *titleLabel = new QLabel(this);
  titleLabel->setText("<b>iqfire natural language updates</b>.");
  label = new QLabel(this);
  label->setText("Natural language updates");
  setPalette(QPalette(KCAMEL));
  pbar = new QProgressBar(this);
  pbar->setMaximumHeight(height/3);
  pb->setMaximumHeight(height/4);
  titleLabel->setMaximumHeight(height/3);
  pb->setMaximumWidth(pb->maximumHeight());
  pbar->setMinimum(0);
  
  label->setMaximumHeight(height/2);
  lo->setMargin(4);
  lo->setSpacing(2);
  lo->addWidget(titleLabel, 0, 0, 1, 6);
  lo->addWidget(label, 1, 0, 1, 7);
  lo->addWidget(pb, 0, 6, 1, 1);
  lo->addWidget(pbar, 2, 0, 1, 7);
 
  setMaximumWidth(width);
  setMaximumHeight(height);
  setMinimumWidth(width);
  setMinimumHeight(height);
  connect(pb, SIGNAL(clicked()), this, SLOT(hide()));
}

void NaturalUpdaterWidget::message(const QString & msg)
{
  QPalette p = label->palette();
  p.setBrush(QPalette::WindowText, QBrush(Qt::black));
  label->setPalette(p);
  label->setText(msg);
}

void NaturalUpdaterWidget::error(const QString & msg)
{
  QPalette p = label->palette();
  p.setBrush(QPalette::WindowText, QBrush(KRED));
  label->setPalette(p);
  label->setText(msg);
  scheduleHide(msg);
}

void NaturalUpdaterWidget::dataReadProgress(int val, int tot)
{
  pbar->setMaximum(tot);
  pbar->setValue(val);
  if(val == pbar->maximum())
    pbar->setVisible(false);
  else
    pbar->setVisible(true);
}

void NaturalUpdaterWidget::showAndPositionAt(const QPoint &topLeft)
{
  QRect rect = geometry();
  int w = rect.width();
  int h = rect.height();

  rect.moveLeft(topLeft.x() - w);
  rect.moveTop(topLeft.y() - h);
  setGeometry(rect);
  show();
}

void NaturalUpdaterWidget::scheduleHide(const QString& finalMessage)
{
  pbar->hide();
  label->setText(finalMessage);
  QTimer::singleShot(8000, this, SLOT(hide()));
}







