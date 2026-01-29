#include "includes/NaturalSentence.h"
#include "TextBrowser.h"
#include <QPushButton>
#include <QWidget>
#include <QApplication>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QObject>

class TextBrowser;
int main(int argc, char *argv[])
{
  QApplication a(argc, argv);
  a.setApplicationName("NaturalTest");
  a.setOrganizationName("giacomos.it");

  QWidget *widget = new QWidget(0);
  TextBrowser *tb = new TextBrowser(widget);
  QTextBrowser *qtb  = new QTextBrowser(widget);
  qtb->setReadOnly(true);
  QPushButton *pb = new QPushButton(widget);
  QPushButton *pbReload = new QPushButton(widget);
  pbReload->setText("Reload dictionary");
  pb->setText("Interpreta");
  QVBoxLayout *lo = new QVBoxLayout(widget);
  lo->addWidget(pbReload);
  lo->addWidget(tb);
  lo->addWidget(qtb);
  lo->addWidget(pb);
  QObject::connect(pb, SIGNAL(clicked()), tb, SLOT(process()));
  QObject::connect(tb, SIGNAL(processed(const QString &)), qtb, SLOT(setText(const QString &)));
  QObject::connect(pbReload, SIGNAL(clicked()), tb, SLOT(reloadDict()));
  widget->resize(QSize(700,800));
  widget->show();
  
  return a.exec();
  
}

