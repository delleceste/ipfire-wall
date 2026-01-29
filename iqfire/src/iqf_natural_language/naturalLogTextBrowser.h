#ifndef NATURAL_LOG_TEXT_BROWSER_H
#define NATURAL_LOG_TEXT_BROWSER_H

#include <iqfwidgets.h>

class NaturalLogTextBrowser : public IQFTextBrowser
{
  Q_OBJECT
  public:
    NaturalLogTextBrowser(QWidget *parent);
    
  public slots:
    void addOk(const QString &s);
    void addWarning(const QString &w);
    void addError(const QString &e);
    void clear();
    
  private:
    QString d_html;
    QString d_legend, d_closeList, d_closeHtml, d_header;
    QStringList d_messages;
    void update();
    void init();
};

#endif
