#ifndef TEXT_BROWSER_H
#define TEXT_BROWSER_H

#include <QTextBrowser>
#include <QMessageBox>

class TextBrowser : public QTextBrowser
{
  Q_OBJECT
  public: 
    TextBrowser(QWidget *parent);
    
  public slots:
    void process();
    void reloadDict();
    void popupError(const QString& origin, const QString& msg);
    
  signals:
    void processed(const QString &);
};



#endif
