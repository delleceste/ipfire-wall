#ifndef NATURAL_PROGRESS_BAR_H
#define NATURAL_PROGRESS_BAR_H

#include <QProgressBar>
#include <QString>

class NaturalProgressBar : public QProgressBar
{
  Q_OBJECT
  public:
    NaturalProgressBar(QWidget *parent);
    void setText(const QString &s) { d_text = s; }
  
  protected:
    QString text() const { return d_text; }
    
  private:
    QString d_text;
};


#endif
