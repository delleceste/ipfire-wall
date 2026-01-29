#ifndef IQF_TRAFFIC_WIDGET_H
#define IQF_TRAFFIC_WIDGET_H

#include <QToolBar>
#include <QString>
#include <QLabel>

class QTimer;
class QPushButton;
class QStackedWidget;
class QComboBox;
class QEvent;

class IQFTrafficToolBar : public QToolBar
{
    Q_OBJECT
  public:
    IQFTrafficToolBar(const QString &ifnam, const QString& title, QWidget *parent = 0);
    QString name() { return d_ifnam; }
    
     enum Unit { BIT, BYTE};
     
  protected:
    void enterEvent(QEvent *e);
    void leaveEvent(QEvent *e);
    
  protected slots:
    void refresh();
    void configure();
    void configured();
    void configureCanceled();
    
  private:
    QTimer *refreshTimer;
    QLabel *d_label;
    QString d_ifnam;
    QStackedWidget *sw;
    QComboBox *combo;
    QPushButton *d_confButton;
    int d_unit;
    
    void setUnit(QString u);
    double convertToUnit(double u, QString &unit);
};



#endif