#ifndef NATURAL_UPDATER_WIDGET
#define NATURAL_UPDATER_WIDGET

#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include <QString>

class NaturalUpdaterWidget : public QWidget
{
  Q_OBJECT
  public:
    NaturalUpdaterWidget(QWidget *parent);
    void showAndPositionAt(const QPoint &p);
    
  public slots:
    void message(const QString &);
    void error(const QString &);
    void dataReadProgress(int, int);
    void scheduleHide(const QString& lastMessage);
    
  private:
    QLabel *label;
    QProgressBar *pbar;
    
};


#endif
