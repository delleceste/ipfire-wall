#ifndef NATURAL_WIDGET_H
#define NATURAL_WIDGET_H

#include <QWidget>
#include <QEvent>
#include <QString>
#include <QTreeWidget>
#include "machineTextToRules.h"

class NaturalTextBrowser;
class QLabel;
class IQFTextBrowser;
class NaturalLogTextBrowser;
class NaturalProgressBar;

class NaturalWidget : public QWidget
{
Q_OBJECT
  public:
  NaturalWidget(QWidget *parent);
  
  void saveNaturalText();
  
  NaturalLogTextBrowser *logTextBrowser() { return logB; }
  
  public slots:
    void appendNaturalText(const QString&);
    void reloadDictAndGrammar();
  
  signals:
    void newNaturalItem(const uid_t, const int, const int, const QStringList &, const QString &);
    void clearNaturalItems();
    void showRuleTree();
    void applyNaturalRules();
  
  protected:
    /* to catch new item events */
    bool event(QEvent *);
  
  protected slots:
    void evaluate();
    void popupError(const QString&, const QString &);
    void slotShowRuleTree() { emit showRuleTree(); } 
    void searchToggled(bool);
    void findTextInBrowser();
    void applyAndSave();
    void textModified();
    void updateProgressBar(int, int, const QString& txt);
    
    void processNaturalText();
    
  private:
    NaturalTextBrowser  *naturalBrowser;
    QTreeWidget *previewTree;
    NaturalLogTextBrowser *logB;
    NaturalProgressBar *pBar;
    QList<NaturalItemEvent> d_pendingNaturalEvents;
};


#endif
