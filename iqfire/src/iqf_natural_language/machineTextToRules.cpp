#include <QCoreApplication>
#include <QDateTime>
#include "machineTextToRules.h"
#include "machineSentenceToRule.h"

MachineTextToRules::MachineTextToRules(const MachineText &txt, QObject *parent) : QObject(parent)
{
  d_mtext = txt;
}
    
void MachineTextToRules::extractRules()
{
  bool error = false;
  int progress = 0, totSteps;
  QString progressMsg;
  QList<MachineSentence> sentences = d_mtext.machineSentences();
  
  ClearNaturalItemsEvent * clearEvent = new ClearNaturalItemsEvent();
  QCoreApplication::postEvent(parent(), clearEvent);
  
  if(sentences.size() == 0)
  {
    pwarn("No sentences in text \"%s\"", qstoc(d_mtext));
    QString warn = QString("Text <cite>%1</cite> does not contain any sentence").arg(d_mtext);
    WarningMessageEvent *wme = new WarningMessageEvent(warn);
    qApp->postEvent(parent(), wme);
  }
  
  totSteps = sentences.size();
  
  foreach(MachineSentence ms, sentences)
  {
    progress++;
    MachineSentenceToRule msConverter(ms);
    QStringList ruleItem = msConverter.toRuleItem();
    qDebug() << "extractedRule:" << ruleItem;
    NaturalSentence associatedNaturalSentence = ms.associatedNaturalSentence();
    if(msConverter.conversionOk())
    {
      NaturalItemEvent *nev = new NaturalItemEvent(NEWITEMEVENT, msConverter.policy(), msConverter.owner(),
		msConverter.direction(), ruleItem, associatedNaturalSentence);
      QCoreApplication::postEvent(parent(), nev);
      progressMsg = QString("rule extraction (%1/%2)").arg(progress).arg(totSteps);
      emit extractionProgress(progress, totSteps, progressMsg);
    }
    else
    {
      perr("Conversion of \"%s\" failed", qstoc(ms));
      perr("error reported: %s", qstoc(msConverter.errmsg()));
      QString err = QString("<strong>ERROR</strong>: \"<cite>%1</cite>\": %2").arg(ms.associatedNaturalSentence()).arg(msConverter.errmsg());
      ErrorMessageEvent *eme = new ErrorMessageEvent(err);
      qApp->postEvent(parent(), eme);
      error = true;
     }
     if(msConverter.warnings())
     {
       foreach(QString w, msConverter.warningsList())
       {
	 QString warn = QString("<strong>WARNING</strong>: \"<cite>%1</cite>\": %2").arg(ms.associatedNaturalSentence()).arg(w);
	 WarningMessageEvent *wme = new WarningMessageEvent(warn);
	 qApp->postEvent(parent(), wme);
       }
     }
  } /* foreach */
  if(!error)
  {
    QString msg = QString("natural text processing completed on <strong>%1</strong>").arg(QDateTime::currentDateTime().toString());
    OkMessageEvent *me = new OkMessageEvent(msg);
    qApp->postEvent(parent(), me);
  }
  else
  {
    QString err = QString("natural text processing completed <strong>with one or more errors</strong> on %1").arg(QDateTime::currentDateTime().toString());
    ErrorMessageEvent *eme = new ErrorMessageEvent(err);
    qApp->postEvent(parent(), eme);
  }
  /* at the end, post an end processing event */
  NaturalRuleExtractionEndEvent* nreee = new NaturalRuleExtractionEndEvent();
  qApp->postEvent(parent(), nreee);
}





