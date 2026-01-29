#include <iqfire.h>
#include "naturalWidget.h"
#include <iqfwidgets.h>
#include <QSplitter>
#include <QMessageBox>
#include <QSettings>
#include <QGridLayout>
#include <QVector>
#include <ipfire_structs.h>
#include <iqflog.h>
#include <iqfpolicy.h>
#include <natural_language.h>
#include <ServiceProcessor.h>
#include <QHeaderView>
#include <QGroupBox>
#include <QTimer>
#include "naturalTextBrowser.h"
#include "naturalTreeItem.h"
#include "naturalLogTextBrowser.h"
#include "naturalProgressBar.h"
#include "naturalTextResolverThread.h"


NaturalWidget::NaturalWidget(QWidget *parent) : QWidget(parent)
{
  QSettings s;
  QWidget *moreButtonsWidget = new QWidget(this);
  QWidget *editorW = new QWidget(this);
  QWidget *previewW = new QWidget(this);
  QWidget *logW = new QWidget(this);
  editorW->setObjectName("Editor");
  previewW->setObjectName("Preview");
  logW->setObjectName("Log");
  QGridLayout *editorLo = new QGridLayout(editorW);
  QVBoxLayout *previewLo = new QVBoxLayout(previewW);
  QVBoxLayout *logLo = new QVBoxLayout(logW);
  QHBoxLayout *moreButtonsWidgetLo = new QHBoxLayout(moreButtonsWidget);
  
  QSplitter *splitter = new QSplitter(this);
  QGridLayout* glo = new QGridLayout(parent);
  naturalBrowser = new NaturalTextBrowser(editorW);
  naturalBrowser->setObjectName("Natural language IQFTextBrowser");
  previewTree = new QTreeWidget(previewW);
  naturalBrowser->setObjectName("Machine language IQFTextBrowser");
  logB = new NaturalLogTextBrowser(logW);
  IQFPushButton *pbEvaluate = new IQFPushButton(this);
  pbEvaluate->setText("Evaluate Text");
  pbEvaluate->disableHelp(true);
  IQFPushButton *pbApplySave = new IQFPushButton(this);
  pbApplySave->setText("Apply and Save");
  pbApplySave->disableHelp(true);
  pbApplySave->setObjectName("Apply and Save");
  pBar = new NaturalProgressBar(this);
  pBar->setObjectName("Natural progress bar");
  pBar->setHidden(true);
  
  IQFPushButton *pbClear = new IQFPushButton(this);
  pbClear->setText("Clear Preview");
  pbClear->disableHelp(true);
  IQFPushButton *pbTree = new IQFPushButton(this);
  pbTree->setText("Rule Tree");
  pbTree->disableHelp(true);
  pbTree->setIcon(QIcon(ICON_PATH + "ruletree.png"));
  QHeaderView *headerView = previewTree->header();
  headerView->setResizeMode(QHeaderView::ResizeToContents);
  IQFPushButton *pbEvalLog = new IQFPushButton(this);
  pbEvalLog->setObjectName("Button Log");
  pbEvalLog->setText("Evaluation log");
  pbEvalLog->setCheckable(true);
  pbEvalLog->disableHelp(true);
  IQFPushButton *pbPreview = new IQFPushButton(this);
  pbPreview->setText("Rule Preview");
  pbPreview->setCheckable(true);
  pbPreview->setObjectName("Button Preview");
  pbPreview->disableHelp(true);
  IQFPushButton *clearLogB = new IQFPushButton(this);
  clearLogB->setText("Clear Log");
  clearLogB->disableHelp(true);
  QLabel *labelPreview = new QLabel(previewW);
  labelPreview->setText("Natural language rules preview");
  QLabel *labelNaturalText = new QLabel(editorW);
  labelNaturalText->setText(QString("Natural language rule editor (<b>%1</b>)").
    arg(s.value("NATURAL_LANGUAGE", "italiano").toString()));
  labelNaturalText->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  labelPreview->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  pbPreview->setSizePolicy(QSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed));
  pbEvalLog->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  pbClear->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  clearLogB->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  
  /* label and button to search */
  IQFPushButton *pbFind = new IQFPushButton(editorW);
  pbFind->setText("Find");
  pbFind->setObjectName("pushButtonFind");
  pbFind->disableHelp(true);
  IQFPushButton *pbMore = new IQFPushButton(this);
  pbMore->setText("More");
  pbMore->setCheckable(true);
  pbMore->setChecked(false);
  pbMore->disableHelp(true);
  connect(pbMore, SIGNAL(toggled(bool)), moreButtonsWidget, SLOT(setVisible(bool)));
  connect(pbFind, SIGNAL(clicked()), this, SLOT(findTextInBrowser()));
  
  IQFLineEdit *leSearch = new IQFLineEdit(editorW);
  leSearch->setObjectName("lineEditSearch");
  leSearch->disableHelp(true);
  IQFPushButton *pbSearch = new IQFPushButton(editorW);
  pbSearch->setIcon(QIcon(ICON_PATH + "search.png"));
  pbSearch->setCheckable(true);
  pbSearch->setSizePolicy(QSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed));
  pbSearch->disableHelp(true);
  connect(pbSearch, SIGNAL(toggled(bool)), pbFind, SLOT(setVisible(bool)));
  connect(pbSearch, SIGNAL(toggled(bool)), this, SLOT(searchToggled(bool)));
  
  QLabel *labelEvalLog = new QLabel(logW);
  labelEvalLog->setText("Evaluation logs");
  
  /* editor layout widgets */
  editorLo->addWidget(labelNaturalText, 0, 0, 1, 2);
  editorLo->addWidget(pbFind, 0, 5, 1, 1);
  editorLo->addWidget(pbSearch, 0, 6, 1, 1);
  editorLo->addWidget(leSearch, 0, 3, 1, 2);
  editorLo->addWidget(naturalBrowser, 1, 0, 4, 7);
  
  previewLo->addWidget(labelPreview);
  previewLo->addWidget(previewTree);
  logLo->addWidget(labelEvalLog);
  logLo->addWidget(logB);
  
  previewTree->setHeaderLabels(QStringList() << "Policy" << "Dir" << "Proto" << "Source IP" << 
    "Dest. IP" << "S.Port" << "D.Port" << "In iface" << "Out iface" << "Stateful" << "Notify"
    << "TCP flags");
  
  connect(pbTree, SIGNAL(clicked()), this, SLOT(slotShowRuleTree()));
  connect(pbEvaluate, SIGNAL(clicked()), this, SLOT(evaluate()));
  connect(pbClear, SIGNAL(clicked()), previewTree, SLOT(clear()));
  connect(pbEvalLog, SIGNAL(toggled(bool)), logW, SLOT(setVisible(bool)));
  connect(pbPreview, SIGNAL(toggled(bool)), previewW, SLOT(setVisible(bool)));
  connect(pbApplySave, SIGNAL(clicked()),  this, SLOT(applyAndSave()));
  connect(clearLogB, SIGNAL(clicked()),  logB, SLOT(clear()));
  connect(logB, SIGNAL(textChanged()), this, SLOT(textModified()));
  
  splitter->setOrientation(Qt::Vertical);
  splitter->setSizes(QList<int>() << 10 << 6 << 6 << 1);
  splitter->addWidget(editorW);
  splitter->addWidget(previewW);
  splitter->addWidget(logW);
  glo->addWidget(splitter, 0, 0, 18, 6);
  glo->addWidget(moreButtonsWidget, 18, 0, 1, 6);
  /* bottom buttons */
  glo->addWidget(pbEvaluate, 19, 0, 1, 1);
  glo->addWidget(pBar, 19, 1, 1, 2);
  glo->addWidget(pbApplySave, 19, 3, 1, 1);
  glo->addWidget(pbTree, 19, 4, 1, 1);
  glo->addWidget(pbMore, 19, 5, 1, 1);
  moreButtonsWidgetLo->addWidget(pbEvalLog);
  moreButtonsWidgetLo->addWidget(clearLogB);
  moreButtonsWidgetLo->addWidget(pbClear);
  moreButtonsWidgetLo->addWidget(pbPreview);
  moreButtonsWidget->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  
  pbEvalLog->setChecked(false);
  pbPreview->setChecked(false);
  logW->setHidden(true);
  previewW->setHidden(true);
  
  pbSearch->setChecked(false);
  pbFind->setHidden(true);
  leSearch->setHidden(true);
  moreButtonsWidget->setHidden(true);
  pbApplySave->setHidden(true);
}

void NaturalWidget::processNaturalText()
{
  bool res;
  QSettings s;
  bool strictSyntaxCheck = s.value("NATURAL_LANGUAGE_STRICT_SYNTAX_CHECK", true).toBool();
  /* force strictSyntaxCheck to false now... - unused - */
  strictSyntaxCheck = false;
  NaturalTextResolverThread *resolver = qobject_cast<NaturalTextResolverThread *>(sender());
  if(resolver)
  {
    NaturalText *nt = resolver->text();
    ServiceProcessor *servProcessor = new ServiceProcessor();
    nt->setCustomProcessor(servProcessor);
    
    nt->startProcessing();
    
    if(nt->error())
      perr("An error occurred in NaturalText->separateSentences(): %s", qstoc(nt->lastError()));
    else
    {
      QList<NaturalSentence> sentences = nt->sentences();
      foreach(NaturalSentence ns, sentences)
	qDebug() << "separate sentences: " << ns << ", ";
      /* conversion */
      NaturalTextToMachine toMachine(nt, this, strictSyntaxCheck);
      connect(&toMachine, SIGNAL(progress(int, int, const QString&)), this, SLOT(updateProgressBar(int, int, const QString&)));
      res = toMachine.convertToMachine();
	QString processedText;
      if(res) /* res == true, conversion succeeded */
      {
	MachineText *mt = toMachine.machineText();
	QList<MachineSentence> machineSentences = mt->machineSentences();
	int i;
	for(i = 0; i < machineSentences.size(); i++)
	{
	  processedText += QString("%1. %2\n").arg(i).arg(machineSentences[i]);
	}
	pinfo("processing machine text...");
	MachineTextToRules *mttor = new MachineTextToRules(*mt, this);
	connect(mttor, SIGNAL(extractionProgress(int, int, const QString&)), this, SLOT(updateProgressBar(int, int, const QString&)));
	mttor->extractRules();
      }
      else
	processedText = QString("There was an error processing the text.\n"
	  "The reported error was: \"%1\"").arg(toMachine.lastErrorMessage());
    }
  }
  
}

/* evaluate natural text, without applying to rule tree.
 * Will call MachineTextToRules::extractRules() to get the rules from the natural text.
 * MachineTextToRules::extractRules() emits a NaturalItemEvent when a natural rule has
 * been successfully created. In event() below, we take the natural item event and we 
 * enqueue it in a QList. The list will be read when applyAndSave() is called.
 */
void NaturalWidget::evaluate()
{
   previewTree->clear();
   /* initialize natural browser error flag */
   naturalBrowser->setHasErrors(false);
   /* clear natural browser: it is not useful to accumulate history ... */
   logB->clear();
   /* clear list of pending natural events */
   d_pendingNaturalEvents.clear();
   
   NaturalText *nt = new NaturalText(naturalBrowser->toPlainText(),
      this);
  NaturalTextResolverThread *resThread = new NaturalTextResolverThread(nt, this);
  connect(resThread, SIGNAL(finished()), this, SLOT(processNaturalText()));
  connect(resThread, SIGNAL(resolutionProgress(int, int, const QString&)), this, 
	   SLOT(updateProgressBar(int, int, const QString&)), Qt::QueuedConnection);
  resThread->start();
}

void NaturalWidget::applyAndSave()
{
  /* new rule items must be appended to the rule tree (in EXTRACTION_END_EVENT) */
  emit applyNaturalRules();
  saveNaturalText();
}

void NaturalWidget::saveNaturalText()
{
  naturalBrowser->save();
}

void  NaturalWidget::popupError(const QString& origin, const QString& msg)
{
  QMessageBox::information(this, origin, msg);
}

void NaturalWidget::appendNaturalText(const QString& s)
{
  QString text;
  text = QString(" %1 ").arg(s);
  naturalBrowser->insertPlainText(text);
}

void NaturalWidget::updateProgressBar(int val, int tot, const QString& txt)
{
  if(val == tot)
    QTimer::singleShot(1000, pBar, SLOT(hide()));
  else
    pBar->show();
  if(tot != pBar->maximum())
  {
    pBar->setMaximum(tot);
  }
  pBar->setText(txt);
  pBar->setValue(val);
  printf("\e[0;33msetto progress a %d su %d\e[0m\n", val, tot);
//   pBar->update();
//   qApp->processEvents();
}

bool NaturalWidget::event(QEvent *e)
{
  if( (e->type() == ERRMESSAGEEVENT || e->type() == WARNMESSAGEEVENT) && (parent() != NULL))
  {
    QPushButton *logB = parent()->findChild<QPushButton *>("Button Log");
    if(logB && !logB->isChecked())
      logB->setChecked(true);
  }
  if(e->type() == NEWITEMEVENT) /* only take the event and insert a copy into the list of pendingNaturalEvents */
  {
    QSettings s;
    NaturalItemEvent* nev = dynamic_cast<NaturalItemEvent *>(e);
    if(nev)
    {
      NaturalSentence naturalSentence = nev->naturalSentence();
      QStringList itemStrings = nev->itemStrings();
      NaturalItemEvent naturalItemEvent(NEWITEMEVENT, nev->policy(), nev->owner(), nev->direction(), 
	itemStrings, naturalSentence);
      /* add a new Natural event to the list of natural events, for future apply and save */
      d_pendingNaturalEvents.push_back(naturalItemEvent);
      NaturalTreeItem* previewItem = new NaturalTreeItem(previewTree, nev);
      previewItem->setIcon(0, QIcon(ICON_PATH + "natural_language.png"));
      return true;
    }
  }
  else if(e->type() == CLEARITEMSEVENT)
  {
    ClearNaturalItemsEvent *cnie =  dynamic_cast<ClearNaturalItemsEvent *>(e);
    if(cnie)
      emit clearNaturalItems();
  }
  else if(e->type() == ERRMESSAGEEVENT)
  {
    ErrorMessageEvent *eme = dynamic_cast<ErrorMessageEvent *>(e);
    if(eme)
      logB->addError(eme->message());
    naturalBrowser->setHasErrors(true);
  }
  else if(e->type() == OKMESSAGEEVENT)
  {
    OkMessageEvent *okme = dynamic_cast<OkMessageEvent *>(e);
    if(okme)
      logB->addOk(okme->message());
  }
  else if(e->type() == WARNMESSAGEEVENT)
  {
    WarningMessageEvent *wme = dynamic_cast<WarningMessageEvent *>(e);
    if(wme)
      logB->addWarning(wme->message());
  }
  else if(e->type() == EXTRACTION_END_EVENT) /* end of processing */
  {
    QPushButton *previewButton, *applySaveButton;
    previewButton = parent()->findChild<QPushButton *>("Button Preview");
    if(!naturalBrowser->hasErrors() && parent() && (previewButton))
      previewButton->setChecked(true);
    if(!naturalBrowser->hasErrors() && parent() && (applySaveButton = parent()->findChild<QPushButton *>("Apply and Save")))
    {
	applySaveButton->setVisible(true);
	/* add new items to the rule tree */
	foreach(NaturalItemEvent nev, d_pendingNaturalEvents)
	  emit newNaturalItem(nev.owner(), nev.policy(),  nev.direction(), nev.itemStrings(), nev.naturalSentence());
    }
    else if(naturalBrowser->hasErrors())
    {
      logB->addError("<strong>No rules have been taken into account and added: correct the errors in the natural text</strong>.");
      /* remove items from the preview in case of error, if present */
      previewTree->clear();
      if(previewButton->isChecked()) /* hide it: no need to show an empty tree */
	previewButton->setChecked(false);
    }
    d_pendingNaturalEvents.clear(); /* remove any rule from the list */
  }
  return QObject::event(e);
}

void NaturalWidget::searchToggled(bool t)
{
  QSettings s;
  if(parent())
  {
    IQFLineEdit *le = parent()->findChild<IQFLineEdit *>("lineEditSearch");
    IQFPushButton *pb = parent()->findChild<IQFPushButton *>("pushButtonFind");
    if(le && pb)
    {
      le->setVisible(t);
      if(t)
      { 
	QString initTxt = s.value("NATURAL_SEARCH_INIT", "type text to find").toString();
	le->setText(initTxt);
	le->selectAll();
	le->setFocus();
	pb->setData(QVariant("Next"));
	naturalBrowser->initSearch();
	pb->setIcon(QIcon(ICON_PATH + "search_doc.png"));
	pb->setText("Find");
      }
    }
  }
}

void NaturalWidget::findTextInBrowser()
{
  QSettings s;
  if(parent())
  {
    IQFLineEdit *le = parent()->findChild<IQFLineEdit *>("lineEditSearch");
    IQFPushButton *pb = parent()->findChild<IQFPushButton *>("pushButtonFind");
    naturalBrowser->setFocus();
    if(le && pb)
    {
      QString txt = le->text();
      s.setValue("NATURAL_SEARCH_INIT", txt);
      if(pb->data().toString() == "Next")
      {
	if(!naturalBrowser->find(txt))
	{
	  pb->setData(QVariant("Previous"));
	  pb->setText("Previous");
	  pb->setIcon(QIcon(ICON_PATH + "back.png"));
	}
	else /* found: can go looking forward */
	{
	  pb->setText("Next"); /* might be left initialized to `Find' */
	  pb->setIcon(QIcon(ICON_PATH + "forward.png"));
	}
      }
      else
      {
	if(!naturalBrowser->find(txt, QTextDocument::FindBackward))
	{
	  pb->setText("Next");
	  pb->setData(QVariant("Next"));
	  pb->setIcon(QIcon(ICON_PATH + "forward.png"));
	}
      }
    }
  }
}

void NaturalWidget::reloadDictAndGrammar()
{
  Dictionary::instance()->reload();
  Grammar::instance()->reload();
}

void NaturalWidget::textModified()
{
  QPushButton *pbApplySave = parent()->findChild<QPushButton *>("Apply and Save");
  if(pbApplySave)
    pbApplySave->setHidden(true);
}



