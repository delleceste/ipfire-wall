#include "iqfwidgets.h"
#include "iqf_message_proxy.h"
#include "iqf_utils.h"
#include "iqf_resolver_threads.h"
#include "iqfruletree.h"
#include <QStringList>
#include <QSettings>
#include <QString>
#include <QTimer>
#include <QApplication>
#include <QScrollBar>
#include <qwt_legend_item.h>
#include <qwt_plot_curve.h>
#include <dictionary.h>
#include "resolver_proxy.h"

IQFHelpBrowser *IQFHelpBrowser::_instance = NULL;
IQFInfoBrowser *IQFInfoBrowser::_instance = NULL;

void IQFHelpBrowser::setHtml(QString h)
{
	int scrollValue = verticalScrollBar()->value();
	if(h != "" && h != "Help unavailable")
		IQFTextBrowser::setHtml(h);
	verticalScrollBar()->setValue(scrollValue);
	currentHtml = h;
}

void IQFInfoBrowser::setHtml(QString h)
{
	int scrollValue = verticalScrollBar()->value();
	if(h != "" && h != "Info unavailable")
		IQFTextBrowser::setHtml(h);
	verticalScrollBar()->setValue(scrollValue);
	currentHtml = h;
}


IQFLineEdit::IQFLineEdit(QWidget *p) :  QLineEdit(p), _info(QString()), _help(QString()),
			 _modified(false), _help_disabled(false), _info_disabled(false)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFLineEdit::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	_modified = true;
	if(timer->isActive())
		timer->stop();
	emit widgetLeft();
}

void IQFLineEdit::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	if(_info.isEmpty())
		_info = objectName().remove("lineEdit");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();
}

void IQFLineEdit::updateMessages()
{
	if(!_info_disabled)
		IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	if(!_help_disabled)
		IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}

IQFCheckBox::IQFCheckBox(QWidget *p) : QCheckBox(p), _info(QString()), _help(QString()),
			 _modified(false), _help_disabled(false), _info_disabled(false)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFCheckBox::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	if(_info.isEmpty())
		_info = objectName().remove("checkBox");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();
}

void IQFCheckBox::updateMessages()
{
	if(!_info_disabled)
		IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	if(!_help_disabled)
		IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}

void IQFCheckBox::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	_modified = true;
	if(timer->isActive())
		timer->stop();
	emit widgetLeft();
}

IQFComboBox::IQFComboBox(QWidget *p) :  QComboBox(p), _info(QString()), _help(QString()),
			 _modified(false), _help_disabled(false), _info_disabled(false)
{
	
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFComboBox::setEntry(QString &s)
{
	int i;
	for(i = 0; i < count(); i++)
		if(itemText(i) == s)
			break;
	if(i == count()) /* no item found with text s */
		insertItem(i, s);
	qDebug() << "setto current index" << i << "text: " << itemText(i);
	setCurrentIndex(i);
}

void IQFComboBox::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	if(_info.isEmpty())
		_info = objectName().remove("comboBox");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();
}

void IQFComboBox::updateMessages()
{
	if(!_info_disabled)
		IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	if(!_help_disabled)
		IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}

void IQFComboBox::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	_modified = true;
	if(timer->isActive())
		timer->stop();
	emit widgetLeft();
}

IQFSpinBox::IQFSpinBox(QWidget *p) :  QSpinBox(p), _info(QString()), _help(QString()),
		       _modified(false), _help_disabled(false), _info_disabled(false)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFSpinBox::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	_modified = true;
	if(timer->isActive())
		timer->stop();
	emit widgetLeft();
}

void IQFSpinBox::updateMessages()
{
	if(!_info_disabled)
		IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	if(!_help_disabled)
		IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}


void IQFSpinBox::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	if(_info.isEmpty())
		_info = objectName().remove("spinBox");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();
}

IQFDoubleSpinBox::IQFDoubleSpinBox(QWidget *p) :  QDoubleSpinBox(p), _info(QString()), _help(QString()),
		       _modified(false), _help_disabled(false), _info_disabled(false)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFDoubleSpinBox::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	_modified = true;
	if(timer->isActive())
		timer->stop();
	emit widgetLeft();
}

void IQFDoubleSpinBox::updateMessages()
{
	if(!_info_disabled)
		IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	if(!_help_disabled)
		IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}


void IQFDoubleSpinBox::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	if(_info.isEmpty())
		_info = objectName().remove("spinBox");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();
}

IQFRadioButton::IQFRadioButton(QWidget *p) :  QRadioButton(p), _info(QString()), _help(QString()),
			       _modified(false), _help_disabled(false), _info_disabled(false)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFRadioButton::updateMessages()
{
	if(!_info_disabled)
		IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	qDebug() << "infoDisabled: " << _info_disabled;
	if(!_help_disabled)
		IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}


void IQFRadioButton::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	if(_info.isEmpty())
		_info = objectName().remove("radioButton");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();
}

void IQFRadioButton::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	_modified = true;
	if(timer->isActive())
		timer->stop();
	emit widgetLeft();
}


IQFPushButton::IQFPushButton(QWidget *p) :  QPushButton(p), _info(QString()),
			     _help(QString()), _help_disabled(false), _info_disabled(false)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFPushButton::updateMessages()
{
	if(!_info_disabled)
		IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	if(!_help_disabled)
		IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}

void IQFPushButton::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	if(timer->isActive())
		timer->stop();
	emit widgetLeft();
}

void IQFPushButton::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	if(_info.isEmpty())
		_info = objectName().remove("pushButton");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();
}



IQFLegendItem::IQFLegendItem(QWidget *parent, QwtPlotCurve* associated_curve) :
		QwtLegendItem(parent), assoc_curve(associated_curve)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	connect(this, SIGNAL(scroll(int)), IQFInfoBrowser::infoBrowser(), SLOT(scroll(int)));
	connect(this, SIGNAL(scroll(int)), IQFHelpBrowser::helpBrowser(), SLOT(scroll(int)));
}

void IQFLegendItem::updateMessages()
{
	IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo(_info));
	IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(_help));
}


void IQFLegendItem::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	if(_info.isEmpty())
		_info = objectName().remove("plotItem");
	if(_help.isEmpty())
		_help = objectName();
	timer->start();

}

void IQFLegendItem::leaveEvent(QEvent *e)
{
	Q_UNUSED(e);
	
	IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo("stats"));
	IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp("stats"));
}

IQFSplitter::IQFSplitter(QWidget *p) : QSplitter(p)
{
	been_moved = false;
	connect(this, SIGNAL(splitterMoved(int, int)), this, 
		SLOT(IQFSplitterMoved(int, int)));
}

/* Instances of IQFHelpBrowser and IQFInfoBrowser are initialized
 * to NULL at the beginning of this file.
 */

/* Calls IQFHelpBrowser() passing NULL: you must reparent 
 * your widget.
 */
IQFHelpBrowser* IQFHelpBrowser::helpBrowser()
{
	if(_instance == NULL)
		return (_instance = new IQFHelpBrowser(0) );
	else
		return _instance;
}

IQFInfoBrowser* IQFInfoBrowser::infoBrowser()
{
	if(_instance == NULL)
		return (_instance = new IQFInfoBrowser(0) );
	else
		return _instance;
}

IQFHelpBrowser::IQFHelpBrowser(QWidget* parent) : IQFTextBrowser(parent)
{
	setType(IQFTextBrowser::Help);
	setObjectName("iqfire-wall Help Browser");
}

IQFHelpBrowser::~IQFHelpBrowser()
{
	
}

IQFInfoBrowser::IQFInfoBrowser(QWidget* parent) : IQFTextBrowser(parent)
{
	setType(IQFTextBrowser::Info);
	setObjectName("iqfire-wall Info Browser");
}

IQFInfoBrowser::~IQFInfoBrowser()
{
	
}

IQFNavigationPanel::IQFNavigationPanel(QWidget *parent) : QTextBrowser(parent)
{
	setObjectName("iqfire-wall Navigation panel text browser");
}
		
void IQFNavigationPanel::setSource( const QUrl & name )
{
	if(name.toString() == "console")
		emit changePage(0);
	else if(name.toString() == "stats")
		emit changePage(4);
	else if(name.toString() == "tree")
		emit changePage(3);
	else if(name.toString() == "view")
		emit changePage(6);
	else if(name.toString() == "pendingRules")
		emit changePage(5);
	else if(name.toString() == "config" || name.toString() == "consoleConfig")
		emit changePage(2);
	else if(name.toString() == "notifiedPackets" )
		emit changePage(1);
	else if(name.toString() == "manual")
		emit changePage(8);
	else if(name.toString() == "silent")
		emit silentModality(true);
	else if(name.toString() == "verbose")
		emit silentModality(false);
	else if(name.toString() == "showHelp")
		emit showHelp(true);
	else if(name.toString() == "showInfo")
		emit showInfo(true);
	
}

IQFStackedWidget::IQFStackedWidget(QWidget* parent) : QStackedWidget(parent)
{
	QSettings s;
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	connect(timer, SIGNAL(timeout()), this, SLOT(updateMessages()));
	/* initialize the enable flag for the info update on each page, if needed */
	infoEnabledForPage[0] = true;
	infoEnabledForPage[1] = true;
	infoEnabledForPage[2] = true;
	/* ... */
}
QSize IQFStackedWidget::minimumSizeHint() const
{ 
	return minimumSize() + QSize(130, 0);
}

void IQFStackedWidget::enterEvent(QEvent *e)
{
	timer->start();
	QWidget::enterEvent(e);
}

void IQFStackedWidget::leaveEvent(QEvent *e)
{
	if(timer->isActive())
		timer->stop();
	QWidget::enterEvent(e);
}

void IQFStackedWidget::updateMessages()
{
	setInfoAndHelpForPage(currentIndex(), true);
}

void IQFStackedWidget::setInfoAndHelpForPage(int page, bool calledByTimer)
{
	/* if you want to disable info updates for some page, insert the couple 
	 * <int page, bool enable> in the infoEnabledForPage map, as done in the 
	 * examples for case 0, 1 and 2.
	 * The map is public, so the caller can easily insert the page and the
	 * boolean to enable/disable the info updates. If needed, an  analogue 
	 * map can be created for help updates. The first need for this object 
	 * arose from the need to avoid updates for the info console when the 
	 * filter is active.
	 */
	
	/* if calledByTimer is true, then setInfoAndHelpForPage has been called
	 * by the timer which refreshes help and info browser.
	 * In this case, not all the info must be updated: that's the case of the
	 * rule tree or the filter view, where the info widget is dedicated to
	 * the summary of a rule/the filter.
	 */
	switch(page)
	{
		case 0:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("console"));
			if(infoEnabledForPage[0]) /* when the filter view is active, do not refresh */
				IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("console"));
			break;
		case 1:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("notified"));
			if(infoEnabledForPage[1])
				IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("notified"));
			break;
			
		case 2:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("filterView"));
			if(!calledByTimer && infoEnabledForPage[2])
				IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("filterView"));
			break;
		case 3:
// 			if(IQFRuleTree::itemSelected())
// 				qDebug() << "items selected in ruleTree: not updating help";
// 			else
// 			{
				IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("ruleTree"));
				if(!calledByTimer)
					IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("ruleTree"));
// 			}
			break;	
		case 4:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("stats"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("stats"));
			break;	
		case 5:
			 /* natural language: we do not want it to change on mouse enter event because 
			* the user has to be able to navigate the dictionary/grammar help while editing
			* the text. 
			*/
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo(QString("natural_language_%1").arg(Dictionary::instance()->language())));
			break;
		case 6:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("pendingRules"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("pendingRules"));
			break;
					
		case 7:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("ruleView"));
// 			if(!calledByTimer)
				IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("ruleView"));
			break;
		case 8:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("config"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("config"));
			break;
		case 9:
			IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("manualWidget"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("manualWidget"));
			break;
		case 10:
		  IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("stateTables"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("stateTables"));
			break;
		case 11:
		  IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("snatTables"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("snatTables"));
			break;
		case 12:
		  IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("dnatTables"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("dnatTables"));
			break;
		case 13:
		  IQFHelpBrowser::helpBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getHelp("kmemUsage"));
			IQFInfoBrowser::infoBrowser()->
					setHtml(IQFMessageProxy::msgproxy()->getInfo("kmemUsage"));
			break;
	}
}

IQFProgressBar::IQFProgressBar(QWidget *parent) : QProgressBar(parent)
{
	setHidden(true);
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(2500);
	connect(timer, SIGNAL(timeout()), this, SLOT(hide()));
}
	
void IQFProgressBar::setProgress(int value)
{
	if(value > 0 && value < maximum())
	{
		if(isHidden())
			setHidden(false);
		qApp->processEvents();
	}
	else
	{
		timer->start(); /* will hide the progressbar */
	}
	setValue(value);
// 	qDebug() << "setto value a " << value << "su un massimo di " << maximum();
}


