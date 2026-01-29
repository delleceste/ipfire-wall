#include "iqf_text_browser.h"
#include "resolver_proxy.h"
#include "iqf_message_proxy.h"
#include <QSettings>
#include <QtDebug>
#include <QScrollBar>
#include <naturalHelpRetriever.h>
#include <dictionary.h>


IQFTextBrowser::IQFTextBrowser(QWidget *par) : QTextBrowser(par)
{
	QSettings s;
	QStringList paths = s.value("BROWSER_PATHS",BROWSER_DEFAULT_PATHS).
			toStringList();
	setSearchPaths(paths);
	_type = Info;
}

void IQFTextBrowser::clickFromInfoLink(const QUrl& url)
{
	QString qsurl = url.toString();
	if(_type == IQFTextBrowser::Help && qsurl.startsWith("browserHelp://natural_language"))
	{
		qsurl = qsurl.remove("browserHelp://");
		qsurl = QString("natural_language_%1").arg(Dictionary::instance()->language());
		setHtml(IQFMessageProxy::msgproxy()->getHelp(qsurl));
	}
	else if(_type == IQFTextBrowser::Help && qsurl.startsWith("browserHelp://"))
	{
		qsurl = qsurl.remove("browserHelp://");
		setHtml(IQFMessageProxy::msgproxy()->getHelp(qsurl));
	}
}

void IQFTextBrowser::processAction(QString action)
{
	qDebug() << "processAction()" << action;
	QString toResolve;
	IQFResolverProxy *resolver = IQFResolverProxy::resolver();
	/* resolver is SIGNAL/SLOT connected in the TextBrowser constructor */
	if(action.startsWith("action://resolve"))
	{
		action.remove("action://resolve");
		d_currentNumericResolution = action;	
		resolver->resolve(action);
	}
	else if(action.startsWith("action://naturalhelp/"))
	{
	  action.remove("action://naturalhelp/");
	  NaturalHelpRetriever r(action);
	  setHtml(r.getHelp());
	}
	else if(action.startsWith("action://naturallanguage_appendtext/"))
	{
	  QString textToAppend = action.remove("action://naturallanguage_appendtext/");
	  emit appendNaturalTextFromClick(textToAppend);
	}
}

void IQFTextBrowser::resolutionUpdate(const QString &unres, const QString& type, const QString& res)
{
	printf("\e[1,36mresolution update\e[0m\n");
	QString newHtml, s;
	if(unres == d_currentNumericResolution.remove(type)) /* the slot is the correct one */
	{
		s = res;
		/* the associated data must contain the sip we wanted to update,
		 * to be sure the user hasn't changed rule
		 */
		if(currentHtml.contains(QString("action://resolve%1%2").arg(type).arg(unres)))
		{
			QRegExp re(QString("<a href=\"action://resolve%1%2.*</a>").arg(type).arg(unres), 
				Qt::CaseSensitive, QRegExp::RegExp2);
			re.setMinimal(true);
			newHtml += QString(" <strong class=\"resolved\">%1</strong>").arg(s);
			currentHtml.replace(re, newHtml);
			setHtml(currentHtml);
		}
		else
			qDebug()<< objectName()  << "current HTML non contiene " << QString("action://resolve%1%2").arg(type).arg(unres);
	}
	else
		qDebug()<< objectName()  << "resolutionUpdate is not for me!" << d_currentNumericResolution << unres;
}

void IQFTextBrowser::setSource(const QUrl &name)
{
	qDebug() << "setSource()" << name;
	if(name.toString().contains("file://"))
		QTextBrowser::setSource(name);
	else if(name.toString().contains("action://"))
		processAction(name.toString());
	else
		qDebug() << name << " no actions associated.";
}

void IQFTextBrowser::scroll(int d)
{
	QScrollBar *sb = verticalScrollBar();
	sb->setValue(sb->value() - d/8);
}

