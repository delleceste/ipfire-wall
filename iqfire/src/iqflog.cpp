#include "iqflog.h"
#include "iqfire.h"
#include "colors.h"
#include "qtextline_formatter.h" /* for the color codes */
#include <QDateTime>


Log* Log::_instance = NULL;

Log* Log::log(QWidget* parent)
{
	if(_instance == NULL)
		return (_instance = new Log(parent) );
	else
		return _instance;
}

Log::Log(QWidget *parent) : QWidget(parent)
{
	text = new QTextBrowser(this);
	buttonclose = new QPushButton("&Close", this);
	buttonclear = new QPushButton("&Clear", this);
	grid = new QGridLayout(this);
	grid->addWidget(text, 0, 0, 6, 6);
	grid->addWidget(buttonclose, 6, 5, 1, 1);
	grid->addWidget(buttonclear, 6, 4, 1, 1);
	
	text->setReadOnly(true);
	text->setAcceptRichText(true);
	connect(buttonclose, SIGNAL(clicked()), this, SLOT(closeWindow()));
	connect(buttonclear, SIGNAL(clicked()), this, SLOT(initBrowser()));
	initBrowser();
}

Log::~Log()
{

}

void Log::initBrowser()
{
  text->clear();
  text->append(TR("Log console created."));
  QString html;
	html +=  "<style type=\"text/css\" rel=\"stylesheet\">"
			"p{ display:block; font-family:\"Tahoma sans-serif sans\"; "
			"text-align:justify; font-weight:bold; color:green;} </style>";

	text->setHtml(html);
}

	
void Log::appendOk(QString msg)
{
	message(msg);
	Ok();
}
	
	
void Log::appendFailed(QString msg)
{
	text->setFontWeight(text->fontWeight() + 2);
	text->setTextColor(KDARKRED);
	text->insertHtml("<strong>!</strong> ");
	text->setTextColor(Qt::black);
	message(msg);
	text->insertHtml("  <span>[");
	text->setTextColor(KDARKRED);
	text->insertHtml("<strong>ERROR</strong>");
	text->setTextColor(Qt::black);
	text->insertHtml("]</span><br/>\n");
	text->setFontWeight(text->fontWeight() - 2);
	emit somethingHasFailed();
}
	
	
void Log::appendNumber(QString message, int n)
{
	Q_UNUSED(message);
	Q_UNUSED(n);
}
	
	
void Log::appendTwoStrings(QString message, QString result)
{
	Q_UNUSED(message);
	Q_UNUSED(result);
}
	
	
void Log::appendMsg(QString message)
{
	text->insertHtml(QString("\n<cite>%1</cite> : ").arg(QDateTime::currentDateTime().toString("ddd MMM yy hh:mm:ss")));
	text->insertHtml(QString("<span>%1</span>").arg(message));
}
	
void Log::message(QString message)
{
	text->insertHtml(QString("\n<cite>%1</cite> : ").arg(QDateTime::currentDateTime().toString("ddd MMM yy hh:mm:ss")));
	text->insertHtml(QString("<span>%1</span>").arg(message));
}
	
	
void Log::Ok()
{
	text->setTextColor(Qt::black);
	text->insertHtml("<span>[");
	QColor green(KDARKGREEN);
	text->setTextColor(green);
	text->insertHtml("<strong>OK</strong>");
	text->setTextColor(Qt::black);			
	text->insertHtml("]</span><br/>\n");
}
	
bool Log::somethingFailed()
{
	if(something_failed)
	{
		/* When asked if something failed, say yes
		 * if something failed, but then reset the 
		 * something_failed to false.
		 */
		something_failed = false;
		return true;
	}
	return false;
}
	
void Log::Failed()
{
	text->setTextColor(Qt::black);
	text->insertHtml("\t<span>[");
	text->setTextColor(KDARKRED);
	text->setFontWeight(text->fontWeight() + 2);
	text->insertHtml("<strong>FAILED</strong>");
	text->setFontWeight(text->fontWeight() - 2);
	text->setTextColor(Qt::black);
	text->insertHtml("]</span><br/>\n");
	emit somethingHasFailed();
	
}	
	
void Log::closeWindow()
{
	emit widgetClosed();
}



