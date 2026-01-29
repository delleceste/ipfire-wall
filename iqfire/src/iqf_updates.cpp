#include <QHttp>
#include <QSettings>
#include <QDate>
#include <QGridLayout>
#include <QProgressBar>
#include <QTimer>
#include <QStackedWidget>
#include <knotification.h>
#include "iqf_updates.h"
#include "iqf_version.h"
#include "iqfwidgets.h"
#include "iqfire.h"
#include "iqfsystray.h"
#include "iqf_updater.h"

IQFUpdates::IQFUpdates(QWidget *parent) : QWidget(parent)
{
	QSettings s;
	sw = new QStackedWidget(this);
	QWidget *page1 = new QWidget(this);
	QWidget* page2 = new QWidget(this);
	/* setup the widget */
	tb = new IQFTextBrowser(page1);
	bt = new IQFPushButton(page1);
// // 	adminPwdLineEdit = new IQFLineEdit(this);
	
	updButton = new IQFPushButton(page2);
	QGridLayout *lo = new QGridLayout(page1);
	lo->addWidget(tb, 0, 0, 3, 4);
	lo->addWidget(bt, 3, 3, 1, 1);
	lo->addWidget(updButton, 3, 2, 1, 1);
	bt->setText("Cancel");
	tb->setOpenExternalLinks(true);
	/* second page: the console with the updater */
// // 	updaterTerminal = new IQFUpdaterKonsole(page2);
	QGridLayout *lo2 = new QGridLayout(page2);
// // 	lo2->addWidget(updaterTerminal, 0, 0, 3, 4);
	IQFPushButton *backButton = new IQFPushButton(page2);
	lo2->addWidget(backButton, 3, 3, 1, 1);
	backButton->setText("Close");
	
	/* layout for page 1 and 2 */
	QHBoxLayout *hlo = new QHBoxLayout(this);
	hlo->addWidget(sw);
	
	sw->addWidget(page1);
	sw->addWidget(page2);
	
	/* prepare QHttp object and connections */
	http = new QHttp("http://www.giacomos.it", 80, this);
	connect(bt, SIGNAL(clicked()), this, SLOT(abortUpdate()));
	connect(backButton, SIGNAL(clicked()), this, SLOT(close()));
	connect(updButton, SIGNAL(clicked()), this, SLOT(update()));
	connect(http, SIGNAL(requestFinished(int, bool)), this, SLOT(requestDone(int, bool)));
	IQFVersion version;
	currentVersion = version.iqf_version();
	current_version_string = version.iqf_versionString();
	setWindowTitle("iqFirewall: updates");
	setAttribute(Qt::WA_QuitOnClose, false);
	setAttribute(Qt::WA_DeleteOnClose, true);
	setWindowFlags(Qt::Window);
	setWindowIcon(QIcon(ICON_PATH + "get-hot-new-stuff.png"));
	resize(400, 400);
	up2dStatus = 0;
	updButton->setHidden(true);
}

IQFUpdates::~IQFUpdates()
{
  pinfo("deleting updates widget `%s`", qstoc(objectName()));
}

void IQFUpdates::update()
{
	QString address;
	sw->setCurrentIndex(1);
	QRegExp re("<!--download:.*-->", 
		   Qt::CaseSensitive, QRegExp::RegExp2);
	re.setMinimal(true);
	int pos = re.indexIn(html);
	if(pos >  -1)
	{
		address = re.cap(0);
		address.remove("<!--download:").remove("\"-->");
	}

}

void IQFUpdates::lookForUpdates()
{
	QSettings s;
	QDate today, updDay;
	if(s.value("LOOK_FOR_UPDATES", true).toBool())
	{
		today = QDate::currentDate();
		updDay = s.value("NEXT_UPDATE", today).toDate();

		if(updDay <= today)
		{
			/* look for updates */
			downloadVersion();
		}
		/* if it's not time to look for updates, do not do anything */
	}
}

void IQFUpdates::downloadVersion()
{
	QSettings s;
	
	if(s.value("PROXY_ENABLED", false).toBool())
	{
		qDebug() << "setting proxy";
		http->setProxy(s.value("PROXY_HOST", "").toString(),
			       s.value("PROXY_PORT", 8080).toInt(),
				       s.value("PROXY_USER", "").toString(),
					       s.value("PROXY_PASSWORD", "").toString());
	}
	sethostID = http->setHost("www.giacomos.it");
	getID = http->get("/iqfire/version.html");
}

void IQFUpdates::requestDone(int id, bool failed)
{
	QByteArray ba;
	QSettings s;
	int days;
	QString up2dmsg;
	QDate today = QDate::currentDate();
	if(id == getID) /* the request was completed for the get() */
	{
		if(failed)
		{
			setWindowTitle("Error getting up to date info");
			QString error = QString("<html><h3>Error getting information about updates</h3>"
				"<p>The error was \"%1\"</p>").arg(http->errorString());
			error += "<p>Check in the settings of the <em>user interface</em> if you have "
				"correctly setup the <strong>proxy</strong> address and port</p>";
			error += "<ul>To access the configuration window:"
					"<li>go to <strong>settings->Configure the firewall "
					"interface</strong>;</li>"
					"<li>choose the <strong>Updates</strong> tab;</li>"
					"<li><strong>enable</strong> the section "
					"<strong>Http Proxy Settings</strong>;</li>"
					"<li>insert the correct parameters for the "
					"<strong>Proxy address</strong> and <strong>Proxy port</strong>;</li>"
					"<li>eventually insert your <strong>proxy username</strong>"
					" and <strong>password</strong>.</li>"
					"</ul></html>";
			
			tb->setHtml(error);
			up2dmsg = QString("Error retrieving information from the web.\n"
			  "The error was \"%1\"").arg(
			  http->errorString());
// 			  KNotification *notification = new KNotification("GenericNotification");
// 			  notification->setActions(QStringList() << "More Information");
// 			  notification->addContext("systray", "systray");
// 			  notification->setText(up2dmsg);
// 			  connect(notification, SIGNAL(activated(unsigned int)), this, SLOT(show()));
// 			  notification->sendEvent();
		}
		else /* if all ends with success, update the interval */
		{
			setWindowTitle("Software updates");
			ba = http->readAll();
			html = QString(ba);
			up2dStatus = upToDate(html);
			if(up2dStatus > 0)
			{
				tb->setHtml(html);
				up2dmsg = "A new version of the firewall is available.\nClick here to get more information.";
			}
			else if(up2dStatus == 0)/* tell you are up to date */
			{
				up2dmsg =  QString("<html><h3>Your software is up to date</h3>"
				"<p>Your iq<strong>firewall</strong> is up to date.</p>"
				"<ul>The version is:"
				"<li>\"%1\"</li></ul></html>").arg(current_version_string);
				up2dmsg =  QString("Your software is up to date. The version is \"%1\"").arg(current_version_string);
				tb->setHtml(up2dmsg);
				
			}
			else if(up2dStatus == -1)
			{
				QString errMsg;
				errMsg = QString("<html><h3>Unable to find version information</h3>"
						"<p>Sorry, the web document about  "
						" the iq<strong>firewall</strong> version does not "
						" contain information about versions.</p>"
						"<ul>Please contact the author at: "
						"<li><a href=\"mailto:delleceste@gmail.com\""
						"</li></ul></html>");
				tb->setHtml(errMsg);
				up2dmsg = "There was an error in the version file\nClick here for more information.";
			}
			else if(up2dStatus == -2)
			{
				QString errMsg;
				errMsg = QString("<html><h3>Bad iqfirewall version</h3>"
						"<ul>Please contact the author at: "
						"<li><a href=\"mailto:delleceste@gmail.com\""
						"</li></ul></html>");
				tb->setHtml(errMsg);
				up2dmsg = "There was an error in the version file.\nClick here for more information.";
			}
			/* at the end, set the next update date */
			days = s.value("UPDATES_INTERVAL", 5).toInt();
			QDate nextUpdate = today.addDays(days);
			s.setValue("NEXT_UPDATE", nextUpdate);
			s.setValue("LAST_UPDATE", today);
			qDebug() << "nuovo update tra" << days << "giorni, il " <<
				nextUpdate;
// 			KNotification *notification = new KNotification("GenericNotification");
// 			if(up2dStatus != 0)
// 			{
// 			  notification->setActions(QStringList() << "More Information");
// 			  connect(notification, SIGNAL(activated(unsigned int)), this, SLOT(show()));
// 			}
// 			notification->addContext("systray", "systray");
// 			notification->setText(up2dmsg);
// 			notification->sendEvent();	
		}
	}
	else if(id == sethostID)
	{
		if(failed)
		{
			setWindowTitle("Software updates: failed");
			QString error = QString("<html><h3>Error setting up host</h3>"
					"<p>The error was \"%1\"</p></html>").arg(http->errorString());
			tb->setHtml(error);
			http->abort();
			up2dmsg = QString("Error fetching up to date information from the Internet:\n"
			  "%1.\nClick here for more information").arg(http->errorString());
		}
		else
		{
			tb->setHtml("<html><p>Waiting for information from the host..."
				"</p><p>If nothing happens you might have not configured"
				" correctly the network parameters for the <strong>"
				"software updates</strong>.</p>"
				"<ul>To access the configuration:"
				"<li>go to <strong>settings->Configure the firewall "
				"interface</strong>;</li>"
				"<li>choose the <strong>Updates</strong> tab;</li>"
				"<li><strong>enable</strong> the section "
				"<strong>Http Proxy Settings</strong>;</li>"
				"<li>insert the correct parameters for the "
				"<strong>Proxy address</strong> and <strong>Proxy port</strong>;</li>"
				"<li>eventually insert your <strong>proxy username</strong>"
				" and <strong>password</strong>.</li>"
				"</ul></html>");
		}
	}
	bt->setText("Ok");
	bt->disconnect();
	connect(bt, SIGNAL(clicked()), this, SLOT(close()));
	qDebug() << "emetto firewallUpToDate()";
	
	UpdateEvent *ue = new UpdateEvent(this, up2dmsg);
	qApp->postEvent(IQFIREmainwin::instance()->systemTrayIcon(), ue);
}



int IQFUpdates::upToDate(QString &html)
{
	IQFVersion v;
	QString htmlVersion, versionWithoutDots;
	QRegExp versionRegExp = QRegExp("\\(\\d*\\.\\d*\\.\\d*\\)");
	int version = v.iqf_version();
	int upToDateVersion;
	int startIndex, stopIndex;
	if(version == 0)
		return -1;
	if(html.contains(versionRegExp))
	{
		/* +1 and -1 to remove parenthesis */
		startIndex = html.indexOf(versionRegExp) + 1;
		stopIndex = html.lastIndexOf(versionRegExp) - 1;
		qDebug() << "start" << startIndex << " stop" << stopIndex;
		for(int i = startIndex; i < html.length() && html[i] != ')'; i++)
			htmlVersion += html[i];
	}
	else
		return -1; /* version number not present in the html document */
	
	QStringList parts = htmlVersion.split('.');
	/* suppose that the version is like 
	* xx.yy.zz, whit at most 2 version numbers per part.
	*/
	if(parts.size() == 3)
		upToDateVersion = parts[2].toInt() + parts[1].toInt() * 100 + parts[0].toInt() * 10000;
	else
		return -2;
	
	qDebug() << "versione attuale :" << version << ", nuova: " <<  upToDateVersion;

	if(upToDateVersion > version)
		return 1;
	return 0; /* no need updating */
}

void IQFUpdates::abortUpdate()
{
	http->abort();
	if(isVisible())
		hide();
}





