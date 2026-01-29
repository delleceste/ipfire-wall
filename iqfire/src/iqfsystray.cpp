#include <QVector>
#include <QSettings>
#include <QString>
#include <QtDebug>
#include <QTimer>
#include <QPaintEngine>
#include <QPixmap>
#include <QDateTime>
#include <QMainWindow>
#include <QTreeWidgetItem>
#include <QLinearGradient>
#include <QPainterPathStroker>
#include <klocalizedstring.h>

#include <knotification.h>
/* for sin() */
#include <math.h>

#include "iqf_rulematch_set.h"
#include "iqf_notifier_widget.h"

#include "iqflog.h"
#include "iqfpopup_notifier.h"
#include "ignored_packets_set.h"
#include "iqfsystray.h"
#include "iqf_utils.h"
#include "iqfstats_proxy.h"
#include "iqf_updates.h"

#include <ipfire_structs.h>
#include <macros.h>
#include "iqfire.h" /* for ICON_PATH */


extern "C"
{
	int check_stats(struct netlink_stats* ns, const ipfire_info_t* msg);
	int print_packet(const ipfire_info_t *pack, 
			 const struct ipfire_servent* ipfi_svent,
    		const ipfire_rule_filter *filter);
	int print_lostpack_info(const struct  netlink_stats* nls);
	int get_user_info(int type, char* info);
}
// IQFIcon::IQFIcon(QString path) : QIcon(path)
// {
// 	
// }
// 
// IQFPaintDevice::IQFPaintDevice() : QPaintDevice()
// {
// 	pengine = new QPaintEngine(QPaintEngine::BrushStroke | QPaintEngine::PaintOutsidePaintEvent);
// }
// 
// QPaintEngine* IQFPaintDevice::paintEngine() const
// {
// 	return pengine;
// }



IQFNotifierThread::IQFNotifierThread(QObject *p) : QThread(p)
{
	nfcontrol = IQFNetlinkControl::instance();
	iqflog = Log::log();

	command enable_notifier;
	memset(&enable_notifier, 0, sizeof(command));
	
	if(nfcontrol != NULL)
	{
		enable_notifier.cmd = START_NOTIFIER;
		if(nfcontrol->SendCommand(&enable_notifier) < 0)
		{
			//iqflog->appendFailed("IQFNotifierThread::IQFNotifierThread():"
			//		"failed to enable the notifier thread!");
			qDebug() << "IQFNotifierThread::IQFNotifierThread():failed to enable the notifier thread!";
		}
		nh_notifier = alloc_netl_handle(NETLINK_IPFI_GUI_NOTIFIER);
		
	}	
}

IQFNotifierThread::~IQFNotifierThread()
{
	printf("\e[1;32m*\e[0m closing notifier communication link.. ");
	nh_notifier = netl_free_handle(nh_notifier);
	printf("\e[1;32mOk\e[0m.\n");
}

void IQFNotifierThread::run()
{
	int bytes_read;
	int quiet = 0;
	ipfire_info_t* mes_from_kern;
	pinfo("notifier thread started");
	memset(&nlstats, 0, sizeof(struct netlink_stats) );
	qRegisterMetaType<ipfire_info_t>();
	while(1)
	{
		mes_from_kern = (ipfire_info_t *) malloc(sizeof(ipfire_info_t));

		if( (bytes_read = read_from_kern(nh_notifier, (unsigned char*) mes_from_kern, 
		     sizeof(ipfire_info_t) ) ) < 0)
		{
			libnetl_perror(TR( "listener(): error getting message from kernel!\n"));
			/* Go on reading, do not exit. */
		}
		else if(bytes_read == 0)
		{
			printf("read 0 bytes!\n");
		}
		else
		{
			if(mes_from_kern->exit)
				break;
			if(quiet == 0)
			{
				emit newNotification(mes_from_kern);
				//print_packet(&mes_from_kern, NULL, NULL);	
			}
		}
	}
}

int IQFSysTray::get_kernel_stats_light()
{
	IQFStatsProxy *statsp = IQFStatsProxy::statsProxy();
	memset(&kstats, 0, sizeof(kstats));
	
	if(statsp)
		statsp->getStatsLight(&kstats);
	else 
		return -1;
	
	return 0;
}

IQFSysTray::~IQFSysTray()
{
	if(notifier != NULL && notifier->isRunning())
	{
		printf("\e[1;32m*\e0m waiting for notifier to exit...\t");
		notifier->wait();
		printf("\e[1;32mOk\e[0m.\n");
		delete notifier;
	}
	if(popup != NULL)
	{
// 		ret = popup->saveIgnoredPackets();
// 		if(ret < 0)
// 			QMessageBox::information(0, "Error", "Error saving the ignored packet list!");
// 		else
// 			qDebug() << "Saved " << ret << " packets to ignore";
		delete popup;
	}
	
}

void IQFSysTray::createMenu()
{
	QSettings s;
	IQFIREmainwin *mainWindow = qobject_cast<IQFIREmainwin *>(parent());
	if(mainWindow == NULL)
	{
		QMessageBox::critical(0, "Error: parent null or not mainWin!",
			"Error: the parent is not a mainWindow object!\n"
			"Cannot create the system tray menus!\n");
		return;
	}
	QMenu* trayIconMenu = new QMenu(mainWindow);

	/* VIEW actions */
	QMenu *viewMenu = new QMenu("View...", trayIconMenu);
	
	QAction *naturalLanguage = viewMenu->addAction(QIcon(ICON_PATH + "natural_language.png"),
			"Natural Language", parent(), SLOT(showNaturalLanguage()));
	connect(naturalLanguage, SIGNAL(triggered()), parent(), SLOT(show()));
	
	QAction *viewConsole = viewMenu->addAction(QIcon(ICON_PATH + "console.png"),
			"Console", parent(), SLOT(showPageConsole()));
	connect(viewConsole, SIGNAL(triggered()), parent(), SLOT(show()));
	QAction *viewTree = viewMenu->addAction(QIcon(ICON_PATH + "ruletree.png"),
			"Rule tree", parent(), SLOT(showRuleTree()));
	connect(viewTree, SIGNAL(triggered()), parent(), SLOT(show()));
	QAction *viewStats = viewMenu->addAction(QIcon(ICON_PATH + "stats.png"),
			"Statistics", parent(), SLOT(showStats()));
	connect(viewStats, SIGNAL(triggered()), parent(), SLOT(show()));
	
	QAction *viewPending = viewMenu->addAction(QIcon(ICON_PATH + "pending_rules.png"),
			"Packets waiting for auth", parent(), SLOT(showPendingRules()));
	connect(viewPending, SIGNAL(triggered()), parent(), SLOT(show()));
	
	QAction *viewNotified = viewMenu->addAction(QIcon(ICON_PATH + "notified.png"),
			"Notified packet list", parent(), SLOT(showNotifiedPackets()));
	connect(viewNotified, SIGNAL(triggered()), parent(), SLOT(show()));
	
	QAction *configFilter = viewMenu->addAction(QIcon(ICON_PATH + "filter.png"),
			"Configure a filter view", parent(), SLOT(showConsoleSettings()));
	connect(configFilter, SIGNAL(triggered()), parent(), SLOT(show()));
	
	QAction *viewMan = viewMenu->addAction(QIcon(ICON_PATH + "tip.png"),
			"Firewall manual", parent(), SLOT(showManual()));
	connect(viewMan, SIGNAL(triggered()), parent(), SLOT(show()));
	
	/* end of view actions */
	trayIconMenu->addMenu(viewMenu);
	trayIconMenu->addSeparator();

	/* Popups actions: checkable and to synchronize with settings widget */
	QMenu *popupsMenu = new QMenu("Popups...", trayIconMenu);
	
	matchingPackets = new QAction( "Unknown connections", trayIconMenu);
	matchingPackets->setCheckable(true);
	connect(matchingPackets, SIGNAL(toggled(bool)), this, SLOT(enablePopupNotifier(bool)));
	connect(matchingPackets,  SIGNAL(toggled(bool)), parent(), SLOT(triggerReloadSettings(bool)));
	popupsMenu->addAction(matchingPackets);
	
	notifierPopup = new QAction("Matching packets", trayIconMenu);
	notifierPopup->setCheckable(true);
	connect(notifierPopup,  SIGNAL(toggled(bool)), this, SLOT(enablePopupOnMatchNotifier(bool)));
	connect(notifierPopup,  SIGNAL(toggled(bool)), parent(), SLOT(triggerReloadSettings(bool)));
	popupsMenu->addAction(notifierPopup);
	
	trayIconMenu->addMenu(popupsMenu);
	trayIconMenu->addSeparator();

	/* system tray animation: checkable and to synchronize with settings widget */
	animationAct = new QAction("Systray animation", trayIconMenu);
	animationAct->setCheckable(true);
	connect(animationAct, SIGNAL(toggled(bool)),  this, SLOT(setAnimationEnabled(bool)));
	connect(animationAct,  SIGNAL(toggled(bool)), parent(), SLOT(triggerReloadSettings(bool)));
	trayIconMenu->addAction(animationAct);
	
	trayIconMenu->addSeparator();

	/* minimize/restore actions */
	QAction *minimizeAction = new QAction(tr("Mi&nimize"), trayIconMenu);
        connect(minimizeAction, SIGNAL(triggered()), parent(), SLOT(hide()));	
        QAction *restoreAction = new QAction(tr("&Restore"), trayIconMenu);
        connect(restoreAction, SIGNAL(triggered()), parent(), SLOT(show()));
	/* quit action */
        QAction *quitAction = new QAction(tr("&Quit"), trayIconMenu);
        connect(quitAction, SIGNAL(triggered()), parent(), SLOT(QuitApplication() ) );

        trayIconMenu->addSeparator();
	/* icons */
        minimizeAction->setIcon(QIcon((QString(ICON_PATH) + "minimize.png")));
        restoreAction->setIcon(QIcon((QString(ICON_PATH) + "view_tree.png")) );
        quitAction->setIcon(QIcon((QString(ICON_PATH) + "exit.png")) );
        
	trayIconMenu->addAction(minimizeAction);
        trayIconMenu->addAction(restoreAction);

	trayIconMenu->addSeparator();
        
	trayIconMenu->addAction(quitAction);
        setContextMenu(trayIconMenu);
	initCheckableMenuActions();
}

void IQFSysTray::initCheckableMenuActions()
{
	QSettings s;
	matchingPackets->setChecked(s.value("POPUP_ENABLE", true).toBool());
	notifierPopup->setChecked(s.value("POPUP_ON_MATCH", true).toBool());
	animationAct->setChecked(s.value("ANIMATE_SYSTRAY", true).toBool());
}

IQFSysTray::IQFSysTray(QObject *par) : QSystemTrayIcon(par)
{
	QSettings s;
	timer = NULL;
	popup = NULL;
	d_alpha = s.value("SYSTRAY_ALPHA_CHANNEL", 127).toInt();
	memset(&kstats, 0, sizeof(kstats));

	refresh_no = 0;
	mean_acc = mean_den = last_acc = last_den = 0;
	delta_acc_sum = delta_den_sum = 0;
	last_delta_acc_height = 0;
	last_delta_den_height = 0;
	last_deltaAlphaAcc = last_deltaAlphaDen = 0;

	redColor = QColor(KDARKRED);
	redColor.setAlpha(d_alpha);
	greenColor = QColor(KDARKGREEN);
	greenColor.setAlpha(d_alpha);
	
	nfcontrol = IQFNetlinkControl::instance();
	iqflog = Log::log();
	
	/* Initialize last_acc and last_den */
	if(get_kernel_stats_light() >=0)
	{
		last_acc = kstats.allowed;
		last_den = kstats.blocked;
	}
	
	/* The timer that refreshes the statistics and the icon */
	timer = new QTimer(this);
	timer->setSingleShot(false);
	timer->setInterval(s.value("SYSTRAY_REFRESH_TIMEOUT_MILLIS", 800).toInt());
	
	circularGauge = s.value("ICON_CIRCULAR_GAUGE", true).toBool();

	connect(timer, SIGNAL(timeout()), this, SLOT(refreshIcon()));
	
	/* Create the icon */
	if(getuid() != 0)
		pix = new QPixmap(ICON_PATH + "ipfire.png");
	else /* a red background icon for root! */
		pix = new QPixmap(ICON_PATH + "ipfire-root.png");
	
	setIcon(QIcon(*pix));
	
	animation = s.value("ANIMATE_SYSTRAY", true).toBool();
	mean_adjust_factor = s.value("SYSTRAY_MEAN_ADJUST_FACTOR", 2.5).toDouble();
	arrowsEnabled = s.value("SYSTRAY_ARROWS_ENABLED", true).toBool();
	blockNeedleLen = s.value("SYSTRAY_BLOCK_NEEDLE_LEN", 0.8).toDouble();
	allowNeedleLen = s.value("SYSTRAY_ALLOW_NEEDLE_LEN", 1.0).toDouble();
	
	if(animation)
	{
		timer->start();
	}
	
	notifier = new IQFNotifierThread(this);
	toNotifySet = new IQFRuleMatchSet();
	
	nwidget = new IQFNotifierWidget(0);
	
	qRegisterMetaType<ipfire_info_t>();
	connect(notifier, SIGNAL(newNotification(ipfire_info_t*)), this, SLOT(notify(ipfire_info_t*)),
	       Qt::QueuedConnection);
	
	notifier->start();
	popup = NULL;

	if(popup == NULL)
	{
		popup = new IQFPopup(0);
		connect(popup, SIGNAL(popupsDisabled()), this, SLOT(emitPopupNotifierDisabled()));
	}
	if(popup->isPopupEnabled())
	{
		IgnoredPacketsSet *ign_set = IgnoredPacketsSet::instance();
		
		if(ign_set->loadingFailed())
			showMessage("Error opening file", QString("Error opening the file in read mode"
					"\nwhile trying to load the packets to ignore for the popup."));
	}
	
	/* call this _after_ the creation of the timer and the popup */
	createMenu();
	updateToolTip();
	connect(IQFStatsProxy::statsProxy(), SIGNAL(statsUpdated()), this, SLOT(updateToolTip()));
}

void IQFSysTray::showMessage(const QString & title, const QString & message, 
			MessageIcon icon, int millisecondsTimeoutHint)
{
  disconnect(this, SIGNAL(messageClicked()));
//   KNotification *notification = new KNotification("GenericNotification");
//   notification->setActions(QStringList() << "ok");
//   notification->addContext("systray", "systray");
//   notification->setText(message);
//   notification->sendEvent();
  QSystemTrayIcon::showMessage(title, message, icon, millisecondsTimeoutHint); 
}

void IQFSysTray::setAlpha(int a)
{
  QSettings s;
  s.setValue("SYSTRAY_ALPHA_CHANNEL", a);
  d_alpha = a;
  redColor.setAlpha(a);
  greenColor.setAlpha(a);
}

void IQFSysTray::enableTimer(bool en)
{
	QSettings s;
	if(timer && !en)
	{
		if(timer->isActive())
			timer->stop();
	}
	else if(timer)
	{
		if(!timer->isActive())
		{
			timer->setInterval(s.value("SYSTRAY_REFRESH_TIMEOUT_MILLIS", 800).toInt());
			timer->start();
		}
	}	
}

void IQFSysTray::setAnimationEnabled(bool enabled)
{
	QSettings s;
	animation = enabled;
	s.setValue("ANIMATE_SYSTRAY", enabled);
	if(timer && timer->isActive() && !enabled)
	{
		timer->stop();
		if(pix != NULL) /* clear the rects eventually drawn */
			setIcon(QIcon(*pix));
	}
	if(timer && !timer->isActive() && enabled)
	{
		timer->setInterval(s.value("SYSTRAY_REFRESH_TIMEOUT_MILLIS", 800).toInt());
		timer->start();
	}
}

int  IQFSysTray::animationSpeed()
{
	QSettings s;
	if(timer && timer->isActive())
		return s.value("SYSTRAY_REFRESH_TIMEOUT_MILLIS", 800).toInt();
	else
		return -1;
}

void IQFSysTray::changeTimerTimeout(int millis)
{
	if(timer && (millis != timer->interval()))
	{
		if(timer->isActive())
		{
			timer->stop();
			timer->setInterval(millis);
			timer->start();
		}
		else if(timer)
			timer->setInterval(millis);
	}	
}

void IQFSysTray::notify(ipfire_info_t *info)
{
	int popupw = 370;
	int popuph = 160;
	int notifw = 245;
	int notifh = 155;
	if(popup->isPopupOnMatchEnabled() && info->notify)
	{
		IQFRuleMatch *rm = new IQFRuleMatch(info);
		if(toNotifySet->notRecentlyShown(rm))
		{
			toNotifySet->addEntry(rm);
			QStringList itemSL;
			/* Prepend the date/time to the string list */
			itemSL << QDateTime::currentDateTime().toString();
			itemSL << rm->stringRepresentation();
			QTreeWidgetItem *notifyItem = new QTreeWidgetItem(itemSL);
			emit newNotifyItem(notifyItem);
			if(info->direction != IPFI_OUTPUT)
			{
				/* input and forward need more space */
				notifw += 25;
				notifh += 20;
			}
			nwidget->resize(QSize(notifw, notifh));
			QPoint p = popupPosition(notifw, notifh);
			nwidget->showMessage(itemSL, p, info);
		}
		else
			delete rm;
	}
	/* else if because the packets with notify set are accepted or dropped, not
	 * unknown, while only the unknow enter the branch below.
	 */
	else if(popup->isPopupEnabled() && popup->itemCount() < popup->maxItemCount() && info->response == 0)
	{
		/* toBeIgnored() first of all verifies that the number of items
		 * in the tree is less than the maximum allowed.
		 */
		if(!popup->toBeIgnored(info))
		{
			if(!popup->isVisible())
			{
				popup->resize(QSize(popupw, popuph));
				popup->setUserResizableHeaders();
				popup->move(popupPosition(popupw, popuph));
				popup->show();
			}	
			popup->addInfo(info);
			//qDebug() << "+ Aggiungo pacchetto: " << popup->last_ignored_packet.toReadableString();
		}
// 		else
// 			qDebug() << "popup to be ignored: " << popup->last_ignored_packet.toReadableString();
	}

	free(info);
}

QPoint IQFSysTray::popupPosition(int popupWidth, int popupHeight)
{
	QRect systray_geometry;
	QPoint topleft;
	systray_geometry = geometry();
	topleft = systray_geometry.topLeft();
	systray_geometry.moveLeft(systray_geometry.topLeft().x() - popupWidth);
	systray_geometry.moveTop(systray_geometry.topLeft().y() - popupHeight);
	return systray_geometry.topLeft();
}

void IQFSysTray::refreshIcon()
{
	if(circularGauge)
		updateIconGauge();
	else
		updateIcon();
}
		
		
void IQFSysTray::updateIconGauge()
{
	int delta_acc, delta_den;
	int linelen;
	/* The center of the system tray icon */
	QPointF center;
	/* The other points, one for acc, the other for den */
	QPointF endAcc, endDen;
	/* The angles, one for the line of denial, the other for the line of accept  */
	double alphaDen, alphaAcc, alpha0 = 5.0/4.0 * M_PI;
	double alphaArrow = M_PI/12.0;
	double range = 3.0 * M_PI / 2.0;
	double deltaAlphaDen, deltaAlphaAcc;
	/* size of the icon */
	int actualw, actualh;
	
	actualw = icon().actualSize(QSize(100,100)).width();
	actualh = icon().actualSize(QSize(100,100)).height();
	center.setX(actualw/2.0);
	center.setY(actualh/2.0);
	
	if(actualw <= actualh)
		linelen = actualw/2;
	else
		linelen = actualh/2;
	
	if(get_kernel_stats_light() < 0)
	{
		/* eventually place a systray icon with an error meaning */
		/* ... */
		return;
	}
	
	refresh_no++;
	delta_acc = kstats.allowed - last_acc;
	delta_den = kstats.blocked - last_den;
// 	/* mean_acc, mean_den */
// 	if(delta_den > mean_den)
// 		mean_den = delta_den;
// 	if(delta_acc > mean_acc)
// 		mean_acc = delta_acc;
	
	delta_acc_sum += delta_acc;
	mean_acc = delta_acc_sum/(double) refresh_no;
	mean_acc *= mean_adjust_factor;
	delta_den_sum += delta_den;
	mean_den = delta_den_sum/(double) refresh_no;
	mean_den *= mean_adjust_factor;
	
	if(mean_acc != 0 && delta_acc <= mean_acc)
		deltaAlphaAcc = (range * (double) delta_acc / mean_acc);
	else if(mean_acc != 0 && delta_acc > mean_acc)
		deltaAlphaAcc = range;
	else
		deltaAlphaAcc = 0.0;
	
// 	qDebug() << "linelen" << linelen <<
// 			 "a0: " << alpha0 << " a1: " << alpha0 + range << "range: " << range << " deltaAlphaAcc " << deltaAlphaAcc;
	alphaAcc = alpha0 - deltaAlphaAcc;
	
	if(mean_den != 0 && delta_den <= mean_den)
		deltaAlphaDen = (range * (double) delta_den / mean_den);
	else if(mean_den != 0 && delta_den > mean_den)
		deltaAlphaDen = range;
	else
		deltaAlphaDen = 0.0;
	
	alphaDen = alpha0 - deltaAlphaDen;
	
	if(deltaAlphaAcc != last_deltaAlphaAcc || 
		  deltaAlphaDen != last_deltaAlphaDen)
	{
		QPixmap pixpaint(*pix);
		QPointF arr1, arr2;
		QPainter painter(&pixpaint);
		QRectF rect(QPoint(0, 0), QSize(actualw, actualh));
		QPen pen(greenColor, 3);
		pen.setCapStyle(Qt::RoundCap);
		QPen arcPen(KDARKVIOLET,2);
		arcPen.setDashPattern(QVector<qreal>() << 10 << 10 << 4 << 1);
		arcPen.setStyle(Qt::CustomDashLine);
		painter.setPen(arcPen);
		painter.drawArc(rect, -45 * 16, 270*16);
		
// 		qDebug() << "%: " << 100 * (double)delta_acc / (double)mean_acc << "delta_acc" << delta_acc << "mean_acc" << mean_acc;
// 		qDebug() << "deg " << 360 * alphaAcc / (2 * M_PI) << "(alphaAcc" << alphaAcc << ")" << "endAcc" << endAcc;
		painter.setPen(pen);
	
		painter.setPen(pen);
		/* accept */
		endAcc.setX(center.x() + allowNeedleLen * linelen * cos(alphaAcc));
		endAcc.setY(center.y() - allowNeedleLen * linelen * sin(alphaAcc));
		painter.drawLine(center, endAcc);
		if(arrowsEnabled)
		{
			arr1.setX(center.x() + 0.7 * allowNeedleLen * linelen * cos(alphaAcc + alphaArrow));
			arr1.setY(center.y() - 0.7 * allowNeedleLen * linelen * sin(alphaAcc + alphaArrow));
			arr2.setX(center.x() + 0.7 * allowNeedleLen * linelen * cos(alphaAcc - alphaArrow));
			arr2.setY(center.y() - 0.7 * allowNeedleLen * linelen * sin(alphaAcc - alphaArrow));
		
			painter.drawLine(endAcc, arr1);
			painter.drawLine(endAcc, arr2);
		}
		
		/* denial arrow and line */
		pen.setColor(redColor);
		painter.setPen(pen);
		endDen.setX(center.x() + linelen * blockNeedleLen * cos(alphaDen));
		endDen.setY(center.y() - linelen * blockNeedleLen * sin(alphaDen));
		painter.drawLine(center, endDen);
		if(arrowsEnabled)
		{
			arr1.setX(center.x() + 0.7 * blockNeedleLen * linelen * cos(alphaDen + alphaArrow));
			arr1.setY(center.y() - 0.7 * blockNeedleLen * linelen * sin(alphaDen + alphaArrow));
			arr2.setX(center.x() + 0.7 * blockNeedleLen * linelen * cos(alphaDen - alphaArrow));
			arr2.setY(center.y() - 0.7 * blockNeedleLen * linelen * sin(alphaDen - alphaArrow));
			painter.drawLine(endDen, arr1);
			painter.drawLine(endDen, arr2);
		}
		
		QIcon newicon = QIcon(pixpaint);
		setIcon(newicon);
	}
	last_deltaAlphaAcc = deltaAlphaAcc;
	last_deltaAlphaDen = deltaAlphaDen;
	last_acc = kstats.allowed;
	last_den = kstats.blocked;
}

/* called at every timeout */
void IQFSysTray::updateIcon()
{
	int delta_acc, delta_den, icon_height;
	double delta_acc_height, delta_den_height, step, rectWidth;
	int actualw, actualh;
	
	actualw = icon().actualSize(QSize(100,100)).width();
	actualh = icon().actualSize(QSize(100,100)).height();
	
	step = actualw/11.0;
	rectWidth = 3.0 * step;
	
	if(get_kernel_stats_light() < 0)
	{
		/* eventually place a systray icon with an error meaning */
		/* ... */
		return;
	}
	
	refresh_no++;

	//qDebug() << "kstats.allowed:" << kstats.allowed << "kstats.blocked:" << kstats.blocked;
	delta_acc = kstats.allowed - last_acc;
	delta_den = kstats.blocked - last_den;
	
	/* mean_acc, mean_den */
	if(delta_den > mean_den)
		mean_den = delta_den;
	if(delta_acc > mean_acc)
		mean_acc = delta_acc;
	
	delta_acc_sum += delta_acc;
	mean_acc = delta_acc_sum/(double) refresh_no;
	mean_acc *= mean_adjust_factor;
	delta_den_sum += delta_den;
	mean_den = delta_den_sum/(double) refresh_no;
	mean_den *= mean_adjust_factor;
	
	/* delta_acc : mean_acc = delta_height : icon_height */
	icon_height = actualh;
	
	if(mean_acc != 0)
		delta_acc_height = delta_acc * icon_height / mean_acc;
	else
		delta_acc_height = 0;
	
	if(mean_den != 0)
		delta_den_height = delta_den * icon_height / mean_den;
	else
		delta_den_height = 0;
	
	if(refresh_no % 5 == 0)
	{
// 		qDebug() 
// 			<< "d_acc" << delta_acc <<
// 			"d_acc_h" << delta_acc_height <<
// 			"mean_acc" << mean_acc <<
// 			"icon_height" << icon_height;
// 		qDebug() 
// 				<< "d_den" << delta_den <<
// 				"d_den_h" << delta_den <<
// 				"mean_den" << mean_den <<
// 				"icon_height" << icon_height;
	}
	
	last_acc = kstats.allowed;
	last_den = kstats.blocked;

	/* avoid repainting if the traffic is 0 */
	if(delta_acc_height != last_delta_acc_height || 
		delta_den_height != last_delta_den_height)
	{	
		QPixmap pixpaint(*pix);
		QPainter painter(&pixpaint);
		QRectF rect(2 *step, actualh, rectWidth, -delta_acc_height);
		QRectF rectden(6 * step, actualh, rectWidth, -delta_den_height);
		painter.fillRect(rect, QBrush(greenColor));
		painter.fillRect(rectden, QBrush(redColor));
		QIcon newicon = QIcon(pixpaint);
		setIcon(newicon);
	}
	last_delta_acc_height = delta_acc_height;
	last_delta_den_height = delta_den_height;

}


void IQFSysTray::enablePopupNotifier(bool enable) 
{
	QSettings s;
	 if(popup) 
	 	popup->setPopupEnabled(enable);
	 s.setValue("POPUP_ENABLE", enable);
}
		
void IQFSysTray::enablePopupOnMatchNotifier(bool enable) 
{ 
	QSettings s;
	if(popup)
		popup->setPopupOnMatchEnabled(enable);
	s.setValue("POPUP_ON_MATCH", enable);
}
		
/* popup notifier calls addInfo() (see) specifying the flag */	
void IQFSysTray::setPopupNotifierResolveEnabled(bool en) 
{ 
	if(popup) 
		popup->setResolveEnabled(en);
	
}

void IQFSysTray::setPopupMaxItems(int items) 
{ 
	if(popup) 
		popup->setPopupBuffer(items);
}
		
void IQFSysTray::setPopupOnMatchTimeout(int secs) 
{ 
	if(nwidget)
		nwidget->changeTimeout(secs);
}
		
void IQFSysTray::setPopupOnMatchResolveEnabled(bool en) 
{ 
	if(nwidget)
		nwidget->setResolveEnabled(en);
		
}
		
void IQFSysTray::setNotifyActiveServicesOnly(bool en) 
{ 
	if(popup)
		popup->setNotifyListeningOnly(en);
		
}

bool IQFSysTray::event(QEvent *e)
{
  if(e->type() == SOFTWARE_UPDATE_EVENT)
  {
    QString msg;
    if(static_cast <UpdateEvent *>(e))
      msg = static_cast <UpdateEvent *>(e)->message();
    /* showMessage disconnects(this, SIGNAL(messageClicked()) */
    showMessage("IQFire-wall: updates", msg, QSystemTrayIcon::Information, 10000);
    /* connect after showMessage() */
    connect(this, SIGNAL(messageClicked()), static_cast <UpdateEvent *>(e)->sender(), SLOT(show()));
    e->accept();
  }
  return QSystemTrayIcon::event(e);
}

void IQFSysTray::upToDateBaloon(const QString &msg)
{
    IQFUpdates* iqfu = qobject_cast<IQFUpdates *>(sender());
    qDebug() << "Ricevuto segnale e slot upToDateBaloon";
    showMessage("IQFire-wall: updates", msg, QSystemTrayIcon::Information, 300000);
    if(iqfu)
      connect(this, SIGNAL(messageClicked()), iqfu, SLOT(show()));
}

void IQFSysTray::updateToolTip()
{
	QString tt; /* tool tip */
	char username[PWD_FIELDS_LEN] = "unavailable";
	IQFStatsProxy *statsp = IQFStatsProxy::statsProxy();
	unsigned long long tot_rcv = statsp->sum();
	unsigned long long tot_acc = statsp->inAcc() + statsp->inAccImpl() +
			statsp->outAcc() + statsp->outAccImpl() +
			statsp->fwdAcc() + statsp->fwdAccImpl();
	unsigned long long tot_blocked = tot_rcv - tot_acc;
	
	double percentage_blocked = 0;
	double percentage_accepted = 0;
	
	if(tot_rcv > 0 )
	{
		percentage_blocked = (double) 100 * tot_blocked / tot_rcv;
		percentage_accepted = 100 - percentage_blocked;
	}
	get_user_info(USERNAME, username);
	tt += QString("iqfire-wall v.%1\n").arg(VERSION);
	tt += QString("firewall loaded in kernel on:\n%1\n").arg(QDateTime::
		fromTime_t(statsp->moduleLoadTime()).toString());
	tt += QString("User:\t%1\n").arg(username);
	tt += QString("--------------------------------------------\n");
	tt += QString("-Processed packets:\t%1\n").arg(tot_rcv, 0);
	tt += QString("-Accepted:\t\t%1%\n").arg(percentage_accepted, 0, 'f', 3);
	tt += QString("-Blocked:\t\t%1%\n").arg(percentage_blocked, 0, 'f', 3);
	setToolTip(tt);
 }

 void IQFSysTray::setArrowsEnabled(bool en)
 {
	 QSettings s;
	 arrowsEnabled = en; 
	 s.setValue("SYSTRAY_ARROWS_ENABLED" , en);
 }

 void IQFSysTray::setMeanAdjustFactor(double val)
 {
	 QSettings s;
	 qDebug() << "changing mean adjust factor to " << val;
	 mean_adjust_factor = val; 
	 s.setValue("SYSTRAY_MEAN_ADJUST_FACTOR", val);
 }

 void IQFSysTray::changeAllowNeedleLen(double len)
 {
	 QSettings s;
	  allowNeedleLen = len; 
	  s.setValue("SYSTRAY_ALLOW_NEEDLE_LEN", len);
 }
 
 void IQFSysTray::changeBlockNeedleLen(double len) 
 { 
	 QSettings s;
	 blockNeedleLen = len;  
	 s.setValue("SYSTRAY_BLOCK_NEEDLE_LEN", len);
 }
 
 void IQFSysTray::setCircularDashboard(bool en)
 {
	 QSettings s;
	 circularGauge = en; 
	 s.setValue("ICON_CIRCULAR_GAUGE" , en);
 }
 
 void IQFSysTray::changeAnimationSpeed(int val)
 {
	 QSettings s;
	 changeTimerTimeout(val);
	 s.setValue("SYSTRAY_REFRESH_TIMEOUT_MILLIS", val);
 }

