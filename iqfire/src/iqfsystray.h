#ifndef IQF_SYSTRAY_H
#define IQF_SYSTRAY_H

#include <QSystemTrayIcon>
#include <QThread>
#include <QEvent>
#include <QPaintEngine>
#include <QPaintDevice>
#include <QVector>
#include <QMetaType>
#include <QEvent>

#include "iqfpopup_notifier.h"
#include "iqf_notifier_widget.h"
#include <ipfire_structs.h>

Q_DECLARE_METATYPE(ipfire_info_t);

class QTreeWidgetItem;
class IQFNetlinkControl;
class Log;
class QTimer;
class IQFPopup;
class IQFRuleMatchSet;
class IQFNotifierWidget;
class IQFIREmainwin;
class QWidget;

#define SOFTWARE_UPDATE_EVENT (QEvent::Type) 8776

class UpdateEvent : public QEvent
{
  public:
    UpdateEvent(QWidget* sender, const QString msg) : QEvent(SOFTWARE_UPDATE_EVENT) 
      { d_msg = msg; d_sender = sender; }
    
    QString message() { return d_msg; }
    QWidget *sender(){ return d_sender; }
    
  private:
    QString d_msg;
    QWidget *d_sender;
};

class IQFNotifierThread : public QThread
{
	Q_OBJECT
	public:
		IQFNotifierThread(QObject *par);
		~IQFNotifierThread();
			
	signals:
		void newNotification(ipfire_info_t *);
		
	protected:
		void run();
		
	private:
		IQFNetlinkControl* nfcontrol;
		Log *iqflog;
		struct netl_handle *nh_notifier;
		struct netlink_stats nlstats;
		
};

class IQFSysTray : public QSystemTrayIcon 
{
	Q_OBJECT
	public:
		/* Give a QMainWindow to allow the popup widgets to have a parent.
		 * This is needed for the windowFlags of the notifier, which are of
		 * type ToolBar
		 */
		IQFSysTray(QObject *parent);
		~IQFSysTray();
		IQFNotifierWidget *notifierWidget() { return nwidget; }
		
		void setPopupMaxItems(int items);
		void setPopupOnMatchTimeout(int secs);
		void setPopupOnMatchResolveEnabled(bool en);
		void setNotifyActiveServicesOnly(bool en);
		
		void enableAnimation(bool en) { animation = en; }
		void setAnimationSpeed(int speed);
		int animationSpeed(); 
		void changeTimerTimeout(int millis);
		
		void initCheckableMenuActions();
		void showMessage ( const QString & title, const QString & message, 
			MessageIcon icon = Information, int millisecondsTimeoutHint = 10000 );
			
	public slots:
		void notify(ipfire_info_t *);
		void setAnimationEnabled(bool enabled);
		void enablePopupNotifier(bool enable);
		void enablePopupOnMatchNotifier(bool enable);
		/* popup notifier calls addInfo() (see) specifying the flag */
		void setPopupNotifierResolveEnabled(bool en);
		void upToDateBaloon(const QString &);
		void setArrowsEnabled(bool en);
		void setCircularDashboard(bool en);
		void setMeanAdjustFactor(double val);
		void changeAllowNeedleLen(double len);
		void changeBlockNeedleLen(double len);
		void changeAnimationSpeed(int val);
		void setAlpha(int alpha);
	
	signals:
		void newNotifyItem(QTreeWidgetItem *);
		void popupNotifierDisabled();
		
	protected:
	  bool event(QEvent *e);
		
	protected slots:
		void enableTimer(bool en);
		
		/** at every interval timeout this is called and 
		 * updates the statistics, repainting the Icon.
		 */
		void updateIcon();
		
		/** at every interval timeout this is called and 
		 * updates the statistics, repainting the Icon, but with 
		 * a `gauge' instead of two rectangles.
		 */
		void updateIconGauge();
		void refreshIcon(); /* calls one of the above */
		void emitPopupNotifierDisabled() { emit popupNotifierDisabled(); }
		void updateToolTip();
		
	private:
		bool animation;
		unsigned long refresh_no;
		double delta_acc_sum, delta_den_sum, mean_adjust_factor;
		double last_delta_acc_height, last_delta_den_height;
		double last_deltaAlphaAcc, last_deltaAlphaDen;
		QPixmap *pix;
		QTimer *timer;
		IQFNetlinkControl *nfcontrol;
		Log *iqflog;
		
		QPoint popupPosition(int popupWidth, int popupHeight);
		
		struct kstats_light kstats;
		double mean_acc, mean_den;
		unsigned long last_acc, last_den;
		
		/* fills kstats obtaining data from the kernel */
		int get_kernel_stats_light();
		
		IQFRuleMatchSet *toNotifySet;
		IQFNotifierThread *notifier;
		
		IQFPopup *popup;
		IQFNotifierWidget *nwidget;
		
		/* Creates right click menu and submenus.
		 * Call this AFTER the creation of the popup and the timer
		 */
		void createMenu();
		QAction  *matchingPackets;
		QAction *notifierPopup; 
		QAction* animationAct;
		
		bool circularGauge, arrowsEnabled;
		QPen *arcPen;
		double allowNeedleLen, blockNeedleLen;
		QColor redColor, greenColor;
		int d_alpha;
};

#endif





