#ifndef IQF_UPDATES_H
#define IQF_UPDATES_H


#include <QWidget>

class QHttp;
class QProgressBar;
class IQFPushButton;
class IQFTextBrowser;
class IQFLineEdit;
class IQFUpdaterKonsole;
class QStackedWidget;

class IQFUpdates : public QWidget
{
	Q_OBJECT
	public:
		IQFUpdates(QWidget *parent);
		~IQFUpdates();
		void downloadVersion();
	
	public slots:	
		void lookForUpdates();
		
	protected:
		
	signals:
		void updateFinished();
		
	private slots:
		void requestDone(int id, bool ok);
		void abortUpdate();
		void update();
	private:
		int upToDate(QString &html);
		QString current_version_string;
		int currentVersion;
		int up2dStatus;
		QHttp *http;
		IQFPushButton *bt;
		IQFPushButton *updButton;
		IQFTextBrowser *tb;
		int getID, sethostID;
		QStackedWidget *sw;
		IQFLineEdit *adminPwdLineEdit;
		
		IQFUpdaterKonsole *updaterTerminal;
		
		QString html;
};


#endif





