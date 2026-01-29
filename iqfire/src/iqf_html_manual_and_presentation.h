#ifndef IQF_MANUAL_AND_PRESENTATION_H
#define  IQF_MANUAL_AND_PRESENTATION_H

#include "iqfwidgets.h"
#include <QTextBrowser>

class QShowEvent;
class QTimer;
class IQFIREmainwin;

class IQFPresenter : public IQFTextBrowser
{
	Q_OBJECT
	public:
		IQFPresenter(QWidget *parent);
		void setStartupPage(int p) { startupPage = p ; }
		
		void loadHome(bool get_rules_nums = false);
		void substitute(const QString &orig, const QString &subst);
		
	public slots:
		void setSource(const QUrl &name);
	
	protected slots:
		void showEvent(QShowEvent *e);
		void hideEvent(QHideEvent *e);
		void refreshHome();
		
		
	private:
		bool atHome;
		QTimer *timer;
		int timerInterval;
		unsigned int accRNum, denRNum, trRNum;
		int startupPage;
};



#endif

