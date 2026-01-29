#ifndef STATS_TEXTBROWSER
#define STATS_TEXTBROWSER

#include <QTextBrowser>
#include <ipfire_structs.h>
#include "iqfstats_proxy.h"


class QTimer;

class StatsText : public QTextBrowser
{
	Q_OBJECT
	public:
		StatsText(QWidget *parent);
		
	protected:
		void showEvent(QShowEvent *e);
		void hideEvent(QHideEvent *e);
	
	protected slots:
		void updateStats();
		
	private:
		QTimer *timer;
		int interval;
};


#endif

