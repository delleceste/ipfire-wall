#ifndef IQF_SPLASH_H
#define IQF_SPLASH_H
#include <QSplashScreen>
#include <QProgressBar>

class QLabel;


class IQFSplash : public QSplashScreen
{
	Q_OBJECT
	public:
		static IQFSplash *splashScreen(QWidget *parent = NULL);
		void setSteps(int s) { if(pb) pb->setMaximum(s); }
		
	public slots:
		void newStep(QString &message, int progress);
		void newStep(const char* message, int progress);
			
	private:
		IQFSplash( QWidget * parent);
		QProgressBar *pb;
		QLabel *label;
		static IQFSplash *_instance;
		
};



















#endif


