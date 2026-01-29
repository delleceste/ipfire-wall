#ifndef IQFIRE_LOG
#define IQFIRE_LOG

#include <QString>
#include <QMessageBox>
#include <QtDebug>
#include <QTextBrowser>
#include <QPushButton>
#include <QGridLayout>

class IQFIREmainwin;

extern "C"
{
	/* Returns the translated string langline, 
 * declared global so not destroyed at the
 * end of the function execution.
 */
char* translation(const char* eng);

#define TR(eng) (translation(eng) )

}

class Log : public QWidget
{
	Q_OBJECT
	public:
	
	static Log* log(QWidget *parent);
	static Log* log() { return _instance; }
	
	void appendOk(QString message);
	
	void appendFailed(QString message);
	
	void appendNumber(QString message, int n);
	
	void appendTwoStrings(QString message, QString result);
	
	void appendMsg(QString message);
	
	void message(QString message);
	
	void Ok();
	
	void Failed();
	
	bool somethingFailed();
	
	void forceShowLogs() { emit somethingHasFailed(); }
	
	protected slots:
	
	void closeWindow();
	void initBrowser();

	signals:
		void somethingHasFailed();
		void widgetClosed();
	
	private: /* Singleton: the constructor is private */
		
	Log(QWidget *parent);
	~Log();
		
	static Log* _instance;
	
	QTextBrowser *text;
	QPushButton *buttonclose;
	QPushButton *buttonclear;
	QGridLayout *grid;
	
	bool something_failed;
};



#endif










