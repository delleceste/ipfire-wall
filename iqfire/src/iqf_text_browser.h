#ifndef IQF_TEXT_BROWSER_H
#define IQF_TEXT_BROWSER_H

#include <QTextBrowser>
#include <QString>


#define BROWSER_DEFAULT_PATHS QStringList() << "/usr/share/iqfire/doc/info/" \
		<< "/usr/share/iqfire/doc/help/" << "/usr/share/iqfire/doc/manual/"

class IQFTextBrowser : public QTextBrowser
{
	Q_OBJECT
	public:
		enum browserType { Info, Help };
		
		IQFTextBrowser(QWidget *par);
		
		void setType(int t ) { _type = t; };
		int type() { return _type; }
		
	public slots:
		void clickFromInfoLink(const QUrl&);
		void setSource(const QUrl &name);
		void resolutionUpdate(const QString &unres, const QString &type, const QString& res);
		void scroll(int d);
		
  signals:
	void appendNaturalTextFromClick(const QString&);

	protected:
		QString currentHtml;

	private:
		int _type;
		void processAction(QString s);
		
		QString d_currentNumericResolution;
		
	
};

#endif
