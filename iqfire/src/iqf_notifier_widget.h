#ifndef IQF_NOTIFIER_WIDGET
#define IQF_NOTIFIER_WIDGET

#include <QWidget>
#include <QString>
#include <QStringList>
#include <QTextBrowser>
#include <ipfire_structs.h>
#include <QPoint>

class QLabel;
class QTimer;
class QPoint;

class NotifierTextBrowser : public QTextBrowser
{
	Q_OBJECT
	public:
		 NotifierTextBrowser(QWidget *parent) : QTextBrowser(parent) {}
	public slots:
		void setSource( const QUrl & name ) { Q_UNUSED(name); };
};

class IQFNotifierWidget : public QWidget
{
	Q_OBJECT
	public:
		IQFNotifierWidget(QWidget *parent);
		
		/** Enables/disables the resolver for addresses and ports
		 * in the packet match popup (only).
		 */
		void setResolveEnabled(bool en);
		bool resolveEnable() { return resolve_enable; }
		void changeTimeout(int secs);
		
	public slots:
		void updateContents(QStringList &data);
		void showMessage(QStringList &data, QPoint &p,
			const ipfire_info_t *info);
		void updateMessageWithResolved(const QString &, const QStringList&);
		
	protected:
		void enterEvent(QEvent *e);
		void closeEvent(QCloseEvent *e);
		void setPopupPosition(QPoint& pos) { popupPos = pos; }
		QPoint &popupPosition() { return popupPos; }
		
	protected slots:
		void acknowledged(const QUrl&);
		
	signals:
		void itemAck(QStringList &data);
		
	private:
		/* if no data is passed, then the html is built from the internal 
		 * _data
		 */
		QString buildHtmlMessage(const QStringList& data = QStringList());
		QTimer *timer;
		NotifierTextBrowser *text;
		int timerInterval;
		QStringList _data;
		bool resolve_enable, locked;
		QPoint popupPos;
		
		QString d_currentResolveKey;
};




#endif





