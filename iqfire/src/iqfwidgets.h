#ifndef IQFWIDGETS_H
#define IQFWIDGETS_H

#include <QLineEdit>
#include <QCheckBox>
#include <QComboBox>
#include <QSpinBox>
#include <QRadioButton>
#include <QPushButton>
#include <QStringList>
#include <QString>
#include <QtDebug>
#include <QSplitter>
#include <QTextBrowser>
#include <QStackedWidget>
#include <QProgressBar>
#include <QValidator>
#include <QWheelEvent>
#include <QMap>
#include <QVariant>

#include <qwt_legend_item.h>
#include "iqf_text_browser.h"

class QwtPlotCurve;
class QTimer;


class IQFLineEdit : public QLineEdit
{
	Q_OBJECT
	public:
		
	IQFLineEdit(QWidget * parent);
	
	void setInfo(QString i) { _info = i; }
	void setHelp(QString h) { _help = h; }
	void setInfoAndHelp(QString s) { _info = s; _help = s; }
	bool modified() { return _modified; }
	
	void disableHelp(bool disable) { _help_disabled = disable; }
	void disableInfo(bool disable) { _info_disabled = disable; }
	bool helpDisabled() { return _help_disabled; }
	bool infoDisabled() { return _info_disabled; }
	
	QString info() { return _info; }
	QString help() { return _help; }
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void helpChanged(QString help);
		void widgetLeft();
		void scroll(int steps);
		
	private:
		QString _info, _help;
		bool _modified, _help_disabled, _info_disabled;
		QTimer *timer;
	
};

class IQFCheckBox : public QCheckBox
{
	Q_OBJECT
	public:
		IQFCheckBox(QWidget * parent);
		void setInfo(QString i) { _info = i; }
		void setHelp(QString h) { _help = h; }
		void setInfoAndHelp(QString s) { _info = s; _help = s; }
		bool modified() { return _modified; }
		
		void disableHelp(bool disable) { _help_disabled = disable; }
		void disableInfo(bool disable) { _info_disabled = disable; }
		bool helpDisabled() { return _help_disabled; }
		bool infoDisabled() { return _info_disabled; }
	
		QString info() { return _info; }
		QString help() { return _help; }
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void helpChanged(QString help);
		void widgetLeft();
		void scroll(int steps);
		
	private:
		QString _info, _help;
		bool _modified, _help_disabled, _info_disabled;
		QTimer *timer;
};

class IQFComboBox : public QComboBox
{
	Q_OBJECT
	public: 
		IQFComboBox(QWidget * parent);	
		void setInfo(QString i) { _info = i; }
		void setHelp(QString h) { _help = h; }
		void setInfoAndHelp(QString s) { _info = s; _help = s; }
		bool modified() { return _modified; }
		
		void disableHelp(bool disable) { _help_disabled = disable; }
		void disableInfo(bool disable) { _info_disabled = disable; }
		bool helpDisabled() { return _help_disabled; }
		bool infoDisabled() { return _info_disabled; }
		
		QString info() { return _info; }
		QString help() { return _help; }
		
		void setEntry(QString &s);
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void helpChanged(QString help);
		void widgetLeft();
		void scroll(int steps);
		
	private:
		QString _info, _help;
		bool _modified, _help_disabled, _info_disabled;
		QTimer *timer;
};

class IQFSpinBox : public QSpinBox
{
	Q_OBJECT
	public: 
		IQFSpinBox(QWidget * parent);	
		void setInfo(QString i) { _info = i; }
		void setHelp(QString h) { _help = h; }
		void setInfoAndHelp(QString s) { _info = s; _help = s; }
		bool modified() { return _modified; }
		
		void disableHelp(bool disable) { _help_disabled = disable; }
		void disableInfo(bool disable) { _info_disabled = disable; }
		bool helpDisabled() { return _help_disabled; }
		bool infoDisabled() { return _info_disabled; }
	
		QString info() { return _info; }
		QString help() { return _help; }
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void widgetLeft();
		void helpChanged(QString help);
		void scroll(int steps);
		
	private:
		QString _info, _help;
		bool _modified, _help_disabled, _info_disabled;
		QTimer *timer;
};

class IQFDoubleSpinBox : public QDoubleSpinBox
{
	Q_OBJECT
	public: 
		IQFDoubleSpinBox(QWidget * parent);	
		void setInfo(QString i) { _info = i; }
		void setHelp(QString h) { _help = h; }
		void setInfoAndHelp(QString s) { _info = s; _help = s; }
		bool modified() { return _modified; }
		
		void disableHelp(bool disable) { _help_disabled = disable; }
		void disableInfo(bool disable) { _info_disabled = disable; }
		bool helpDisabled() { return _help_disabled; }
		bool infoDisabled() { return _info_disabled; }
	
		QString info() { return _info; }
		QString help() { return _help; }
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void widgetLeft();
		void helpChanged(QString help);
		void scroll(int steps);
		
	private:
		QString _info, _help;
		bool _modified, _help_disabled, _info_disabled;
		QTimer *timer;
};


class IQFRadioButton : public QRadioButton
{
	Q_OBJECT
	public: 
		IQFRadioButton(QWidget * parent);
			
		void setInfo(QString i) { _info = i; }
		void setHelp(QString h) { _help = h; }
		void setInfoAndHelp(QString s) { _info = s; _help = s; }
		bool modified() { return _modified; }
		
		void disableHelp(bool disable) { _help_disabled = disable; }
		void disableInfo(bool disable) { _info_disabled = disable; }
		bool helpDisabled() { return _help_disabled; }
		bool infoDisabled() { return _info_disabled; }
	
		QString info() { return _info; }
		QString help() { return _help; }
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void helpChanged(QString help);
		void widgetLeft();
		void scroll(int steps);
		
		
	private:
		QString _info, _help;
		bool _modified, _help_disabled, _info_disabled;
		QTimer *timer;
};

class IQFPushButton : public QPushButton
{
	Q_OBJECT
	public: 
		IQFPushButton(QWidget * parent);
			
		void setInfo(QString i) { _info = i; }
		void setHelp(QString h) { _help = h; }
		void setInfoAndHelp(QString s) { _info = s; _help = s; }
		
		void disableHelp(bool disable) { _help_disabled = disable; }
		void disableInfo(bool disable) { _info_disabled = disable; }
		bool helpDisabled() { return _help_disabled; }
		bool infoDisabled() { return _info_disabled; }
	
		QString info() { return _info; }
		QString help() { return _help; }
		
		void setData(QVariant data) { d_data = data; }
		QVariant data() { return d_data; }
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void helpChanged(QString help);
		void scroll(int steps);
		void widgetLeft();
		
	private:
		QString _info, _help;
		bool _help_disabled, _info_disabled;
		QTimer *timer;
		QVariant d_data;
};

class IQFLegendItem : public QwtLegendItem
{
	Q_OBJECT
	public:
		IQFLegendItem(QWidget *parent, QwtPlotCurve* associated_curve);
		
		void setInfo(QString i) { _info = i; }
		void setHelp(QString h) { _help = h; }
		void setInfoAndHelp(QString s) { _info = s; _help = s; }
	
		QString info() { return _info; }
		QString help() { return _help; }
		
		QwtPlotCurve *associatedCurve() {return assoc_curve; }
	
	protected slots:
		void updateMessages();
	
	protected:
		void enterEvent(QEvent *e);
		/* needs leaveEvent because we must restore the help and the info
		 * when the user leaves a button 
		*/
		void leaveEvent(QEvent *e);
		void emitMessages() { emit infoChanged(_info); emit helpChanged(_help); }
		void wheelEvent(QWheelEvent *e) { emit scroll(e->delta()); QWidget::wheelEvent(e); }
	
	signals:
		void infoChanged(QString info);
		void helpChanged(QString help);
		void scroll(int steps);
		
	private:
		QString _info, _help;
		QwtPlotCurve *assoc_curve;	
		QTimer *timer;
};


class IQFSplitter : public QSplitter
{
	Q_OBJECT
	public:
	IQFSplitter(QWidget *par);
	bool beenMoved() { return been_moved; }
	void reloadState() { if(!state.isEmpty()) restoreState(state); }
	void storeState() { state = saveState(); }
	
	protected slots:
		void IQFSplitterMoved(int, int) { been_moved = true; state = saveState(); }
		 
		
	private:
		bool been_moved;
		QByteArray state;
};

/** Remember to reparent calling setParent() when
 * the ui is setup with setupUi(), or calling reparent()
 * here.
 */
class IQFInfoBrowser : public IQFTextBrowser
{
	Q_OBJECT
	public:
		static IQFInfoBrowser* infoBrowser();
		void reparent(QWidget *par) { setParent(par); }		
			
	public slots:
		void setHtml(QString html);
	private:
		IQFInfoBrowser(QWidget *parent);
		~IQFInfoBrowser();
		static IQFInfoBrowser* _instance;
		
};

/** Remember to reparent calling setParent() when
 * the ui is setup with setupUi(), or calling reparent()
 * here.
 */
class IQFHelpBrowser : public IQFTextBrowser
{
	Q_OBJECT
	public:
		static IQFHelpBrowser* helpBrowser();
		void reparent(QWidget *par) { setParent(par); }	
		
	public slots:
		void setHtml(QString html);
	private:
		IQFHelpBrowser(QWidget *parent);
		~IQFHelpBrowser();
		
		static IQFHelpBrowser* _instance;
		
};

class IQFNavigationPanel : public QTextBrowser
{
	Q_OBJECT
	public:
		IQFNavigationPanel(QWidget *parent);
		
	public slots:
		void setSource( const QUrl & name );
		
	signals:
		void changePage(int index);
		void silentModality(bool on);
		void showHelp(bool on);
		void showInfo(bool on);
	
};

/** This is to reimplement sizeHint() */
class IQFStackedWidget : public QStackedWidget
{
	Q_OBJECT
	public:
		IQFStackedWidget(QWidget *parent);
		QSize minimumSizeHint() const;
		void setInfoAndHelpForPage(int page, bool by_timer);
		
		QMap<int, bool> infoEnabledForPage;
		
	protected slots:
		void updateMessages();
		
	protected:
		void enterEvent(QEvent *e);
		void leaveEvent(QEvent *e);
		
	private:
		QTimer *timer;
		
	
};

/** A progress bar that by default stays hidden and appears when 
 * its value is greater than 0 and less than 100%
 * This is the default behaviour.
 */
class IQFProgressBar : public QProgressBar
{
	Q_OBJECT
	public:
	IQFProgressBar(QWidget *parent);
	
	public slots:
		void setProgress(int value);
		
	private:
		QTimer *timer;
	
};

#endif

