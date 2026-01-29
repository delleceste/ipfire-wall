#ifndef WIDGET_KONSOLE_H
#define WIDGET_KONSOLE_H

//#include <kde/kde_terminal_interface.h>
#include <QWidget>
#include <kxmlguiclient.h>
#include <kparts/part.h>

class TerminalInterface;
class KXmlGuiWindow;
class KMainWindow;

class IQFWidgetKonsole : public QWidget, public KXMLGUIClient
{
	Q_OBJECT
	public:
		IQFWidgetKonsole(QWidget *parent, KMainWindow *mainwin);
	~IQFWidgetKonsole();
	
	public slots:
		void enableResolvPorts(bool enable);
		void shellExited();
		void filterChanged(const QString &filter);
	
	private:
		KParts::ReadOnlyPart *part;
		TerminalInterface *terminal;
	
};



#endif





