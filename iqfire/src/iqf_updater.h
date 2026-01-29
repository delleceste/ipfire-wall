#ifndef UPDATER_KONSOLE_H
#define UPDATER_KONSOLE_H

//#include <kde/kde_terminal_interface.h>
#include <QWidget>
#include <kxmlguiclient.h>
#include <kparts/part.h>

class TerminalInterface;
class KXmlGuiWindow;
class KMainWindow;

class IQFUpdaterKonsole : public QWidget, public KXMLGUIClient
{
	Q_OBJECT
	public:
		IQFUpdaterKonsole(QWidget *parent);
		~IQFUpdaterKonsole();
	
	public slots:
		void shellExited();
		void startUpdate();
	
	private:
		KParts::ReadOnlyPart *part;
		TerminalInterface *terminal;
	
};



#endif





