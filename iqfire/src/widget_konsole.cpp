#include <QtDebug>
#include "widget_konsole.h"
#include <kparts/factory.h>
#include <KMainWindow>
#include <KXmlGuiWindow>
#include <kxmlguiclient.h>
#include <kxmlguifactory.h>
#include <kde_terminal_interface.h>
#include <QMessageBox>
#include <QWidget>
#include <QStringList>
#include <QGridLayout>
#include <QSettings>
#include <QTimer>
#include <QFont>
#include <klibloader.h>
#include <klocale.h>


IQFWidgetKonsole::IQFWidgetKonsole(QWidget *parent, KMainWindow* mainWin) : QWidget(parent), KXMLGUIClient()
{
	QSettings s;
	Q_UNUSED(mainWin);
// 	KLibFactory* factory = KLibLoader::self()->factory( "libkonsolepart" );
	KPluginFactory *factory = KPluginLoader("libkonsolepart").factory();
	
	if ( factory == 0L )
	{
		// inform the user that he should install konsole..
		QMessageBox::information(this, "Information",
			"You need to install konsole!");
		
		return;
	}
	part = static_cast<KParts::ReadOnlyPart *>
			(factory->create<QObject>(this,  this));
	if(part!=NULL)
	  printf("* konsole part created");
	else
	{
	   printf("error creating part\n");
	  return;
	}
	// start the terminal
	terminal = qobject_cast<TerminalInterface*>(part);
	if(!terminal)
	{
		QMessageBox::information(this, "error",
			"Problems creating a terminal interface part!\n"
			"The console will not be available!");
		return;
	}
	if(part->widget() != NULL)
		part->widget()->setFont(QFont("", 7));
	KGlobal::locale()->insertCatalog("konsole");
	
// 	KXMLGUIFactory *gui_factory = mainWin->guiFactory();
// // 	gui_factory->addClient(part);


	QLayout *layout = parent->layout();
	if(layout != NULL)
	{
		layout->addWidget(this);
	}
	else
		qDebug() << "parent layout e` nullo!";
	QGridLayout *lo = new QGridLayout(this);
	lo->setMargin(0);
	lo->setSpacing(2);
	lo->addWidget(part->widget());
	connect(part, SIGNAL(destroyed()), this, SLOT(shellExited()));
	
	QStringList l;
	l.push_back("");
	terminal->startProgram(QString::fromUtf8("iqfire-listener"), l);
	bool resolveServices = s.value("RESOLVE_SERVICES", true).toBool();
	if(!resolveServices)
		enableResolvPorts(resolveServices);
	/* else: already enabled by default when calling iqfire-listener */
}

void IQFWidgetKonsole::enableResolvPorts(bool enable)
{
	QSettings s;
	s.setValue("RESOLVE_SERVICES", enable);
	
	if(enable && terminal != NULL) /* Remember to terminate with \n ;) */
		terminal->sendInput("resolv_ports\n");
	else if(terminal != NULL)
		terminal->sendInput("noresolv_ports\n");
	else
		QMessageBox::information(this, "Error", "The terminal is no more available");
	
}

IQFWidgetKonsole::~IQFWidgetKonsole()
{
// 	KLibFactory* factory = KLibLoader::self()->factory( "konsolepart" );
	KPluginFactory *factory = KPluginLoader("libkonsolepart").factory();
	if(factory)
	{
		printf("\e[1;32m*\e[0m closing terminal...\t\t\t");
		if(terminal)
		{
			terminal->sendInput("quit");
			printf("\e[1;32mOk\e[0m.\n");
		}
		else
			printf( "\n\e[1;35mwarning\e[0m: terminal no more available.\e[0m\n");
	}
	else
		printf( "\n\e[1;35mwarning\e[0m: konsole not available.\e[0m\n");
}

void IQFWidgetKonsole::shellExited()
{
	QMessageBox::information(this, "Console no more available",
		"The console will not be available until you restart the firewall");
	terminal = NULL;
}

void  IQFWidgetKonsole::filterChanged(const QString &filter)
{
	QString filter_command;
	if(filter.contains("filter:") && filter.contains("disable"))
		filter_command = filter;
	else
		filter_command = "filter:" + filter;
	
	if(!filter_command.endsWith('\n'))
		filter_command.append('\n');
	if(terminal)
		terminal->sendInput(filter_command);
	else
		QMessageBox::information(this, "Error", "The terminal is no more available");
}
		

