#include <QtDebug>
#include "iqf_updater.h"
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


IQFUpdaterKonsole::IQFUpdaterKonsole(QWidget *parent) : QWidget(parent), KXMLGUIClient()
{
	QSettings s;
	KLibFactory* factory = KLibLoader::self()->factory("libkonsolepart" );
	if ( factory == 0L )
	{
		// inform the user that he should install konsole..
		QMessageBox::information(this, "Information",
			"You need to install konsole!");
		return;
	}
	part = static_cast<KParts::ReadOnlyPart *>
			(factory->create(this, "KParts::ReadOnlyPart"));
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
// // 	terminal->startProgram(QString::fromUtf8("iqfire-listener"), l);
	/* else: already enabled by default when calling iqfire-listener */
}

IQFUpdaterKonsole::~IQFUpdaterKonsole()
{
	KLibFactory* factory = KLibLoader::self()->factory( "konsolepart" );
	if(factory)
	{
		printf("\e[1;32m*\e[0m closing updater terminal...\t\t\t");
		if(terminal)
			printf("\e[1;32mOk\e[0m.\n");
		else
			printf( "\n\e[1;35mwarning\e[0m: terminal no more available.\e[0m\n");
	}
	else
		printf( "\n\e[1;35mwarning\e[0m: konsole not available.\e[0m\n");
}

void IQFUpdaterKonsole::shellExited()
{
	QMessageBox::information(this, "Console no more available",
		"The console will not be available until you restart the firewall");
	terminal = NULL;
}

void  IQFUpdaterKonsole::startUpdate()
{
	if(!terminal)
	{	
		qDebug() << "terminal not available";
		return;
	}
}
		

