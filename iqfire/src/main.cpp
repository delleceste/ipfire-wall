#include "iqfire.h"
#include "iqf_splash.h"
#include "euniqueapplication.h"
#include "iqfinit.h"

#include <KApplication>
#include <QtDebug>
#include <KCmdLineArgs>
#include <KAboutData>
#include <QSettings>

#include <signal.h>

void signal_handler(int signum);

int main(int argc, char **argv)
{
	char servicename[16];
	
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
// // 	signal(SIGSEGV, signal_handler);
	signal(SIGHUP, signal_handler);
	
	strncpy(servicename, "iqfire", 15);
	KAboutData aboutData ("iqfire", 0, ki18n("iQfire"), "0.98.7",
		ki18n( "IQFire - Graphical interface to IPFIREwall" ), KAboutData::License_LGPL_V2,
		ki18n( "(c) 2000-2005 Giacomo S." ), 
		KLocalizedString(), "http://www.giacomos.it/ipfire");

	bool startHidden = false;
	KCmdLineArgs::init (argc, argv, &aboutData);
	KCmdLineOptions options;
	options.add("minimized", 
		    ki18n("Tells iqFirewall to start hidden in the system tray"));
	
	KCmdLineArgs::addCmdLineOptions(options);
	
	KCmdLineArgs *args = KCmdLineArgs::parsedArgs();

	EUniqueApplication app(servicename);
	
 	app.setOrganizationName("IPFIRE-wall-GiacomoStrangolino");
 	app.setOrganizationDomain("giacomos.it");
 	app.setApplicationName("IqFIREWALL");

	IQFIREmainwin* iqmw = IQFIREmainwin::instance(NULL, argc, argv);
	QSettings s;
	startHidden = s.value("STARTUP_HIDDEN", false).toBool();
	/* if there are arguments and the settings do not say to
	 * startup hidden
	 */	
	if(args->isSet("minimized") && !startHidden) 
		startHidden = true;

 	if(!startHidden)
		iqmw->show();
	IQFSplash::splashScreen()->finish(iqmw);
 	return app.UniqueExec();
}

void signal_handler(int signum)
{
	IQFInitializer* init = IQFInitializer::instance();
	switch(signum)
	{
		case SIGINT:
			printf("\e[1;35mSIGINT received: sending goodbye to kernel\e[0m\nBeware: session data not saved!");
			init->SendGoodbye();
			exit(EXIT_SUCCESS);
			break;
		case SIGTERM:
			printf("\e[1;35mSIGTERM received: sending goodbye to kernel\e[0m\nBeware: session data not saved!");
			init->SendGoodbye();
			exit(EXIT_SUCCESS);
			break;
		case SIGHUP:
			printf("\e[1;35mSIGHUP received: sending goodbye to kernel\e[0m\nBeware: session data not saved!");
			init->SendGoodbye();
			exit(EXIT_SUCCESS);
			break;	
		case SIGSEGV:
			printf("\e[1;31mSIGSEGV received: trying to send goodbye to kernel\e[0m\nBeware: session data not saved!");
			init->SendGoodbye();
			exit(EXIT_FAILURE);
			break;
	}

}


