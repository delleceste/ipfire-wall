#include "iqfire_confdir.h"
#include <QMessageBox>
#include <QSettings>
#include <ipfire_structs.h>
#include "iqflog.h"

extern "C"
{
	int setup_confdir();
}

IQFireConfdir::IQFireConfdir()
{
	code = setup_confdir();
	if(code != CFGDIR_UPTODATE)
		notifyConfigCheck(code);
	
}

void IQFireConfdir::notifyConfigCheck(int code)
{
	QSettings s;
	int ret, ret2;
	QString msg, title;
	switch(code)
	{
		case CFGDIR_CREAT:
			title = "iqFirewall configuration directory created";
			msg = "This should be the first time you run iqfirewall\n"
					"The configuration files needed for its correct behaviour\n"
					"have been successfully installed in a hidden directory\n"
					"in your home. The directory name is \".IPFIRE\"\n\n"
					"Have fun now!\n";
			break;
		case CFGDIR_CREAT_FAILED:
			title = "Failed to install the configuration files"; 
			msg = "Failed to create the default configuration\n"
					"environment for the application.\n"
					"Be sure to have the write permissions in your home\n"
					"directory.";
			break;
		case CFGDIR_MIGRATED:
			title = "Old configuration updated";
			msg = "An installation of an  older \"ipfire\" version was detected\n"
					"and the old configuration directory \"IPFIRE\" in your home\n"
					"has been renamed into \".IPFIRE\", always in your home dir.\n"
					"This is a hidden file, since it starts with a dot (\".\")\n"
					"If you need to explore the \".IPFIRE\" configuration directory\n"
					"in your home, remember to enable the visualization of hidden\n"
					"files in your file browser (nautilus or konqueror for instance).\n"
					"If the old \"IPFIRE\" is still present in your home, you can \n"
					"safely remove it and all its contents.\n";
			break;
		case CFGDIR_MIGRATED_FAILED:
			title = "Error updating the firewall configuration";
			msg = "An installation of an  older \"ipfire\" version was detected\n"
					"but it was not possible to move the old directory \"IPFIRE\"\n"
					"into the new called \".IPFIRE\"\n"
					"Be sure to have the write permissions on your home directory and\n"
					"that the directory \".IPFIRE\" (hidden) does not exist yet.";
				
			break;
		case SHARE_CFGDIR_MISSING:
			title = "Firewall installation error";
			msg = QString("The default configuration files, which should stay in \n"
					"\"%1\" are not present.\n"
					"Check your installation or try installing again iqFirewall.\n").
					arg(SHARE_CFGDIR);
			break;
		case CFGDIR_BOTH:
			Log::log()->appendMsg("<strong>Warning</strong>: the directory "
				"\"IPFIRE\" in your home directory is no more needed by iqFirewall\n");
			
			if(!s.value("WARN_BOTH_CONFDIRS", true).toBool())
				break;
			
			title = "Old folder IPFIRE no more needed";
			msg = "iqFirewall has detected that you have installed "
				"both configuration directory \n\"IPFIRE\" and "
				"\".IPFIRE\" in your home folder (hidden).\n"
				"It is safe to remove the unused directory \"IPFIRE\" "
				"from your home.\n";
			ret = QMessageBox::information(0, title, msg, 
					"Ok, but warn me\nagain next time",
				"Ok, don't warn\nme again");
			if(ret == 1)
				s.setValue("WARN_BOTH_CONFDIRS", false);
			break;
	}
	
	/* popup a message */
	switch(code)
	{
		case CFGDIR_CREAT_FAILED:
		case CFGDIR_MIGRATED_FAILED:
		case SHARE_CFGDIR_MISSING:
			QMessageBox::critical(0, title, msg);
		break;
		case CFGDIR_MIGRATED:
		case CFGDIR_CREAT:
			QMessageBox::information(0, title, msg);
			break;
		default:
			break;
	}
}





