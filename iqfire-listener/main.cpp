#include <stdio.h>
#include <stdlib.h>
#include <QtCore>
#include <QApplication>

#include "iqlistener.h"

int main(int argc, char **argv)
{
	int i;
	QApplication app(argc, argv);
	
	Listener *listener = new Listener();
	
	for(i = 0; i < app.arguments().size(); i++)
	{
		/* Port resolution */
		if(app.arguments().at(i) == "-services")
			listener->enablePortResolution(true);
		else if(app.arguments().at(i) == "-noservices")
			listener->enablePortResolution(false);
	}

}




