#include "iqf_splash.h"
#include <QLabel>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QApplication>

IQFSplash* IQFSplash::_instance = NULL;

IQFSplash *IQFSplash::splashScreen(QWidget *parent)
{
	if(_instance == NULL)
		_instance = new IQFSplash(parent);
	
	return _instance;
}

IQFSplash::IQFSplash( QWidget * parent) : QSplashScreen(parent)
{
	QVBoxLayout *lo = new QVBoxLayout(this);
	
	pb = new QProgressBar(this);
	pb->setValue(0);
	label = new QLabel("iQfirewall: an easy to use Linux Firewall", this);
	
	label->setAlignment(Qt::AlignHCenter);
	lo->addWidget(pb);
	lo->addWidget(label);
	QPoint position = pos();
	position.setX(position.x() - width()/2);
	position.setY(position.y() - height()/2);
	move(position);
	show();
}

void IQFSplash::newStep(QString &message, int progress)
{
	label->setText(message);
	pb->setValue(progress);
}

void IQFSplash::newStep(const char* message, int progress)
{
	QString qsmsg(message);
	newStep(qsmsg, progress);
}





