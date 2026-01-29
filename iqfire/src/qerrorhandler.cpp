#include "qerrorhandler.h"

QInfo::QInfo(QWidget *parent, QString title, QString message)
{
	QMessageBox::information(parent, title, message);
}

QError::QError(QWidget *parent, QString title, QString message)
{
	QMessageBox::critical(parent, title, message);
}




















