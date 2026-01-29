#ifndef QERRORHANDLER_H
#define QERRORHANDLER_H

#include <QString>
#include <QMessageBox>

class QInfo
{
public:
	QInfo(QWidget *parent, QString title, QString message);
};

class QError
{
public:
	QError(QWidget *parent, QString title, QString message);
};




#endif








