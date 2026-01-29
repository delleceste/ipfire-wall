#include "iqf_navigation_history.h"
#include <QtDebug>

History* History::_instance = NULL;

History *History::history(QObject *parent, unsigned int maxelems)
{
	if(_instance == NULL)
		_instance = new History(parent, maxelems);
	
	return _instance;
}

History::History(QObject *parent, unsigned int maxelems) : QObject(parent)
{
	_history.resize(0);
	_pos = 0;
	_size = maxelems;
}

QVariant History::next()
{
	if(_history.size() > 0 && _pos < (unsigned) _history.size())
	{
		_pos++;	
	}
// 	qDebug() << "next(): " << _history[_pos - 1];
	emit historyModified();
	return _history[_pos - 1];
}

QVariant History::previous()
{
	if(_pos > 1)
	{
		_pos--;
// 		qDebug() << "previous(): " << _history[_pos - 1];
		emit historyModified();
		return _history[_pos - 1];
	}
// 	qDebug() << "previous(): ritorno pos: " << _pos << " history:" << _history[0];
	emit historyModified();
	return _history[0];
	
}

void History::add(QVariant newpage)
{
	if(_history.size() > 0 && _history[_history.size() - 1] == newpage)
	{
// 		qDebug() << "history: non aggiungo due entry uguali!";
		if(_pos < (unsigned int)_history.size())
			_pos = _history.size();
	}
	else
	{
		_history.push_back(newpage);
	
		if( ((unsigned) _history.size()) > _size)
			_history.remove(0);
		_pos = _history.size();
	}
	emit historyModified();
}

bool History::hasNext()
{ 
// 	qDebug() << "hasNext: pos: " << _pos << "history size: " << _history.size();
	if((_pos < (unsigned) _history.size())
		&& (_history.size() > 0))
		return true;
	return false;	
}

bool History::hasPrevious()
{
// 	qDebug() << "hasPrevious(): pos: " << _pos << "history size: " << _history.size();
	if(_pos > 1)
		return true; 
	return false;
}



