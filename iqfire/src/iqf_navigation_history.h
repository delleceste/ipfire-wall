#ifndef IQF_HISTORY_H
#define IQF_HISTORY_H

#include <QVector>
#include <QVariant>
#include <QObject>

class History : public QObject
{
	Q_OBJECT
	public:
		static History* history(QObject *parent = NULL, unsigned size = 15);
		
		QVariant next();
		QVariant previous();
		unsigned int current() { return _pos; }
		
		bool hasPrevious();
		bool hasNext();
			
		unsigned int size() { return _size; }
		void setSize(unsigned int s) { _size = s; }
		
		unsigned int count() { return (unsigned) _history.size(); }
		void add(QVariant newpage);
		
	public slots:
		
	signals:
		void historyModified();
		
		
	private:
		static History *_instance;
		History(QObject *parent, unsigned size);
		QVector<QVariant> _history;
		unsigned int _pos, _size;
};

#endif

