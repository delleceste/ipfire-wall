#ifndef IQF_VALIDATORS_H
#define IQF_VALIDATORS_H

#include <QValidator>
#include "iqfwidgets.h"
#include <ipfire_structs.h>

/* Ports are normally set by spinBoxes.
 * We need this from treeWidgetItems
  */
class PortValidator : public QIntValidator
{
	Q_OBJECT
	public:
		PortValidator(QObject *parent);
		State validate(QString & input, int & pos) const;
		void setAnyEnabled(bool en) {any = en; }
	private:
		bool any;
};

/** This is used by QLineEdits and can be used to validate
 * input from QTreeWidgetItems.
 * In the last case, one can enable any to accept keywords as
 * "-" or "any"  (which mean the same)
 */
class IPValidator : public QRegExpValidator
{
	Q_OBJECT
	public:
		IPValidator(QObject *parent);
		State validate(QString & input, int & pos) const;
		void setAnyEnabled(bool en) {any = en; }
		void setMyEnabled(bool en) { my = en; }
		void setDifferentEnabled(bool en) { different = en; }
	private:
		bool any, my, different;
};

class IPMaskValidator : public QRegExpValidator
{
	Q_OBJECT
	public:
		IPMaskValidator(QObject *parent);
		State validate(QString & input, int & pos) const;
};

/** validates an IP interval, used in QTreeWidgetItems 
 * Does not check single ips nor "-" or "any", use
 * both IPValidator and IPIntervalValidator for a 
 * combined check.
 */
class IPIntervalValidator : public QRegExpValidator
{
	Q_OBJECT
	public:
		IPIntervalValidator(QObject *parent);
		State validate(QString & input, int & pos) const;
};

class IPGenericValidator : public QRegExpValidator
{
	Q_OBJECT
	public:
		IPGenericValidator(QObject *parent);
		State validate(QString & input, int & pos) const;
};

class PortGenericValidator : public QRegExpValidator
{
	Q_OBJECT
	public:
		PortGenericValidator(QObject *parent);
		State validate(QString & input, int & pos) const;
};

class StringInputValidator : public QRegExpValidator
{
	Q_OBJECT
	public:
		StringInputValidator(QObject *parent, unsigned int len);
		State validate(QString & input, int & pos) const;
};

/** validates addresses with !, MY, any, keywords */
class GenericIPLineEdit : public IQFLineEdit
{
	Q_OBJECT
	public:
		GenericIPLineEdit(QWidget *parent);
};

class GenericPortLineEdit : public IQFLineEdit
{
	Q_OBJECT
	public:
		GenericPortLineEdit(QWidget *parent);
};



class IPLineEdit : public IQFLineEdit
{
	Q_OBJECT
	public:
		IPLineEdit(QWidget *parent);
};

class IPMaskLineEdit : public IQFLineEdit
{
	
	Q_OBJECT
	public:
		IPMaskLineEdit(QWidget *parent);
};

class PortLineEdit : public IQFLineEdit
{
	Q_OBJECT
	public:
		
		PortLineEdit(QWidget *parent);
};

class GenericStringLineEdit : public IQFLineEdit
{
	Q_OBJECT
	public:
		GenericStringLineEdit(QWidget *parent, unsigned int maxlen = RULENAMELEN);
};


#endif
