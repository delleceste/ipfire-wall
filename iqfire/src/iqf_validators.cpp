#include "iqf_validators.h"
#include "iqf_utils.h"
#include <ipfire_structs.h> /* for IFNAMSIZ and RULENAMELEN */
#include "regexps.h"


PortValidator::PortValidator(QObject *parent) : QIntValidator(1, 65535, parent)
{
	/* since for ports we are always evaluating from a TreeWidgetItems */
	any = true; 
}

QValidator::State PortValidator::validate(QString & input, int & pos) const
{
	if(any && (input == "-"  || input == "any"))
		return QValidator::Acceptable;
	return QIntValidator::validate(input, pos);
}					
			
IPMaskValidator::IPMaskValidator(QObject *parent) : QRegExpValidator(QRegExp(IP_REGEXP), parent)
{
	
}

StringInputValidator::StringInputValidator(QObject *parent, unsigned int mlen) :
	QRegExpValidator(parent)
{
	QRegExp re(QString("[\\w\\d\\.\\!\\s\\?\\%\\*\\$\\@\\#\\-\\_~\\+\\=/\\>\\<\\'\\`]{0,%1}").
		arg(mlen));
	setRegExp(re);
}

QValidator::State StringInputValidator::validate(QString & input, int & pos) const
{
	return QRegExpValidator::validate(input, pos);
}

QValidator::State IPMaskValidator::validate(QString & input, int & pos) const
{
	/* netmask can be in an IP form or an integer from 0 to 32 */
	bool ok;
	int mask;
	mask = input.toInt(&ok);
	if(ok && mask >= 0 && mask <= 32)
		return QValidator::Acceptable;
	else
		return QRegExpValidator::validate(input, pos);
}

IPGenericValidator::IPGenericValidator(QObject *parent) :
		QRegExpValidator(QRegExp(IP_GENERIC_REGEXP), parent)
{
	
}

QValidator::State IPGenericValidator::validate(QString & input, int & pos) const
{
	return QRegExpValidator::validate(input, pos);
}
		
PortGenericValidator::PortGenericValidator(QObject *parent) :
		QRegExpValidator(QRegExp(PORT_GENERIC_REGEXP), parent)
{
	
}

QValidator::State PortGenericValidator::validate(QString & input, int & pos) const
{
	QValidator::State ret = QRegExpValidator::validate(input, pos);
	return ret;
	
}		
		
IPValidator::IPValidator(QObject *parent) : QRegExpValidator(QRegExp(IP_REGEXP), parent)
{
	any = false; /* the default for the line edit */
}

QValidator::State IPValidator::validate(QString & input, int & pos) const
{
	if(any && (input == "-" || input == "any" ))
	{
		return QValidator::Acceptable;
	}
	QValidator::State ret = QRegExpValidator::validate(input, pos);
	return ret;
}

IPIntervalValidator::IPIntervalValidator(QObject *parent) :
		QRegExpValidator(QRegExp(IP_INTERVAL_REGEXP), (parent))
{
	
}

QValidator::State IPIntervalValidator::validate(QString & input, int & pos) const
{	
	QValidator::State ret;
	if(input.contains("-") && input.count("-") == 1)
	{
		/* interval */
		ret = QRegExpValidator::validate(input, pos);
	}
	else if(input.contains('/') && input.count('/') == 1)
	{
		QString mod = input;
		mod.replace('/', '-');
		ret = QRegExpValidator::validate(mod, pos);
	}
	else
		ret = QRegExpValidator::validate(input, pos);
	return ret;
}

GenericIPLineEdit::GenericIPLineEdit(QWidget *parent) : IQFLineEdit(parent)
{
	IPGenericValidator *validator = new IPGenericValidator(this);
	setValidator(validator);
}

GenericPortLineEdit::GenericPortLineEdit(QWidget *parent) : IQFLineEdit(parent)
{
	PortGenericValidator *validator = new PortGenericValidator(this);
// 	PortIntervalValidator *validator = new PortIntervalValidator(this);
	setValidator(validator);
}

IPLineEdit::IPLineEdit(QWidget *parent) : IQFLineEdit(parent)
{
	IPValidator *validator = new IPValidator(this);
	setValidator(validator);
}

IPMaskLineEdit::IPMaskLineEdit(QWidget *parent): IQFLineEdit(parent)
{
	IPMaskValidator *validator = new IPMaskValidator(this);
	setValidator(validator);
}

PortLineEdit::PortLineEdit(QWidget *parent): IQFLineEdit(parent)
{
	PortValidator *validator = new PortValidator(this);
	setValidator(validator);
}

GenericStringLineEdit::GenericStringLineEdit(QWidget *parent, unsigned int maxlen) :
	IQFLineEdit(parent)
{
	StringInputValidator *validator = new StringInputValidator(this, maxlen);
	setValidator(validator);
}


