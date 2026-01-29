#include "iqf_item_delegate.h"
#include "iqf_validators.h"
#include "iqf_utils.h"
#include <QLineEdit>
#include <QObject>

IQFLineEditGenericStringItemDelegate::IQFLineEditGenericStringItemDelegate(QObject *parent,
				unsigned int maxlen)
	: QItemDelegate(parent), _maxlen(maxlen)
{
	
}

QWidget * IQFLineEditGenericStringItemDelegate::createEditor (QWidget * parent, 
		const QStyleOptionViewItem & option, const QModelIndex & index ) const
{
	GenericStringLineEdit *editor = new GenericStringLineEdit(parent, _maxlen);
	QString style = "QLineEdit { border: 0px none; border-radius:0px;"
			"padding:0px; }";
	editor->setStyleSheet(style);
	Q_UNUSED(index);
	Q_UNUSED(option);
	return editor;
}

IQFLineEditIPItemDelegate ::IQFLineEditIPItemDelegate(QObject *parent) 
	: QItemDelegate(parent)
{
  
}

QWidget * IQFLineEditIPItemDelegate ::createEditor (QWidget * parent, 
			const QStyleOptionViewItem & option,
   			const QModelIndex & index ) const
{
	GenericIPLineEdit *editor = new GenericIPLineEdit(parent);
	printf("\e[1;32mcreateEditor()\e[0m\n");
	QString style = "QLineEdit { border: 2px none; border-radius:0px;"
		"padding:0px; }";
	editor->setStyleSheet(style);
	Q_UNUSED(index);
	Q_UNUSED(option);
	return editor;
}

IQFLineEditPortItemDelegate ::IQFLineEditPortItemDelegate(QObject *parent) 
	: QItemDelegate(parent)
{

}

QWidget * IQFLineEditPortItemDelegate ::createEditor (QWidget * parent, 
		const QStyleOptionViewItem & option,
  const QModelIndex & index ) const
{
	GenericPortLineEdit *editor = new GenericPortLineEdit(parent);
	QString style = "QLineEdit { border: 0px none; border-radius:0px;"
			"padding:0px; }";
	Q_UNUSED(index);
	Q_UNUSED(option);
	editor->setStyleSheet(style);
	return editor;
}

IQFComboBoxProtoItemDelegate ::IQFComboBoxProtoItemDelegate(QObject *parent) 
	: QItemDelegate(parent)
{
	
}

QWidget * IQFComboBoxProtoItemDelegate ::createEditor (QWidget * parent, 
		const QStyleOptionViewItem & option,
  const QModelIndex & index ) const
{
	QComboBox *editor = new QComboBox(parent);
	Q_UNUSED(index);
	Q_UNUSED(option);
	QString style = "QLineEdit { border: 0px none; border-radius:0px; "
			"padding:0px; background:white; border-width:0px; }";
	editor->setStyleSheet(style);
	editor->insertItems(0, QStringList() << "TCP" << "UDP" << "ICMP" << "IGMP" << "-");
	return editor;
}

void IQFComboBoxProtoItemDelegate::setEditorData(QWidget *editor,
	const QModelIndex &index) const
{
	QString text = index.model()->data(index, Qt::DisplayRole).toString();

	QComboBox* cb = static_cast<QComboBox *>(editor);
// 	le->setFlat(true);
	if(text == "TCP")
		cb->setCurrentIndex(0);
	else if(text == "UDP")
		cb->setCurrentIndex(1);
	else if(text == "ICMP")
		cb->setCurrentIndex(2);
	else if(text.contains("IGMP"))
		cb->setCurrentIndex(3);
	else if(text.contains("-"))
		cb->setCurrentIndex(4);
	
}

void IQFComboBoxProtoItemDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
				    const QModelIndex &index) const
{
	QComboBox *cb = static_cast<QComboBox *>(editor);

	QString text = cb->currentText();

	model->setData(index, text, Qt::EditRole);
}

void IQFComboBoxProtoItemDelegate::updateEditorGeometry(QWidget *editor,
					    const QStyleOptionViewItem &option, const QModelIndex &/* index */) const
{
	editor->setGeometry(option.rect);
}

IQFComboBoxYesNoItemDelegate ::IQFComboBoxYesNoItemDelegate(QObject *parent) 
	: QItemDelegate(parent)
{
	
}

QWidget * IQFComboBoxYesNoItemDelegate ::createEditor (QWidget * parent, 
		const QStyleOptionViewItem & option,
  const QModelIndex & index ) const
{
	QComboBox *editor = new QComboBox(parent);
	Q_UNUSED(index);
	Q_UNUSED(option);
	QString style = "QLineEdit { border: 0px none; border-radius:0px; "
			"padding:0px; background:white; border-width:0px; }";
	editor->setStyleSheet(style);
	editor->insertItems(0, QStringList() << "YES" << "NO");
	return editor;
}

void IQFComboBoxYesNoItemDelegate::setEditorData(QWidget *editor,
		const QModelIndex &index) const
{
	QString text = index.model()->data(index, Qt::DisplayRole).toString();

	QComboBox* cb = static_cast<QComboBox *>(editor);
// 	le->setFlat(true);
	if(text == "YES")
		cb->setCurrentIndex(0);
	else if(text == "NO")
		cb->setCurrentIndex(1);
	
}

void IQFComboBoxYesNoItemDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
		const QModelIndex &index) const
{
	QComboBox *cb = static_cast<QComboBox *>(editor);

	QString text = cb->currentText();

	model->setData(index, text, Qt::EditRole);
}

void IQFComboBoxYesNoItemDelegate::updateEditorGeometry(QWidget *editor,
		const QStyleOptionViewItem &option, const QModelIndex &/* index */) const
{
	editor->setGeometry(option.rect);
}


