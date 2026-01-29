#ifndef IQF_ITEM_DELEGATE_H
#define IQF_ITEM_DELEGATE_H

#include <QItemDelegate>
#include <ipfire_structs.h> /* for RULENAMELEN */

class IQFLineEditGenericStringItemDelegate : public QItemDelegate
{
	Q_OBJECT
	public:
		IQFLineEditGenericStringItemDelegate(QObject *parent,
			unsigned int maxlinelen = RULENAMELEN);
		QWidget * createEditor(QWidget * parent, 
				const QStyleOptionViewItem & option,
     				const QModelIndex & index ) const;
	private:
		unsigned int _maxlen;
};

class IQFLineEditIPItemDelegate : public QItemDelegate
{
	Q_OBJECT
	public:
		IQFLineEditIPItemDelegate(QObject *parent = NULL);
		
		QWidget * createEditor (QWidget * parent, 
			const QStyleOptionViewItem & option,
   			const QModelIndex & index ) const;
// 		void setEditorData(QWidget *editor,
// 				const QModelIndex &index) const;
// 				
// 		void setModelData(QWidget *editor, QAbstractItemModel *model,
// 			const QModelIndex &index) const;
// 					
// 		void updateEditorGeometry(QWidget *editor,
// 			const QStyleOptionViewItem &option,
//    		const QModelIndex &/* index */) const;
	
};

class IQFLineEditPortItemDelegate : public QItemDelegate
{
	Q_OBJECT
	public:
		IQFLineEditPortItemDelegate(QObject *parent = NULL);
		
		QWidget * createEditor (QWidget * parent, 
			const QStyleOptionViewItem & option,
     			const QModelIndex & index ) const;
	
};


class IQFComboBoxProtoItemDelegate : public QItemDelegate
{
	Q_OBJECT
	public:
		IQFComboBoxProtoItemDelegate(QObject *parent = NULL);
		
		QWidget * createEditor (QWidget * parent, 
			const QStyleOptionViewItem & option,
     			const QModelIndex & index ) const;
		void setEditorData(QWidget *editor,
				const QModelIndex &index) const;
						
		void setModelData(QWidget *editor, QAbstractItemModel *model,
			const QModelIndex &index) const;
							
		void updateEditorGeometry(QWidget *editor,
			const QStyleOptionViewItem &option,
   		const QModelIndex &/* index */) const;
	
};

class IQFComboBoxYesNoItemDelegate : public QItemDelegate
{
	Q_OBJECT
	public:
		IQFComboBoxYesNoItemDelegate(QObject *parent = NULL);
		
		QWidget * createEditor (QWidget * parent, 
					const QStyleOptionViewItem & option,
     				const QModelIndex & index ) const;
		void setEditorData(QWidget *editor,
				   const QModelIndex &index) const;
						
		void setModelData(QWidget *editor, QAbstractItemModel *model,
				  const QModelIndex &index) const;
							
		void updateEditorGeometry(QWidget *editor,
					  const QStyleOptionViewItem &option,
       const QModelIndex &/* index */) const;
	
};







#endif


