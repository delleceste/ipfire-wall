#ifndef STYLESHEET_LOADER
#define STYLESHEET_LOADER

#include <QWidget>
#include <QString>
#include <QStringList>

class IQFComboBox;
class IQFCheckBox;
class QTableWidget;
class QTableWidgetItem;
class IQFPushButton;

class StylesheetLoader : public QWidget
{
	Q_OBJECT
	public:
		/** the constructor builds the interface and connects 
		 * signals/slots.
		 * Call setupWidget() to initialize the values of the
		 * widgets with QSettings values.
		 * The constructor does not call setupWidget() because
		 * setupWidget is a method which can be called to reload
		 * the QSettings values at any moment.
		 */
		StylesheetLoader(QWidget *parent);
		
		QString installDir() { return installdirname; }
		void setInstallDir(QString insd);
		QString& currentStyle() { return current_style; }
		QString currentStyleFilename() { return current_style_filename; }
		bool defaultStyle() { return default_stylesheet; }
		QString selectedQtStyle();
		
		/** Initializes the widgets with the values stored in QSettings.
		 * Call it when you want to initialize the stylesheet loader (e.g.
		 * after the constructor) and whenever you want to synchronize the 
		 * widget values with the values in QSettings.
		 */
		void setupWidget();
			
	signals:
		void sheetChanged(const QString &);
		
	protected:
		
	protected slots:
		void addSheet();
		void deleteSheet();
		void selectionChanged();
		void setDefaultStyle(bool);
		void qtStyleChanged(const QString&);
		
	private:
		QTableWidget *table;
		IQFPushButton *pbAdd, *pbRem;
		IQFCheckBox *cbNoStyle;
		IQFComboBox *cbQTStyles;
		QString current_style_filename, installdirname, current_style;
// 		QStringList styleslist;
		QStringList getItemElements(QString &filename);
		
		void loadTable();
		void addTableItem(QStringList texts);
		bool default_stylesheet;
};

#endif

