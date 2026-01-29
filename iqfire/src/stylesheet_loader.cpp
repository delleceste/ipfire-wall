#include <QTableWidget>
#include <QGridLayout>
#include <QFileDialog>
#include <QSettings>
#include <QtDebug>
#include <QDir>
#include <QFile> /* for copy() */
#include <QTextStream>
#include <QMessageBox>
#include <QStyleFactory>
#include <QApplication>
#include "stylesheet_loader.h"
#include "iqfwidgets.h"

#define ITEM_PATH_TYPE (QTableWidgetItem::UserType + 1)

StylesheetLoader::StylesheetLoader(QWidget *parent) : QWidget(parent)
{
	QSettings s;
	installdirname = QDir::homePath() + "/.IPFIRE/styles/";
	pbAdd = new IQFPushButton(this);
	cbNoStyle = new IQFCheckBox(this);
	cbQTStyles = new IQFComboBox(this);
	pbRem = new IQFPushButton(this);
	pbAdd->setText("Add new...");
	pbRem->setText("Remove");
	table = new QTableWidget(this);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	table->setColumnCount(5); /* style name, description, author, date */
	pbAdd->setObjectName("pbAddStyleSheet");
	pbRem->setObjectName("pbRemoveStyleSheet");
	cbNoStyle->setObjectName("cbNoStyle");
	cbQTStyles->setObjectName("comboQtStyles");
	
	cbNoStyle->setText("Qt default style");
	cbNoStyle->setChecked(s.value("QT_DEFAULT_STYLE", true).toBool());
	
	default_stylesheet = s.value("QT_DEFAULT_STYLE", true).toBool();
	if(cbNoStyle->isChecked())
		table->setEnabled(false);
	QGridLayout *lo = new QGridLayout(this);
	lo->setSpacing(4);
	lo->addWidget(table, 0, 0, 5, 5);
	lo->addWidget(pbAdd, 5, 3, 1, 1);
	lo->addWidget(pbRem, 5, 4, 1, 1);
	lo->addWidget(cbNoStyle, 5, 0, 1, 1);
	lo->addWidget(cbQTStyles, 5, 1, 1, 2);

	setInstallDir(installdirname);
	
	current_style_filename = s.value("STYLESHEET_FILENAME", 
		QString("%1example-flat.css").arg(installdirname)).toString();
	
	/* if the stylesheet directory does not exist, try to create it */
	QDir styleDir(installdirname);
	if(!styleDir.exists())
	{
		qDebug() << "The directory " << installdirname << " does not exist. Creating it.";
		if(styleDir.mkpath(installdirname))
		{
			qDebug() << "new path created successfully";
		}
		else
			QMessageBox::information(this, "Error",
				QString("Failed to create the directory \"%1\" for storing the styles.\n"
					"\nVerify that you have the write permission on that directory tree.")
				.arg(installdirname));
	}
	
	loadTable();
	connect(pbAdd, SIGNAL(clicked()), this, SLOT(addSheet()));
	connect(pbRem, SIGNAL(clicked()), this, SLOT(deleteSheet()));
	connect(table, SIGNAL(itemSelectionChanged()), this, SLOT(selectionChanged()));
	connect(cbNoStyle, SIGNAL(toggled(bool)), this, SLOT(setDefaultStyle(bool)));
	connect(cbQTStyles, SIGNAL(currentIndexChanged(const QString &)), this,
		SLOT(qtStyleChanged(const QString&)));
}

void StylesheetLoader::setDefaultStyle(bool en)
{
	QSettings s;
	table->setEnabled(!en);
	default_stylesheet = en;
	if(en)
	{
		current_style = "";
		current_style_filename = installdirname + "/\"\"";
		qApp->setStyleSheet(current_style_filename);
		qApp->setStyle(cbQTStyles->currentText());
	}
	else
		selectionChanged();
}

void StylesheetLoader::loadTable()
{
	QSettings s;
	int i;
	table->clear();
	table->setRowCount(0);
	table->setHorizontalHeaderLabels(QStringList() << "Name" << "Description" << "Author" << "Date" << "File name");
	QDir stylesdir(installdirname);
	/* look for the css files  */
	QStringList styleslist = stylesdir.entryList(QStringList() << "*.css", QDir::Files);
	
	for(i = 0; i < styleslist.size(); i++)
	{
		
		QString filepath = installdirname + styleslist[i];
		QStringList texts = getItemElements(filepath);	
		addTableItem(texts);
	}
	
	for(i = 0; i < table->rowCount(); i++)
	{
		QTableWidgetItem *item;
		item = table->itemAt(i, 4);
		if(item->text() == current_style_filename)
			item->setSelected(true);
			
	}
}

void StylesheetLoader::setInstallDir(QString insd) 
{
	installdirname = insd; 
	if(!installdirname.endsWith("/"))
		installdirname.append('/');
}

void StylesheetLoader::addSheet()
{
	QSettings s;
	QString dirname = s.value("LAST_STYLES_ADD_DIRNAME", installdirname).toString();
	
	QString newStyle = QFileDialog::getOpenFileName(this, tr("Open File"), dirname,
		tr("Cascading Style Sheets  (*.css)"));
	
	QString filename = newStyle.split('/').last();
	
	if(filename != QString())
	{
		QStringList texts;
		QFile origFile(newStyle);
		QFile newFile( installdirname + filename);
		if(newFile.exists())
		{
			QMessageBox::information(this, "Warning", QString("The file \"%1\"\n"
				"is already installed. You should find it into the list").arg(
				filename));
			return;
		}
		else if(!origFile.copy( installdirname + filename))
		{
			QMessageBox::information(this, "Error installing the new style",
				QString("Failed to install the style \"%1\" into the styles\n"
				"directory \"%2\"\n"
				"(Error: %3)").arg(newStyle).arg(installdirname + filename).arg(origFile.error()));
			return;
		}
		/* when we install another style, start looking into the old directory */
		s.setValue("LAST_STYLES_ADD_DIRNAME", newStyle.remove(filename));
		
		loadTable();
	}
}
		
void StylesheetLoader::deleteSheet()
{
	QList<QTableWidgetItem *> selected = table->selectedItems ();
	int i;
	for (i = 0; i < selected.size(); i++)
	{
		if(selected[i]->type() == ITEM_PATH_TYPE)
		{
			QString filename = installdirname + selected[i]->text();
			QFile delfile(filename);
			if(delfile.exists())
			{
				if(!delfile.remove())
					QMessageBox::information(this, "Error",
					QString("Error removing the file \"%1\"").
							arg(filename));
			}
			else
			{
				QMessageBox::information(this, "Warning",
						QString("Unable to remove the style file\n"
					"\"%1\":\n"
					"(%2)").arg(filename).arg(delfile.error()));
			}
		}
	}
	loadTable();
}

void StylesheetLoader::addTableItem(QStringList texts)
{
	if(texts.size() == 5)
	{
		int last_row = table->rowCount();
		QTableWidgetItem *itnam = new QTableWidgetItem(texts[0]);
		QTableWidgetItem *itdesc = new QTableWidgetItem(texts[1]);
		QTableWidgetItem *itauth = new QTableWidgetItem(texts[2]);
		QTableWidgetItem *itdate = new QTableWidgetItem(texts[3]);
		QTableWidgetItem *itpath = new QTableWidgetItem(texts[4], ITEM_PATH_TYPE);
 		table->setRowCount(last_row + 1);
		table->setItem(last_row, 0, itnam);
		table->setItem(last_row, 1, itdesc);
		table->setItem(last_row, 2, itauth);
		table->setItem(last_row, 3, itdate);
		table->setItem(last_row, 4, itpath);
	}
	else
	{
		qDebug() << "Unexpected number of items: " << texts.size();
	}
}

QStringList StylesheetLoader::getItemElements(QString &filename)
{
	QFile file(filename);
	QStringList ret; /* will contain Name, Description, Author, Date */
	QString name = "Unspecified", description = "No description", author = "Unknown", date = "Not indicated";
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		QMessageBox::information(this, "Error", QString("Error opening the file \"%1\""
				"\nfor reading: %2").arg(filename).arg(file.error()));
		return QStringList();
	}

	QTextStream in(&file);
	while (!in.atEnd())
	{
		QString line = in.readLine();
		if(line.contains("@name"))
			name = line.remove("//").remove("#").remove("@name").remove("*")
					.remove("/*").trimmed();
		else if(line.contains("@description"))
			description = line.remove("//").remove("#").remove("@description").trimmed();
		else if(line.contains("@author"))
			author = line.remove("//").remove("#").remove("@author").trimmed();
		else if(line.contains("@date"))
				date = line.remove("//").remove("#").remove("@date").trimmed();
	}
	ret << name << description << author << date << filename.split('/').last();
	return ret;
}

void StylesheetLoader::selectionChanged()
{
	QList<QTableWidgetItem *> selected = table->selectedItems ();
	int i;
	for (i = 0; i < selected.size(); i++)
	{
		if(selected[i]->type() == ITEM_PATH_TYPE)
		{
			QString filename = installdirname + selected[i]->text();
			QFile stylesheetFile( filename);
			if (!stylesheetFile.open(QIODevice::ReadOnly | QIODevice::Text))
				QMessageBox::information(this, "Error", 
					QString("Unable to open the style sheet\n"
					"\"%1\"").arg(filename));

			QTextStream in(&stylesheetFile);
			QString sheet;
			while (!in.atEnd()) {
				sheet += in.readLine();
			}
			qApp->setStyleSheet(sheet);
			
			current_style_filename = filename;
			current_style = sheet;
		}
	}
}

void StylesheetLoader::qtStyleChanged(const QString& str)
{
	QSettings s;
	if(cbNoStyle->isChecked())
		qApp->setStyle(str);
}

QString StylesheetLoader::selectedQtStyle() 
{ 
	return cbQTStyles->currentText(); 
}

void StylesheetLoader::setupWidget()
{
	QSettings s;
	QStringList qtStyles = QStyleFactory::keys();
	cbQTStyles->insertItems(0, qtStyles);
	QString currentStyle = s.value("QT_STYLE", "oxygen").toString();
	for(int i = 0; i < cbQTStyles->count(); i++)
	{
		if(cbQTStyles->itemText(i).compare(currentStyle, Qt::CaseInsensitive) == 0)
		{
			cbQTStyles->setCurrentIndex(i);
			break;
		}
	}
	cbNoStyle->setChecked(s.value("QT_DEFAULT_STYLE", true).toBool());
}

