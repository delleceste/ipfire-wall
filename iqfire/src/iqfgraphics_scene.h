#ifndef IQFGRAPHICS_SCENE_H
#define IQFGRAPHICS_SCENE_H

#include <QGraphicsScene>
#include <QGraphicsView>
#include <QGraphicsRectItem>
#include <QGraphicsEllipseItem>
#include <QGraphicsItem>
#include <QString>
#include <QSettings>
#include <QVector>
#include <ipfire_structs.h>
#include <QMenu>

#include "iqfrule_adder.h"
#include "iqfruletree.h"

class QTimer;

class IQFRectItem : public QGraphicsRectItem
{
	
	public:		
	IQFRectItem(QGraphicsRectItem* parent, 
		    QVector<ipfire_rule*> *associated_rules);
	~IQFRectItem();
	QRect& rect() { return _rect; }
	void setRect(QRect &r) { _rect = r; }
	
	protected:
		bool sceneEvent(QEvent *e);
	private:
		QVector<ipfire_rule*> *p_rules;
		QRect _rect;
};

class IQFEllipseItem : public QGraphicsEllipseItem
{
	
	public:		
		IQFEllipseItem(QGraphicsRectItem* parent, 
			QVector<ipfire_rule*> *associated_rules);
		~IQFEllipseItem();
		QRect ellRect() { return ellrect; }
		void setEllRect(QRect rect) { ellrect = rect; }
		
	protected:
		bool sceneEvent(QEvent *e);
		
	private:
		QVector<ipfire_rule*> *p_rules;
		QRect ellrect;
};

class RuleScene : public QGraphicsView
{
	Q_OBJECT
	public:
		
		RuleScene(QWidget *parent);
		~RuleScene();
		
		QString buildHtmlStats(int direction);
	
	signals:
		void mouseOverItem(QString text);
		void mouseOverItemHelp(QString text);
		void mouseOutsideItem();
		void showStatsIn();
		void showStatsOut();
		void showStatsFwd();
		void blockInterface(bool);
		
	public slots:
		void addOutDNAT() { addDNAT(IPFI_OUTPUT); }
		void addDNAT() { addDNAT(IPFI_INPUT_PRE); }
		void addSNAT();
		void addMasquerade();
		void addPermissionIn() { addPermission(IPFI_INPUT); }
		void addPermissionOut() { addPermission(IPFI_OUTPUT); }
		void addPermissionFwd() { addPermission(IPFI_FWD); }
		void addDenialIn() { addDenial(IPFI_INPUT); }
		void addDenialOut() { addDenial(IPFI_OUTPUT); }
		void addDenialFwd() { addDenial(IPFI_FWD); }
		
	protected:
		void resizeEvent(QResizeEvent *);
		void mousePressEvent(QMouseEvent *);
		void mouseMoveEvent(QMouseEvent* event);
		
	protected slots:
	
		void applyAddRule();	
		void addCancel();
		
		void refreshStats();
		
		/* the following two are in iqfgraphics_html_stats... */
		void itemHovered(const QString &url);
		void itemClicked(const QString &url);
		
	private:
		QGraphicsScene *scene;
		QGraphicsView *view;
		QVector<ipfire_rule*> *p_rules;
		
		IQFEllipseItem* preitem, *postitem;
		IQFRectItem *initem, *outitem, *fwditem;
		
		QGraphicsTextItem *instats, *outstats, *fwdstats, *prestats, *poststats;
		
		void populateScene();
		QRectF myrect, default_item_rect;
		QString buildText(int direction);
		QString buildHelpText(int direction);
		
		QMenu *buildMenu(int direction);
		/* The rule adder */
		IQFRuleAdder* ruleadder;
		
		void addDNAT(int direction);
		
		void addDenial(int direction);
		void addPermission(int direction);
		
		void addRule(ipfire_rule &newrule);
		bool previouslyInsideItem;
		QTimer* timer;
};


#endif


