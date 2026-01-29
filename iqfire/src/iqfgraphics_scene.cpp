#include "iqfgraphics_scene.h"
#include "iqf_message_proxy.h"
#include "iqflog.h"
#include "iqfpolicy.h"
#include "iqfruletree.h"
#include "iqfruletree_item.h"
#include "iqfstats_proxy.h"
#include "colors.h"
#include <ipfire_structs.h>
#include <QtDebug>
#include <QGridLayout>
#include <QPushButton>
#include <QResizeEvent>
#include <QGraphicsTextItem>
#include <QTimer>
#include <QPainterPath>
#include <QGraphicsPathItem>
#include <QLinearGradient>
#include <QSettings>


IQFRectItem::IQFRectItem(QGraphicsRectItem* parent, 
	    QVector<ipfire_rule*> *associated_rules) :
	    QGraphicsRectItem(parent), p_rules(associated_rules)
{
	
}
	
IQFRectItem::~IQFRectItem()
{
	
}

bool IQFRectItem::sceneEvent(QEvent *e)
{
	return QGraphicsRectItem::sceneEvent(e);
}

IQFEllipseItem::IQFEllipseItem(QGraphicsRectItem* parent, 
	    QVector<ipfire_rule*> *associated_rules) :
		QGraphicsEllipseItem(parent), p_rules(associated_rules)
{
	
}
	
IQFEllipseItem::~IQFEllipseItem()
{
	
}

bool IQFEllipseItem::sceneEvent(QEvent *e)
{
	return QGraphicsEllipseItem::sceneEvent(e);
}

RuleScene::RuleScene(QWidget * parent_w)
	: QGraphicsView(parent_w)
{
	QSettings s;
	QGridLayout* lo = new QGridLayout(parent_w);
	scene = new QGraphicsScene(QRect(0, 0, 500, 450));
	
	setRenderHint(QPainter::Antialiasing);
	setBackgroundBrush(QBrush(QColor(220, 220, 255)));
	
	populateScene();
	/* set the view scene */
	setScene(scene);
	show();
	qDebug() << "* rule view";
	lo->setMargin(0);
	lo->addWidget(this, 0, 0);	
	timer = new QTimer(this);
	timer->setSingleShot(false);
	timer->setInterval(s.value("RULE_SCENE_TIMEOUT", 2000).toInt());
	timer->start();
	previouslyInsideItem = false;
	connect(timer, SIGNAL(timeout()), this, SLOT(refreshStats()));
}

RuleScene::~RuleScene()
{
	
}


void RuleScene::refreshStats()
{
	/* Do not get the statistics if the scene is not visible */
	if(!isVisible())
		return;
	/* Get the reference to the singleton */
	IQFStatsProxy *statsp = IQFStatsProxy::statsProxy(this);
	struct kernel_stats kstats = statsp->getStats();
	
	QString pre, post, in, out, fwd;
	
	pre = buildHtmlStats(IPFI_INPUT_PRE);
	post = buildHtmlStats(IPFI_OUTPUT_POST);
	in = buildHtmlStats(IPFI_INPUT);
	out = buildHtmlStats(IPFI_OUTPUT);
	fwd = buildHtmlStats(IPFI_FWD);
	
	instats->setHtml(in);
	outstats->setHtml(out);
	fwdstats->setHtml(fwd);
	prestats->setHtml(pre);
	poststats->setHtml(post);
}

void RuleScene::populateScene()
{
	int ysteps = 12;
	int xsteps = 19;
	myrect = scene->sceneRect();
	qreal vertical_step = myrect.height()/ysteps;
	qreal horizontal_step = myrect.width()/xsteps;
	QPointF top_left = myrect.topLeft();
// 	qDebug() << "punto top left: " << top_left;
	QPointF position = QPointF(top_left.rx() + 5 * horizontal_step, top_left.ry() + 7 * vertical_step);
	
	default_item_rect = QRectF(0, 0, 3 *horizontal_step,  2*vertical_step);
	
	/* position of initem */
	
	initem = (IQFRectItem*) scene->addRect(default_item_rect);
	initem->setFlags(QGraphicsItem::ItemIsSelectable);
	initem->setPos((position));
	initem->setAcceptsHoverEvents(true);
	initem->setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton);
	QLinearGradient ingradient(QPointF(0, 0), QPointF(default_item_rect.bottomRight()));
	ingradient.setColorAt(0, Qt::gray);
	ingradient.setColorAt(1, QColor(100, 255, 100));
	initem->setBrush(QBrush(ingradient));
	
	/* outitem */
	outitem  = (IQFRectItem*) scene->addRect(default_item_rect);	
	position = QPointF(top_left.rx() + 11 * horizontal_step, top_left.ry() + 7 * vertical_step);
	outitem->setPos(position);
	outitem->setFlags(QGraphicsItem::ItemIsSelectable);
	outitem->setAcceptsHoverEvents(true);
	outitem->setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton);
	QLinearGradient outgradient(QPointF(0, 0), QPointF(default_item_rect.bottomRight()));
	outgradient.setColorAt(0, Qt::gray);
	outgradient.setColorAt(1, QColor(78, 217, 217));
	outitem->setBrush(QBrush(outgradient));
	
	/* fwditem */
	fwditem = (IQFRectItem*) scene->addRect(default_item_rect);
	position = QPointF(top_left.rx() + 8 * horizontal_step, top_left.ry() + 1 * vertical_step);
	fwditem->setPos(position);
	fwditem->setFlags(QGraphicsItem::ItemIsSelectable);
	fwditem->setAcceptsHoverEvents(true);
	fwditem->setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton);
	QLinearGradient fwdgradient(QPointF(0, 0), QPointF(default_item_rect.bottomRight()));
	fwdgradient.setColorAt(0, Qt::white);
	fwdgradient.setColorAt(1, QColor(187, 164, 89));
	fwditem->setBrush(QBrush(fwdgradient));
	
	/* pre, post */
	preitem = (IQFEllipseItem *) scene->addEllipse(default_item_rect);
	position = QPointF(top_left.rx() + 1 * horizontal_step, top_left.ry() + 4 * vertical_step);
	preitem->setPos(position);
	preitem->setFlags(QGraphicsItem::ItemIsSelectable);
	preitem->setAcceptsHoverEvents(true);
	preitem->setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton);
	preitem->setBrush(QBrush(KDARKGREEN));
	QLinearGradient pregradient(QPointF(0, 0), QPointF(default_item_rect.bottomRight()));
	pregradient.setColorAt(0, Qt::gray);
	pregradient.setColorAt(1, QColor(200, 200, 24));
	preitem->setBrush(QBrush(pregradient));
	
	postitem = (IQFEllipseItem *) scene->addEllipse(default_item_rect);
	position = QPointF(top_left.rx() + 15 * horizontal_step, top_left.ry() + 4 * vertical_step);
	postitem->setPos(position);
	postitem->setFlags(QGraphicsItem::ItemIsSelectable);
	postitem->setAcceptsHoverEvents(true);
	postitem->setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton);
	QLinearGradient postgradient(QPointF(0, 0), QPointF(default_item_rect.bottomRight()));
	postgradient.setColorAt(0, Qt::white);
	postgradient.setColorAt(1, QColor(10, 100, 110));
	postitem->setBrush(QBrush(postgradient));

	/* draw the line from pre to fwd */

	QGraphicsLineItem* line_pre_fwd = scene->addLine(
			preitem->scenePos().x() + preitem->rect().topRight().x(),
			preitem->scenePos().y() + preitem->rect().topRight().y() + preitem->rect().height()/3, 
			fwditem->scenePos().x(), 
			fwditem->scenePos().y() + default_item_rect.height()/2);
	
	
	QGraphicsLineItem* line_pre_in = scene->addLine(
			preitem->scenePos().x() + preitem->rect().topRight().x(),
			preitem->scenePos().y() + preitem->rect().topRight().y() + 
					preitem->rect().height() * 3/4, 
			initem->scenePos().x(), 
			initem->scenePos().y() + default_item_rect.height()/2);
	
	QGraphicsLineItem* line_fwd_post = scene->addLine(
			fwditem->scenePos().x() + default_item_rect.width(),
			fwditem->scenePos().y() + default_item_rect.height()/2, 
			postitem->scenePos().x(), 
			postitem->scenePos().y() + default_item_rect.height()/3);
	
	QGraphicsLineItem* line_out_post = scene->addLine(
			postitem->scenePos().x(), 
			postitem->scenePos().y() + default_item_rect.height()*3/4,
			outitem->scenePos().x() + default_item_rect.width(),
			outitem->scenePos().y() + default_item_rect.height()/2
			);
	
// 	qDebug() << "Adding initem";
	Q_UNUSED(line_pre_fwd);
	Q_UNUSED(line_pre_in);
	Q_UNUSED(line_fwd_post);
	Q_UNUSED(line_out_post);
	
	prestats = scene->addText("Pre stats");
	prestats->setPos(preitem->pos());
	prestats->moveBy(-default_item_rect.width()/2, -default_item_rect.width()/2);
	instats = scene->addText("INPUT stats");
	instats->setPos(initem->pos());
	instats->moveBy(-default_item_rect.width()/2, default_item_rect.width() + 5);
	instats->setTextInteractionFlags(Qt::TextBrowserInteraction);
	poststats = scene->addText("POST stats");
	poststats->setPos(postitem->pos());
	poststats->moveBy(-default_item_rect.width()/5*4, -default_item_rect.width()/2);
	outstats = scene->addText("OUT stats");
	outstats->setPos(outitem->pos());
	outstats->moveBy(-default_item_rect.width()/2, default_item_rect.width() + 5);
	outstats->setTextInteractionFlags(Qt::TextBrowserInteraction);
	fwdstats = scene->addText("FWD stats");
	fwdstats->setPos(fwditem->pos());
	fwdstats->moveBy(-default_item_rect.width()/2, default_item_rect.width() + 4);
	fwdstats->setTextInteractionFlags(Qt::TextBrowserInteraction);
	
	QGradientStops stops;
	stops << QGradientStop(0.210, KDARKGREEN) << QGradientStop(0.368, KGREEN) <<
		QGradientStop(0.52, KDARKYELLOW) << QGradientStop(0.71, KCYAN) <<
		QGradientStop(0.947, KBLUE);
	//QPointF start = preitem->scenePos();
	QPointF start(0, 0);
	//start.setX(start.x() - horizontal_step);
	//QPointF end = postitem->scenePos();
	//end.setX(end.x() + horizontal_step);
	QPointF end = postitem->scenePos();
	end.setX(end.x() + horizontal_step);
	end.setY(end.y() + 8 * vertical_step);
	QLinearGradient gradient(start,end);
	gradient.setSpread(QGradient::PadSpread);
	gradient.setColorAt(0, Qt::white);
	gradient.setColorAt(1, QColor(140, 144, 184));
// 	gradient.setStops(stops);
	setBackgroundBrush(gradient);
	
	QGraphicsTextItem *textin = scene->addText("INPUT");
	textin->setPos(initem->pos() + QPointF(20, 20));
	QGraphicsTextItem *textpost = scene->addText("POST\nROUTING");
	textpost->setPos(postitem->pos() + QPointF(10, 20));
// 	textpost->setDefaultTextColor(Qt::darkBlue);
	QGraphicsTextItem *textout = scene->addText("OUT");
	textout->setPos(outitem->pos() + QPointF(20, 20));
	QGraphicsTextItem *textfwd = scene->addText("FWD");
	textfwd->setPos(fwditem->pos() + QPointF(20, 20));
	QGraphicsTextItem *textpre = scene->addText("PRE\nROUTING");
	textpre->setPos(preitem->pos() + QPointF(10, 20));
// 	textpre->setDefaultTextColor(Qt::darkYellow);
	
}

void RuleScene::resizeEvent(QResizeEvent *event)
{
	double ratio;
	double dx = 0, dy = 0;
	if (event->size().width() < event->size().height())
	{
		ratio = ((double)event->size().width())/scene->sceneRect().size().width();
		dy = (event->size().height()-event->size().width());
	}
	else
	{
		ratio = ((double)event->size().height())/scene->sceneRect().height();
		dx = (event->size().width()-event->size().height());
	}

	QMatrix m;
	m.scale(ratio, ratio);
	m.translate(dx, dy);
	setMatrix(m);

}

QMenu * RuleScene::buildMenu(int direction)
{
	QMenu *menu = NULL;
	switch(direction)
	{
		case IPFI_INPUT_PRE:
			if(getuid() == 0)
			{
				menu = new QMenu(this);
				menu->addAction("Add DNAT rule", this, SLOT(addDNAT()));
			}
			break;
		case IPFI_OUTPUT_POST:
			if(getuid() == 0)
			{
				menu = new QMenu(this);
				menu->addAction("Add SNAT rule", this, SLOT(addSNAT()));
				menu->addAction("Add MASQUERADE rule", this, SLOT(addMasquerade()));
			}
			break;
		case IPFI_OUTPUT:
			menu = new QMenu(this);
			if(getuid() == 0)
			{
				menu->addAction("Add DNAT rule", this, SLOT(addOutDNAT()));
			}
			menu->addAction("Add Permission rule", this, SLOT(addPermissionOut()));
			menu->addAction("Add Denial rule", this, SLOT(addDenialOut()));
			break;
			
			/* no break here */
		case IPFI_INPUT:
			menu = new QMenu(this);
			menu->addAction("Add Permission rule", this, SLOT(addPermissionIn()));
			menu->addAction("Add Denial rule", this, SLOT(addDenialIn()));
			break;
			
		case IPFI_FWD:
			menu = new QMenu(this);
			menu->addAction("Add Permission rule", this, SLOT(addPermissionFwd()));
			menu->addAction("Add Denial rule", this, SLOT(addDenialFwd()));
			break;
		
		
		
	}
	return menu;
}

void RuleScene::mousePressEvent(QMouseEvent *e)
{
	QMenu *rightMenu = NULL;
	
	QPointF mousePos = mapToScene(e->pos());
	QRectF inrect = QRectF(initem->scenePos(), QSizeF(default_item_rect.width(),
			       default_item_rect.height()));
	QRectF outrect = QRectF(outitem->scenePos(), QSizeF(default_item_rect.width(),
				default_item_rect.height()));
					   
	QRectF prerect = QRectF(preitem->scenePos(), QSizeF(default_item_rect.width(),
				default_item_rect.height()));
	QRectF postrect = QRectF(postitem->scenePos(), QSizeF(default_item_rect.width(),
				 default_item_rect.height()));
	
	QRectF fwdrect = QRectF(fwditem->scenePos(), QSizeF(default_item_rect.width(),
				default_item_rect.height()));
	
	
	if(e->button() == Qt::LeftButton)
	{
		if(inrect.contains(mousePos))
			emit showStatsIn();
		else if(outrect.contains(mousePos))
			emit showStatsOut();
		else if(fwdrect.contains(mousePos))
			emit showStatsFwd();
	}
	else if(e->button() == Qt::RightButton)
	{
		if(inrect.contains(mousePos))
			rightMenu = buildMenu(IPFI_INPUT);
		else if(outrect.contains(mousePos))
			rightMenu = buildMenu(IPFI_OUTPUT);
		else if(prerect.contains(mousePos))
			rightMenu = buildMenu(IPFI_INPUT_PRE);
		else if(postrect.contains(mousePos))
			rightMenu = buildMenu(IPFI_OUTPUT_POST);
		else if(fwdrect.contains(mousePos))
			rightMenu = buildMenu(IPFI_FWD);
		else
			return;
		
		if(rightMenu != NULL)
			rightMenu->exec(e->globalPos());
	}
}

void RuleScene::addRule(ipfire_rule &newrule)
{
	Policy *iqfp = Policy::instance();
	if(iqfp->appendRule(newrule) >= 0)
	{
		iqfp->notifyRulesChanged(); /* to update the tree */
		Log::log()->appendOk(QString("The rule \"%1\" has been successfully added\n"
			"from the rule scene").arg(newrule.rulename));
	}
	else
		Log::log()->appendFailed(QString(
			 "Error adding the rule \"%1\" from the rule scene!").
				arg(newrule.rulename));
}

void RuleScene::addDNAT(int direction)
{
	/* disable interaction with the tree and signal the 
	* mainwindow that the user is modifying/adding a rule
	*/
	emit blockInterface(true);
	qDebug() << "add dnat" << direction;
	IQFRuleAdder *adder = NULL;
	if(direction == IPFI_INPUT_PRE)
		adder = new IQFRuleAdder(this, NULL, IQFRuleAdder::Add,
					       TRANSLATION, direction,
					       IQFRuleTreeItem::DNAT);
	else if(direction == IPFI_OUTPUT)
		adder = new IQFRuleAdder(this, NULL, IQFRuleAdder::Add,
			TRANSLATION, direction,
   			IQFRuleTreeItem::OUTDNAT);
	else
	{
		qDebug() << "void RuleScene::addDNAT(int direction): invalid direction";
	}
	adder->fixPolicy(TRANSLATION);
	adder->fixDirection(direction);
	if(direction == IPFI_INPUT_PRE)
		adder->fixNatType("DNAT");
	else if(direction == IPFI_OUTPUT)
		adder->fixNatType("OUTDNAT");
	connect(adder, SIGNAL(applyOk()), this, SLOT(applyAddRule()));
	connect(adder, SIGNAL(applyCancel()), this, SLOT(addCancel()));
	adder->show();
}

void RuleScene::addSNAT()
{
	/* disable interaction with the tree and signal the 
	* mainwindow that the user is modifying/adding a rule
	*/
	emit blockInterface(true);
	qDebug() << "add snat";
	IQFRuleAdder *adder = new IQFRuleAdder(this, NULL, IQFRuleAdder::Add,
			TRANSLATION, IPFI_OUTPUT_POST,
  			 IQFRuleTreeItem::SNAT);
	adder->fixPolicy(TRANSLATION);
	adder->fixDirection(IPFI_OUTPUT_POST);
	adder->fixNatType("SNAT");
	connect(adder, SIGNAL(applyOk()), this, SLOT(applyAddRule()));
	connect(adder, SIGNAL(applyCancel()), this, SLOT(addCancel()));
	adder->show();
}

void RuleScene::addMasquerade()
{
	/* disable interaction with the tree and signal the 
	* mainwindow that the user is modifying/adding a rule
	*/
	emit blockInterface(true);
	IQFRuleAdder *adder = new IQFRuleAdder(this, NULL, IQFRuleAdder::Add,
					TRANSLATION, IPFI_OUTPUT_POST,
			IQFRuleTreeItem::MASQ);
	adder->fixNatType("MASQUERADE");
	adder->fixPolicy(TRANSLATION);
	adder->fixDirection(IPFI_OUTPUT_POST);
	connect(adder, SIGNAL(applyOk()), this, SLOT(applyAddRule()));
	connect(adder, SIGNAL(applyCancel()), this, SLOT(addCancel()));
	adder->show();
}

void RuleScene::addDenial(int direction)
{
	/* disable interaction with the tree and signal the 
	* mainwindow that the user is modifying/adding a rule
	*/
	emit blockInterface(true);
	qDebug() << "add denial" << direction;
	IQFRuleAdder *adder = new IQFRuleAdder(this, NULL, IQFRuleAdder::Add, DENIAL, direction,
					       IQFRuleTreeItem::FILTER);
	adder->fixPolicy(DENIAL);
	adder->fixDirection(direction);
	connect(adder, SIGNAL(applyOk()), this, SLOT(applyAddRule()));
	connect(adder, SIGNAL(applyCancel()), this, SLOT(addCancel()));
	adder->show();
}

void RuleScene::addPermission(int direction)
{
	/* disable interaction with the tree and signal the 
	* mainwindow that the user is modifying/adding a rule
 	*/
	emit blockInterface(true);
	qDebug() << "add permission" << direction;
	IQFRuleAdder *adder = new IQFRuleAdder(this, NULL, IQFRuleAdder::Add, ACCEPT, direction,
			IQFRuleTreeItem::FILTER);
	adder->fixPolicy(ACCEPT);
	adder->fixDirection(direction);
	connect(adder, SIGNAL(applyOk()), this, SLOT(applyAddRule()));
	connect(adder, SIGNAL(applyCancel()), this, SLOT(addCancel()));
	adder->show();
}

void RuleScene::applyAddRule()
{
	IQFRuleAdder *radder = qobject_cast<IQFRuleAdder*>(sender());
	if(radder != NULL)
	{
		ipfire_rule newrule = radder->Rule();
		addRule(newrule = radder->Rule());
	}
	else
		QMessageBox::critical(this, "iqFIREWALL:error!",
			"Error adding the rule! Contact the author for this error!");
	emit blockInterface(false);
}

void RuleScene::addCancel()
{
	emit blockInterface(false);
}


void RuleScene::mouseMoveEvent(QMouseEvent *e)
{
	QPointF mousePos = mapToScene(e->pos());
	QRectF inrect = QRectF(initem->scenePos(), QSizeF(default_item_rect.width(),
		default_item_rect.height()));
	QRectF outrect = QRectF(outitem->scenePos(), QSizeF(default_item_rect.width(),
				default_item_rect.height()));
					   
	QRectF prerect = QRectF(preitem->scenePos(), QSizeF(default_item_rect.width(),
				default_item_rect.height()));
	QRectF postrect = QRectF(postitem->scenePos(), QSizeF(default_item_rect.width(),
				 default_item_rect.height()));
	
	QRectF fwdrect = QRectF(fwditem->scenePos(), QSizeF(default_item_rect.width(),
				default_item_rect.height()));
	
	if(inrect.contains(mousePos))
	{
		if(!previouslyInsideItem)
		{
			emit mouseOverItem(buildText(IPFI_INPUT));
			emit mouseOverItemHelp(buildHelpText(IPFI_INPUT));
			previouslyInsideItem = true;
		}
	}
	else if(outrect.contains(mousePos))
	{
		if(!previouslyInsideItem)
		{
			previouslyInsideItem = true;
			emit mouseOverItem(buildText(IPFI_OUTPUT));
			emit mouseOverItemHelp(buildHelpText(IPFI_OUTPUT));
		}
	}
	else if(prerect.contains(mousePos))
	{
		if(!previouslyInsideItem)
		{	
			previouslyInsideItem = true;
			emit mouseOverItem(buildText(IPFI_INPUT_PRE));
			emit mouseOverItemHelp(buildHelpText(IPFI_INPUT_PRE));
		}
	}
	else if(postrect.contains(mousePos))
	{
		if(!previouslyInsideItem)
		{	
			previouslyInsideItem = true;
			emit mouseOverItem(buildText(IPFI_OUTPUT_POST));
			emit mouseOverItemHelp(buildHelpText(IPFI_OUTPUT_POST));
		}
	}
	else if(fwdrect.contains(mousePos))
	{
		if(!previouslyInsideItem)
		{	
			previouslyInsideItem = true;
			emit mouseOverItem(buildText(IPFI_FWD));
			emit mouseOverItemHelp(buildHelpText(IPFI_FWD));
		}
	}
	else if(previouslyInsideItem)
	{
// 		emit mouseOutsideItem(); /* it would not allow to read and move the mouse 
//		over another item. 
		previouslyInsideItem = false;
	}
	
}

QString RuleScene::buildText(int direction)
{
	QString t;
	IQFMessageProxy *msgp = IQFMessageProxy::msgproxy();
	switch(direction)
	{
		case IPFI_INPUT:
			t = msgp->getInfo("rulescene_in");
			//t = "Input <a href=\"ADD_INPUT\">add a rule</a>.";
			break;
		case IPFI_INPUT_PRE:
			t = msgp->getInfo("rulescene_pre");
			break;
		case IPFI_OUTPUT:
			t = msgp->getInfo("rulescene_out");
			break;
		case IPFI_OUTPUT_POST:
			t = msgp->getInfo("rulescene_post");
			break;
		case IPFI_FWD:
			t = msgp->getInfo("rulescene_fwd");
			break;
	}
	return t;
}

QString RuleScene::buildHelpText(int direction)
{
	QString t;
	IQFMessageProxy *msgp = IQFMessageProxy::msgproxy();
	switch(direction)
	{
		case IPFI_INPUT:
			t = msgp->getHelp("rulescene_in");
			break;
		case IPFI_INPUT_PRE:
			t = msgp->getHelp("rulescene_pre");
			break;
		case IPFI_OUTPUT:
			t = msgp->getHelp("rulescene_out");
			break;
		case IPFI_OUTPUT_POST:
			t = msgp->getHelp("rulescene_post");
			break;
		case IPFI_FWD:
			t = msgp->getHelp("rulescene_fwd");
			break;
	}
	return t;
}







