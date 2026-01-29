#ifndef IQF_STATS_H
#define IQF_STATS_H


/***************************************************************************
*   Copyright (C) 2008 by Giacomo Strangolino	   			  *
*   delleceste@gmail.com		   				  *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
***************************************************************************/

#include <ipfire_structs.h>
#include <QWidget>


class Log;
class KernelStatsPlot;

class IQFStats : public QWidget
{
	Q_OBJECT
	public:
		
	IQFStats(QWidget *parent, QWidget* legend_widget = NULL);
	~IQFStats();
	
	void hideAllCurves();
	void showCurve(int index);
	
	bool curveVisible(int index);
	
	protected:
	void showEvent(QShowEvent *e);
		
	protected slots:
		void updateStats();
		void showCurve(bool);
		void showStatsIn();
		void showStatsOut();
		void showStatsFwd();
		
	private:
		Log *iqflog;
		KernelStatsPlot *plot;
// 		QwtLegendItem *in_all, *in_block, *in_impl_block, *in_impl_all,
//   			*out_all, *out_block, *out_impl_block, *out_impl_all,
//   			*fwd_all, *fwd_block, *fwd_impl_block, *fwd_impl_all;
		void buildLegend(QWidget *legend_widget);
};

#endif



