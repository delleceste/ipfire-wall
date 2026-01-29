#include <QString>
#include <QColor>
#include <QFont>

#ifdef QTEXT_COLOR

#define ColGreen	setTextColor(Qt::green); 
#define ColRed	 	setTextColor(Qt::red);
#define ColW		setTextColor(Qt::white);
#define ColB		setTextColor(Qt::black);
#define ColViolet	setTextColor(Qt::magenta);
#define ColGray 	setTextColor(Qt::gray);
#define ColYellow	setTextColor(Qt::darkYellow);
#define ColBlue		setTextColor(Qt::blue);

#define ColIn setTextColor(in_color);
#define ColOut setTextColor(out_color);
#define ColPre setTextColor(pre_color);
#define ColPost setTextColor(post_color);
#define ColFwd setTextColor(fwd_color);

#define ColTcp setTextColor(tcp_color);
#define ColUdp setTextColor(udp_color);
#define ColIcmp setTextColor(icmp_color);

#define ColAcc setTextColor(acc_color);
#define ColDen setTextColor(den_color);
#define ColUnk setTextColor(unkn_color);

#define ColSnat setTextColor(snat_color);
#define ColDnat setTextColor(dnat_color);

/* Bold Underline Italic */
#define Underline setFontUnderline(true);
#define NoUnderline setFontUnderline(false);

#define Bold setFontWeight(fontWeight() + 2);
#define NoBold setFontWeight(fontWeight() - 2);

#define Italic setFontItalic(true);
#define NoItalic setFontItalic(false);


#else 

#define ColGreen	; 
#define ColRed	 	;
#define ColW		;
#define ColB		;
#define ColViolet	;
#define ColGray		;
#define ColYellow	;
#define ColBlue		;

#define ColIn ;
#define ColOut ;
#define ColPre ;
#define ColPost ;
#define ColFwd ;

#define ColTcp ;
#define ColUdp ;
#define ColIcmp ;

#define ColAcc ;
#define ColUdp ;
#define ColUnk ;
#define ColSnat ;
#define ColDnat ;
#define ColDen ;

#define Underline ;
#define NoUnderline ;

#define Bold ;
#define NoBold ;

#define Italic ;
#define NoItalic ;

#endif
