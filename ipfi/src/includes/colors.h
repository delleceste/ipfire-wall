/* constants for colors in printf */
#define RED		    "\e[1;31m"
#define GREEN 		"\e[1;32m"
#define YELLOW 		"\e[1;33m"
#define WHITE 		"\e[1;37m"
#define BLUE 			"\e[1;34m"
#define CYAN 			"\e[1;36m"
#define VIOLET 		"\e[1;35m"
#define GRAY			"\e[0;37m"

#define DRED			"\e[0;31m" 		/* dark ones */
#define DGREEN		"\e[0;32m" 
#define DVIOLET 	"\e[0;35m"
#define MAROON 	"\e[0;33m"

#define BLACK	"\e[0;30m"

#define UNDERL 		"\e[4m"
#define BOLD				"\e[1m"

#define CLR 			"\e[00m" 			/* clear */
#define CLRNL		"\e[00m\n"		/* clear and newline */
#define NL				CLRNL

#define  PNL (printf("\e[00m\n") )
#define PCL (printf("\e[00m") )
#define PTAB (printf("\t") )
#define PUND (printf("\e[4m") )
#define PRED  (printf("\e[1;31m") )
#define PGRN (printf("\e[1;32m") )
#define PYEL (printf("\e[1;33m") )
#define PVIO (printf("\e[1;35m") )
#define PGRAY (printf("\e[0;37m") )
#define PBLU (printf("\e[1;34m") )
#define PCYAN (printf("\e[1;36m") )
#define PBLACK (printf("\e[0;30m") )
#define PDVIO (printf("\e[0;35m") )
/* Gray background */
#define PBGGRAY (printf("\e[0;47m") )
#define PBGWHITE (printf("\e[1;47m") )
#define PBOLD (printf("\e[1m") )
#define PBLINK	(printf("\e[0;5m") )
