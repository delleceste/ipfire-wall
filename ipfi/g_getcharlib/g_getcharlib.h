/* Lettura di caratteri dallo standard input in modo non bufferizzato 
 * Vengono intercettati anche i caratteri speciali: arrow keys, F1 ... F12
 * PAGE_UP, PAGE_DOWN ... 
 * Vengono utilizzate le librerie standard del C e si manipola la modalita'
 * di Input Output del terminale.
 * 
 *  (C) Giacomo Strangolino 2005
 *  Software Liberissimo! :)
 *  jacum@libero.it
 */
 
 
#ifndef MYGETCHAR_H
#define MYGETCHAR_H

#include<stdio.h>
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<termios.h>
#ifdef WINDOWS /* altrimenti g++ non trova ioctl() */
#include<sys/ioctl.h>
#else
#include<sgtty.h>
#endif
#include<errno.h>
#include<unistd.h>

/* microsecondi di attesa prima di una lettura successiva di stdin */
#define uSLEEP_INTERVAL 15 

/* definizioni: usano numeri negativi a caso.
 * Ridefinire se necessario con valori diversi.
 */
#define ARROW_LEFT -21000
#define ARROW_RIGHT -21001
#define ARROW_UP -21002
#define ARROW_DOWN -21003
#define ESC -21004
#define F1 -23005
#define F2 -23006
#define F3 -23007
#define F4 -23008
#define F5 -23009
#define F6 -23010
#define F7 -23011
#define F8 -23012
#define F9 -23013
#define F10 -23014
#define F11 -23015
#define F12 -23016
#define PAGSU -24017
#define PAGGIU -24018
#define FINE -24019
#define CANC -24020
#define INS -24021
#define INIZIO_RIGA -24022
#define CTRL_A -103001
#define CTRL_B -103002
#define CTRL_C -103003
#define CTRL_D -103004
#define CTRL_E -103005
#define CTRL_F -103006
#define CTRL_G -103007
#define CTRL_H -103008
#define CTRL_I -103009
#define CTRL_L -1030010
#define CTRL_M -1030011
#define CTRL_N -1030012
#define CTRL_O -1030013
#define CTRL_P -1030014
#define CTRL_Q -1030015
#define CTRL_R -1030016
#define CTRL_S -1030017
#define CTRL_T -1030018
#define CTRL_U -1030019
#define CTRL_V -1030020
#define CTRL_Z -1030021
#define CTRL_X -1030022
#define CTRL_Y -1030023
#define CTRL_W -1030024
#define CTRL_J -1030025
#define CTRL_K -1030026
#define BACKSPACE -1030027

/* funzioni */
/* salva lo stato del terminale */
int g_save_term();  
 /* imposta I/O non bufferizzato */  
int g_set_term();     
/* ripristina lo stato del terminale salvato da save_term() */
int g_reset_term();  
/* restituisce il carattere letto da stdin, con codici particolari 
 * per i tasti speciali */
int g_getchar();  
/* interpreta quanto intercettato da mygetchar() */
int parse_results(int* c);	
/* imposta il file descriptor associato a stdin a non bloccante */
int non_block();
/* imposta il file descriptor associato a stdin a bloccante */
int block();
#endif
