/* Lettura di caratteri dallo standard input in modo non bufferizzato 
 * Vengono intercettati anche i caratteri speciali: arrow keys, F1 ... F12
 * PAGE_UP, PAGE_DOWN ... 
 * Vengono utilizzate le librerie standard del C e si manipola la modalita'
 * di Input Output del terminale.
 * Questa e' la funzione main() di test della libreria "mygetcharlib".
 * Compilazione: gcc -o chars arrows_test.c mygetcharlib.c -Wall
 * 
 *  (C) Giacomo Strangolino 2005
 *  Software Liberissimo! :)
 *  jacum@libero.it
 */


#include <signal.h>
#include "g_getcharlib.h"

void gestore_uscita_mygetchar(int signum);

int main()
{
   int c;
   /* gestore della terminazione */
   signal(SIGINT, gestore_uscita_mygetchar);
   /* salviamo lo stato attuale del terminale */
   if(g_save_term() < 0)
      {
         perror("\e[1;31mErrore di salvataggio dello stato del terminale!\e[1;37m\n");
	 return EXIT_FAILURE;
      }
   printf("Inserisci del testo. Nota come vengono intercettati anche i tasti \e[1;32mspeciali\e[1;37m\n" \
            "Freccia su, freccia giu', INS, FINE, F1...F12...\n"
	    "Control-C per \e[1;31mterminare\e[1;37m.\n");   
   while(1)
   {
      c = g_getchar();
      if(c == ARROW_LEFT)
         printf("\nARROW_LEFT\n");
     else if(c == ARROW_RIGHT)
         printf("\nARROW_RIGHT\n");
      else if(c == ARROW_UP)
         printf("\nARROW_UP\n");
      else if(c == ARROW_DOWN)
         printf("\nARROW_DOWN\n");
      else if(c == ESC)
         printf("\nESC\n");	
      else if(c == F1)
         printf("\nF1\n");	
      else if(c == F2)
         printf("\nF2\n");
      else if(c == F3)
         printf("\nF3\n"); 	 
      else if(c == F4)
         printf("\nF4\n");
      else if(c == F5)
         printf("\nF5\n"); 	 
      else if(c == F6)
         printf("\nF6\n"); 	 
      else if(c == F7)
         printf("\nF7\n"); 	 
      else if(c == F8)
         printf("\nF8\n"); 	  
      else if(c == F9)
         printf("\nF9\n"); 	 
      else if(c == F10)
         printf("\nF10\n"); 	 
      else if(c == F11)
         printf("\nF11\n"); 	 
      else if(c == F12)
         printf("\nF12\n"); 
      else if(c == PAGSU)
         printf("\nPAG_SU\n"); 	 
      else if(c == PAGGIU)
         printf("\nPAG_GIU\n"); 
      else if(c == FINE)
         printf("\nFINE\n");
      else if(c == CANC)
         printf("\nCANC\n");
      else if(c == INS)
         printf("\nINS\n");	 
      else if(c == INIZIO_RIGA)
         printf("\nINIZIO_RIGA\n");	
      /* caratteri di controllo */
      else if(c == CTRL_A)
         printf("\nControl-A\n");
       else if(c == CTRL_B)
         printf("\nControl-B\n");
      else if(c == CTRL_C)
         printf("\nControl-C\n");
       else if(c == CTRL_D)
         printf("\nControl-D\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_E)
         printf("\nControl-E\n");
       else if(c == CTRL_F)
         printf("\nControl-F\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_G)
         printf("\nControl-G\n");
       else if(c == CTRL_H)
         printf("\nControl-H\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_I)
         printf("\nControl-I\n");
       else if(c == CTRL_L)
         printf("\nControl-L\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_M)
         printf("\nControl-M\n");
       else if(c == CTRL_N)
         printf("\nControl-N\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_O)
         printf("\nControl-O\n");
       else if(c == CTRL_P)
         printf("\nControl-P\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_Q)
         printf("\nControl-Q\n");
       else if(c == CTRL_R)
         printf("\nControl-R\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_S)
         printf("\nControl-S\n");
       else if(c == CTRL_T)
         printf("\nControl-T\n");
      else if(c == CTRL_U)
         printf("\nControl-U\n");
       else if(c == CTRL_V)
         printf("\nControl-V\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_Z)
         printf("\nControl-Z\n");
       else if(c == CTRL_X)
         printf("\nControl-X\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_Y)
         printf("\nControl-Y\n");
       else if(c == CTRL_K)
         printf("\nControl-K\n");	 	  	 	 	 	   	 	 	   	
      else if(c == CTRL_W)
         printf("\nControl-W\n");
       else if(c == CTRL_J)
         printf("\nControl-J\n");
      /* backspace */	 
      else if(c == BACKSPACE)
         printf("\nBACKSPACE\n");	 	 	 	  	 	 	 	   	 	 	   	
      else	   	 	 
         printf("%c", c );
    }     
}

void gestore_uscita_mygetchar(int signum)
{
   if(signum == SIGINT)
   {
      printf("\nTerminazione, ripristino le caratteristiche del terminale... ");
      if(g_reset_term() < 0)
         printf("\e[1;31mErrore di reset_term()\n\e[1;37m");
      else
         printf("\t\t[\e[1;32mOK\e[1;37m.]\n\n");
     exit(EXIT_SUCCESS);	 	 
   }
} 
