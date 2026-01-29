/* Lettura di caratteri dallo standard input in modo non bufferizzato 
 * Vengono intercettati anche i caratteri speciali: arrow keys, F1 ... F12
 * PAGE_UP, PAGE_DOWN, caratteri di controllo (Ctrl-KEY) ...
 * Vengono utilizzate le librerie standard del C e si manipola la modalita'
 * di Input Output del terminale.
 * 
 * 
 *  (C) Giacomo Strangolino 2005
 *  Software Liberissimo! :)
 *  jacum@libero.it
 */

/* g_getcharlib.c */

#include "g_getcharlib.h"

struct termio savetty, setty;
/* bloccare i segnali prima di chiamare le funzioni ioctl()! */

/* salva lo stato del terminale */
int g_save_term()   /* da chiamare all'inizio! */
{
  if(ioctl(0, TCGETA, &savetty) < 0)
    {
      perror("\e[1;31mErrore di ioctl: ");
      return -1;
    }
  return 1;
}

/* imposta I/O non bufferizzato */  
int g_set_term()
{
  if(ioctl(0, TCGETA, &setty) < 0)
    goto error;
  setty.c_lflag &= ~ICANON;
  setty.c_lflag &= ~ECHO;
  if(ioctl(0, TCSETAF, &setty) < 0)
    goto error;
  return 1;
 error:
  perror("\e[1;31mErrore di ioctl!\e[1;37m");
  return -1;
}

/* ripristina lo stato del terminale salvato da save_term() */
int g_reset_term()
{ 
  if(ioctl(0, TCSETAF, &savetty) < 0)
    {
      perror("\e[1;31mErrore di ioctl: ");
      return -1;
    }
  return 1;
}

/* restituisce il carattere letto da stdin, con codici particolari 
 * per i tasti speciali */
int g_getchar()
{
   int i = 0;
   int c[6]={0, 0, 0, 0, 0, 0};
   int limite = 3;
   short blocked = 1; /* input blocking if 1 */
   /* salvare lo stato del terminale nel chiamante! */
   /* si suppone che l'input sia bloccante in questo punto iniziale */
   /* io non bufferizzato */
   if(g_set_term() < 0)
      printf("\e[1;31mErrore di set_term()\e[1;37m\n");
   while(i < limite )
   {
      c[i] = getchar();		
      /* decommentare la seguente riga per il debug */  
      //       printf("[i:%d - %d] ", i, c[i]);  
      if(c[0] != 27 )
         break;	
      else
      {
	 usleep(uSLEEP_INTERVAL);
	 if(blocked == 1)  /* chiamo fcntl solo una volta nel ciclo */
	 {
            if(non_block() < 0)
	    {
	       perror("\e[1;31mErrore di fcntl!\e[1;37m\n");
	       return -1;
	    }   
	    else
	       blocked = 0;   
         }
	} 
      if( ( (c[0] == 27) & (c[1] == 91) & (c[2] == 49) ) | ( (c[0] == 27) & (c[1] == 91) & (c[2] == 50) )  )
         limite = 6;
      else if(  ( (c[0] == 27) & (c[1] == 91 ) & ( c[2] == 53) )  | ( ( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 54) )|     \
                 ( ( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 51) ) | ( ( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 50) ) )
         limite = 4; 
#ifdef WINDOWS
      else if ( ( (c[0] == 27) & (c[1] == 91 ) & ( c[2] == 91)) | ( (c[0] == 27) & (c[1] == 91 ) & ( c[2] == 52)) )
	limite = 4;
      
#endif
      i++;
   }
   if(blocked == 0) /* fcntl solo se indispensabile */
   {
      block();
      blocked = 1;
   }   
   if(g_reset_term() < 0)
	   perror("\e[1;31mErrore di reset_term() nel tentativo di ripristinare il terminale\e[1;37m\n");
   return parse_results(c);
}

/* interpreta quanto intercettato da mygetchar() */
int parse_results(int* c)
{
   if(c[2] == 'A')
      return ARROW_UP;
   else if(c[2] == 'B')
      return  ARROW_DOWN;
   else if(c[2] == 'C')
      return ARROW_RIGHT;
   else if(c[2] == 'D')
      return ARROW_LEFT;        
   else if((c[1] == 79 ) & ( c[2] == 80) )
      return F1;  
   else if((c[1] == 79 ) & ( c[2] == 81) )
      return F2;  
   else if((c[1] == 79 ) & ( c[2] == 82) )
      return F3;   
   else if((c[1] == 79 ) & ( c[2] == 83) )
      return F4;  
   else if((c[3] == 53 ) & ( c[4] == 126 ) )
      return F5;   
   else if((c[3] == 55 ) & ( c[4] == 126) )
      return F6; 
   else if((c[3] == 56 ) & ( c[4] == 126 ) )
      return F7;     
   else if((c[3] == 57 ) & ( c[4] == 126) )
      return F8;  
   else if((c[3] == 48 ) & ( c[4] == 126 ) )
      return F9;   
   else if((c[3] == 49 ) & ( c[4] == 126) )
      return F10; 
   else if((c[3] == 51 ) & ( c[4] == 126 ) )
      return F11;   
   else if((c[3] == 52 ) & ( c[4] == 126 ) )
      return F12; 
   else if((c[1] == 91 ) & ( c[2] == 70 ) )
      return FINE;    
   else if((c[1] == 91 ) & ( c[2] == 72 ) )
      return INIZIO_RIGA;        
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 53  ) & ( c[3] == 126) )
      return PAGSU;
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 54  ) & ( c[3] == 126) )
      return PAGGIU;   
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 51  ) & ( c[3] == 126) )
      return CANC;    
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 50  ) & ( c[3] == 126) )
      return INS;        
#ifdef WINDOWS
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 91  ) & ( c[3] == 65) )
      return F1;  
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 91  ) & ( c[3] == 66) )
      return F2; 
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 91  ) & ( c[3] == 67) )
      return F3;  
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 91  ) & ( c[3] == 68) )
      return F4; 
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 91  ) & ( c[3] == 69) )
      return F5; 
   else if(( c[0] == 27 ) & ( c[1] == 91 ) & ( c[2] == 52  ) & ( c[3] == 126) )
      return FINE; 
   else if( (c[0] == 27) &  ( c[1] == 91 ) & ( c[2] == 49  ) & ( c[3] == 126) )
     return INIZIO_RIGA;
#endif
   else if(c[2] == EOF)
      return ESC; 
   else if(c[0] == 1)
      return CTRL_A;
   else if(c[0] == 2)
      return CTRL_B;   
   else if(c[0] == 3)
      return CTRL_C;   
   else if(c[0] == 4)
      return CTRL_D;   
   else if(c[0] == 5)
      return CTRL_E;   
   else if(c[0] == 6)
      return CTRL_F;   
   else if(c[0] ==7)
      return CTRL_G;       
  else if(c[0] == 8)
#ifdef WINDOWS
    return BACKSPACE;
#else
      return CTRL_H;
#endif
   else if(c[0] == 9)
      return CTRL_I;   
   else if(c[0] == 12)
      return CTRL_L;   
   //    else if(c[0] == 10)   /* il 10 e' il 1n */
//       return CTRL_M;   
   else if(c[0] == 14)
      return CTRL_N;   
   else if(c[0] == 15)
      return CTRL_O;   
   else if(c[0] ==16)
      return CTRL_P;  	
   else if(c[0] ==17)
      return CTRL_Q;       
  else if(c[0] == 18)
      return CTRL_R;
   else if(c[0] == 19)
      return CTRL_S;   
   else if(c[0] == 20)
      return CTRL_T;   
   else if(c[0] == 21)
      return CTRL_U;   
   else if(c[0] == 22)
      return CTRL_V;   
   else if(c[0] == 15)
      return CTRL_Z;   
   else if(c[0] ==24)
      return CTRL_X;      	 	 	 	   	 	 	   	
   else if(c[0] == 23)
      return CTRL_W;   
   else if(c[0] ==25)
      return CTRL_Y;   
    else if(c[0] == 11)
      return CTRL_K;   
//        else if(c[0] ==10) /* il 10 e' il 1n */
//       return CTRL_J;  
   else if(c[0] == 127)
      return BACKSPACE;                   
   else
      return c[0];   
}

/* imposta il file descriptor associato a stdin a non bloccante */
int non_block()
{
   int result = -1;
   if( (result = fcntl(0, F_GETFL) )< 0)  /* leggiamo i flag associati a stdin */
      {
         perror("\e[1;31mErrore di fcntl nella lettura dei flag\e[1;31m");
	 return -1;
      }
   if(fcntl(0, F_SETFL, result | O_NONBLOCK) < 0)   /* mettiamo lo stdin in stato non bloccante */
   {
         perror("\e[1;31mErrore di fcntl nella scrittura dei flag\e[1;31m");
         return -1; 
   }	
   return 1; 
}

/* imposta il file descriptor associato a stdin a bloccante */
int block()
{
   int result = -1;
   if( (result = fcntl(0, F_GETFL) ) < 0)  
      {
         perror("\e[1;31mErrore di fcntl nella lettura dei flag\e[1;31m");
	 return -1;
      }
   if(fcntl(0, F_SETFL, result & ~O_NONBLOCK) < 0)  /* mettiamo lo stdin in stato bloccante */
   {
         perror("\e[1;31mErrore di fcntl nella scrittura dei flag\e[1;31m");
         return -1; 
   }	
   return 1; 
 }
