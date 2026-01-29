/* semafori */
#include "includes/semafori.h"
#include "includes/ipfire_userspace.h"
#include<errno.h>

int ottieni_sem_key(const char * pathname, int id_oggetto)
{
  /* chiave del semaforo */
  key_t sem_key;
  /* ottengo la chiave specificando un pathname di un file esistente
     e un numero di progetto
  */
  if( (sem_key = ftok(pathname, id_oggetto) ) == -1)
    {
      perror("ftok()");
	  printf("Filename for ftok(): \"%s\"\n", pathname);		
      return -1;
    } 
  return sem_key;
}
 

/* questa funzione crea un semaforo e restituisce l'id se non esiste,
 * restituisce l'id se esiste gia'.
 */
int  ottieni_sem_id(key_t sem_key)
{
  /* id del semaforo creato */
  int sem_id;
  /* fine dichiarazioni */
  /* int semget(key_t key, int nsems, int flag */
  /* se key != 0, l'effetto dipende da flag, nsems indica il numero di semafori che deve contenere
     l'insieme creato
  */
  /* creo il semaforo solo se non esiste gia' */
  /* controllo se il semaforo esiste chiamando semget con nsems =0 e flag =0 */
  /* semget cosi' restituisce l'id del semaforo se esiste, altrimenti fallisce con errno = ENOENT
     se il semaforo non esiste
  */
  if( (sem_id = semget(sem_key, 0, 0) )  == -1 && errno == ENOENT) /* non esiste */
    {
      //printf("\e[0;37mVerra' creato il semaforo.\e[00m\n");
      sem_id=semget(sem_key, 1, IPC_CREAT|0660); /* creazione dell'insieme di semafori se non esiste gia'*/
      if(sem_id == -1)
	{
	  perror("semget()");
	  return -1;  /* errore di creazione */
	}
      else
	return sem_id;

      /* a questa creazione corrisponde l'inizializzazione della struttura semid_ds, associata all'insieme di
	 semafori, che contiene il numero dei semafori dell'insieme, due campi temporali, e una struttura
	 di permessi per consentire l'alterazione del semaforo.
	 Ciascun semaforo e' reallizzato come una struttura di tipo sem che ne contiene i dati essenziali come
	 il valore del semaforo ...
	 Il semaforo va inizializzato:
      */
    }
  else  /* dico che il semaforo gia' esiste con un determinato id */
    {
      //printf("\e[0;37mIl semaforo gia' esiste, con id %d\e[00m\n", sem_id);
      return sem_id;
    }

}

int impostazione_semaforo(int sem_id, int valore)
{
  /* union per il semaforo: usata per l'inizializzazione */
  union semun semunion_file_changed={0};
  /* imposto il valore del semaforo passato come parametro */
  semunion_file_changed.val=valore;

  if(semctl(sem_id, 0, SETVAL, semunion_file_changed) == -1)
    {
      perror("semctl()");
      return -1;
    }
  else   /* stabilisco di restituire il valore dell'id */
    return sem_id;
}

/* restituisce l'id stesso se esiste, 0 altrimenti */
int esiste_semaforo(int sem_key)
{
  return semget(sem_key, 0, 0);
}

int valore_semaforo(int sem_id)
{
  return semctl(sem_id, 0, GETVAL);
}

int rimuovi_semaforo(int semid)
{
  return ( semctl(semid, 1, IPC_RMID < 0) );
}

int unlock_sem(int id_sem)
/* void perche' la uso in situazioni non critiche: non controllo lo stato d'uscita,
 * la uso solo per sincronizzare la stampa */
{
    if(impostazione_semaforo(id_sem , SEMVERDE) < 0)  
      {
		perror("\e[1;31munlock_sem() Errore di impostazione del semaforo al verde\e[1;37m");
		return -1;
      }
  return 1;	
}

int lock_sem(int id_sem)
/* void perche' la uso in situazioni non critiche: non controllo lo stato d'uscita,
 * la uso solo per sincronizzare la stampa */
{
    if(impostazione_semaforo(id_sem , SEMROSSO) < 0)  
      {
		perror("\e[1;31mlock_sem(): Errore di impostazione del semaforo al rosso\e[1;37m");
		return -1;
      }
  return 1;	
}

int sem_locked(int id_sem)
{
    if(valore_semaforo(id_sem) == SEMROSSO)
      return 1;
    else
      return 0;   
}

int create_semaphore(int init_color)
{
	key_t semkey;
	key_t semid;
	char homedir[PWD_FIELDS_LEN];
	char namefile[MAXFILENAMELEN]="";
	get_user_info(HOMEDIR, homedir);
	if(strlen(homedir) + 20 < MAXFILENAMELEN)
		strcat(namefile, homedir);
	strcat(namefile, "/.IPFIRE/firehelp");
	if( (semkey = ottieni_sem_key(namefile, 1) ) < 0)
		{
			printf(RED "Error obtaining a key for semaphore!" NL);
			return -1;
		}
	if( (semid = ottieni_sem_id(semkey) ) < 0)
		{
			printf(RED "Error obtaining an id for semaphore!" NL);
			return -1;
		}
	if(impostazione_semaforo(semid, SEMVERDE) < 0)
	{
		printf(RED "Error initializing semaphore to green." NL);
		return -1;
	}
	return semid;
}
