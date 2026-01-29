/* definizioni per semafori.c */
#ifndef SEMAFORI_H
#define SEMAFORI_H
#include<sys/ipc.h>
#include<sys/sem.h>
#include<errno.h>
#include<stdio.h>
#include "colors.h"
#include <stdlib.h>
#define SEMROSSO 0
#define SEMVERDE 1
#ifdef WINDOWS
int dummy_sem_set(int colour);
int dummy_sem_read();
#else
#ifndef FREEBSD
union semun
{
  int val;
  struct semid_ds *buf;
  unsigned short* array;
  struct seminfo *__buf;
};
#endif

int ottieni_sem_key(const char * pathname, int id_oggetto);

int  ottieni_sem_id(key_t sem_key);

int impostazione_semaforo(int sem_id, int valore);

int esiste_semaforo(int sem_key);

int valore_semaforo(int sem_id);

int rimuovi_semaforo(int sem_id);

int create_semaphore(int init_color);

#endif /* WINDOWS */
int lock_sem(int id);
int unlock_sem(int id);
int sem_locked(int id_sem);
#endif /* CLISERV */
