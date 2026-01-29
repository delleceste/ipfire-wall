# makefile di analyzer - versione 0.1 -
# Giacomo Strangolino 
# jacum@libero.it

CC = gcc
OUTPROGNAME = analyze
FLAGS = -Wall -O3
RULENAME_FLAGS = -DENABLE_RULENAME
default: all

all:
	@echo
	@echo compilazione di ANALYZER in corso con il supporto per i nomi alle regole.
	@echo Digitare make all_no_rulename per disabilitare i nomi delle regole.
	@echo
	$(CC) -o $(OUTPROGNAME) analyzer.c ../g_getcharlib/g_getcharlib.c $(FLAGS) $(RULENAME_FLAGS)
	@echo 
	@echo Digitare ./$(OUTPROGNAME) per avviare ANALYZER.
	@echo
	
all_no_rulename:
	@echo
	@echo compilazione di ANALYZER in corso senza il supporto per i nomi alle regole...
	@echo
	$(CC) -o $(OUTPROGNAME) analyzer.c ../g_getcharlib/g_getcharlib.c $(FLAGS)
	@echo
	@echo Digitare ./$(OUTPROGNAME) per avviare ANALYZER.
	@echo