#!/bin/bash

set -e

clear
echo -e "\n\n"

case "$1" in
uninstall)
    if [ "${LANG}" == "it_IT" ]; then
	echo -e "Questa procedura \e[1;31mrimuovera'\e[0m IPFIRE-wall dal computer.\nDesideri continuare? [s n] (+ invio)"
    else
	echo -e "This script will \e[1;31mremove\e[0m IPFIRE-wall from this computer\nDo you want to proceed? [y n] (+ return)"
    fi
    
    read response
    
    case "$response" in
    	[yYsS])
    	
    	if [ "${USER}" == "root" ]; then
    	
    		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Rimuovo i moduli dal kernel se necessario..."
    		else
			echo -e "Removing kernel modules if loaded..."
    		fi
  
    		modprobe -r ipfi
    	
    		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Rimuovo gli script di avvio\n"
		else
			echo -e "Removing startup script...\n"
		fi
	
		if [ -x /etc/init.d/rc.ipfire ]; then
			rm /etc/init.d/rc.ipfire	
		fi
			
		if [ -x /etc/rc0.d/K30ipfire ]; then
			echo -e "link /etc/rc0.d/K30ipfire"
			rm /etc/rc0.d/K30ipfire
		fi
			
		if [ -x /etc/rc6.d/K30ipfire ]; then
			echo -e "link /etc/rc6.d/K30ipfire"
			rm /etc/rc6.d/K30ipfire
		fi
			
		if [ -x /etc/rc2.d/S80ipfire ]; then
			echo -e "link /etc/rc2.d/S80ipfire"
			rm /etc/rc2.d/S80ipfire
		fi
			
		if [ -x /etc/rc3.d/S80ipfire ]; then
			echo -e "link /etc/rc3.d/S80ipfire"
			rm /etc/rc3.d/S80ipfire
		fi	
			
		if [ -x /etc/rc.d/rc.ipfire ]; then
			echo -e "rc.ipfire -> directory \e[1;33mrc.d\e[0m\n"
			rm /etc/rc.d/rc.ipfire	
		fi

		if [ -e /usr/share/icons/ipfire/ipfire.png ]; then
			echo -e "icons...\e[0m\n"
			rm -rf /usr/share/icons/ipfire
		fi	

	fi #user is root
	
	if [ "${LANG}" == "it_IT" ]; then
		echo -e "Rimuovo la cartella IPFIRE dalla tua home e tutto il suo contenuto? [s n]  (+ invio)"
    	else
		echo -e "Remove IPFIRE directory in your home and all its files? [y n] (+ return)"
    	fi
    	
    	 read response
    
    	case "$response" in
    	[yYsS])
    		if [ -x ~/IPFIRE ]; then
    			rm -r ~/IPFIRE
			echo "removing desktop icon"
			rm ~/Desktop/ipfire.desktop
    		fi
    	;;
    	esac
    	
    	if [ "${LANG}" == "it_IT" ]; then
		echo -e  "\nDinstallazione completata!\n"
   	else
		echo -e -n "\nUninstall complete!\n\n"

    	fi	
    	;;
    esac  
    exit 1
    ;;
esac



if [ "${LANG}" == "it_IT" ]; then
	echo -e "\t\tINSTALLAZIONE DI \e[1;31mIPFIRE-wall\e[0m"
	if [ "${USER}" != "root" ]; then
		echo -e -n "\t\tInstallazione da utente normale ("
		echo -e "\e[1;32m${USER}\e[0m)\n\n"
	else
		echo -e -n "\t\tInstallazione in modalita' amministratore ("
		echo -e "\e[1;32m${USER}\e[0m)\n\n"
	fi
		echo -e "Vuoi continuare? [\e[1;31mn\e[00m per annullare, un tasto \e[1;32mqualsiasi\e[0m per continuare]  (+ invio)"
else
	echo -e "\t\t\e[1;31mIPFIRE-wall\e[0m INSTALLATION"
	if [ "${USER}" != "root" ]; then
		echo -e -n "\t\tYou are a normal user ("
		echo -e  "\e[1;32m${USER}\e[0m)\n\n"
	else
		echo -e -n "\t\tSuper user installation ("
		echo -e "\e[1;32m${USER}\e[0m)\n\n"
		echo -e "Do you want to continue? [\e[1;31mn\e[0m to cancel, \e[1;32many other key\e[0m to go on] (+ return)"
	fi
fi
	read response
		
	case "$response" in
	[nN]*)
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "\n\e[1;31mInstallazione annullata!\e[00m\n\n"
		else
			echo -e "\n\e[1;31mInstallation canceled!\e[00m\n\n"
		fi
		exit 1
		;;
	esac

echo -e "\n\e[1;32mInstalling IPFIRE-wall\n\e[0m"
 
	if [ "${LANG}" == "it_IT" ]; then
		echo "1. Copia dei file delle impostazioni e delle regole nella propria home."		
	else
		echo -e "\e[1;33mNormal user installation.\e[00m"
		echo "1. Copying settings and rule files in your home directory."
	fi
	
	if [ ! -d ~/IPFIRE ]; then
		echo -e "\e[1;35mDirectory ~/IPFIRE not exixting: creating it\e[0m\n"
		mkdir ~/IPFIRE
	fi
	
	if [ -d ~/IPFIRE ]; then
		echo -e "Updating languages...\n"
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Aggiorno il/i file delle traduzioni in altre lingue..."		
		else
			echo -e "Updating languages...\n"
		fi
		cp IPFIRE/languages ~/IPFIRE -r
		if [ "${LANG}" == "it_IT" ]; then
			echo  -e "Aggiorno i file del mailer..."		
		else
			echo -e "Updating mailer files...\n"
		fi
# backup the mailer options if the file already exists
		if [ -e ~/IPFIRE/mailer/options ]; then
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "* \e[1;35mIl file delle opzioni del mailer in ~/IPFIRE/mailer/ esiste gia': non lo copio.\e[0m\n"		
			else
				echo -e "* \e[1;35mMailer options file already present: i won't update it!\n"
			fi
		else
			# Create mailer directory if it doesn't exist
			if [ ! -d ~/IPFIRE/mailer ]; then
				echo "Ipfire mailer directory"
				mkdir ~/IPFIRE/mailer
			fi
			echo "Mailer options file"
			cp mailer/* ~/IPFIRE/mailer -r
		fi
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Aggiorno l'help e i file di esempio delle regole"
		else
			echo -e "Updating help and sample ruleset files...\n"
		fi
		cp IPFIRE/allowed.base ~/IPFIRE/
		cp IPFIRE/allowed.base.README ~/IPFIRE/
		cp IPFIRE/blacklist.example ~/IPFIRE/
		cp IPFIRE/firehelp ~/IPFIRE/
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Creo un collegamento sul Desktop."
		else
			echo -e "Creating Desktop link...\n"
		fi
		
		cp icons/ipfire.desktop ~/Desktop
		
		#if [ -e ~/IPFIRE/ipfire.log ]; then
		#	echo -e "\e[1;35mlog file already present: i will save it in ipfire.log.bkup!\e[0m\n"
		#	cp ~/IPFIRE/ipfire.log ~/IPFIRE/ipfire.log.backup
		#fi
		#cp IPFIRE/ipfire.log ~/IPFIRE/
		
		
		if [ -e ~/IPFIRE/options ]; then
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "\e[1;35mIl file delle opzioni e' gia' presente: non copio quello nuovo!\e[0m\n"
			else
				echo -e "\e[1;35mOptions file already present: i will not copy the new file!\e[0m\n"
			fi
		else
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "Copio il file delle opzioni nella home.\e[0m\n"
			else
				echo -e "Copying options file in the home directory!\e[0m\n"
			fi

			cp IPFIRE/options ~/IPFIRE/
			cp IPFIRE/options.it ~/IPFIRE/
		fi
		
		
		if [ "${USER}" != "root" ]; then
		
		  if [ -e ~/IPFIRE/allowed ]; then
		  	if [ "${LANG}" == "it_IT" ]; then
				echo -e "\e[1;35mNon installo le regole di permesso: file gia' presente!\e[0m\n"
			else
				echo -e "\e[1;35mNot installing permission ruleset: file already present!\e[0m\n"
			fi
		  else
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "Creo il file delle regole di permesso vuoto...\n"
			else
				echo -e "Installing the default permission empty ruleset...\n"
			fi	
			cp IPFIRE/allowed ~/IPFIRE
		  fi
# root user: copio dopo le regole di permesso, se non sono gia` presenti.
		else
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "\e[1;35mLe regole di permesso per l'utente root vengono installate in seguito, se necessario.\e[0m\n"
			else
				echo -e "\e[1;35mRoot permission ruleset will be installed later, if necessary.\e[0m\n"
			fi
		fi
		
		if [ -e ~/IPFIRE/blacklist ]; then
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "\e[1;35mNon installo le regole di negazione: file gia' presente!\e[0m\n"
			else
				echo -e "\e[1;35mNot installing denial ruleset: file already present!\e[0m\n"
			fi
		else
			cp IPFIRE/blacklist ~/IPFIRE/
		fi
		
		if [ -e ~/IPFIRE/translation ]; then
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "\e[1;35mNon installo le regole di NAT: file gia' presente!\e[0m\n"
			else
				echo -e "\e[1;35mNot installing NAT ruleset: file already present!\e[0m\n"
			fi
		else
			cp IPFIRE/translation ~/IPFIRE/
		fi
		
		if [ -e ~/IPFIRE/blacksites ]; then
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "\e[1;35mNon installo le regole di blocco dei siti: file gia' presente!\e[0m\n"
			else
				echo -e "\e[1;35mNot installing blocked sites ruleset: file already present!\e[0m\n"
			fi
			
		else
			cp IPFIRE/blacksites ~/IPFIRE/
		fi
	fi
		
		
        if [ "${LANG}" == "it_IT" ]; then
		echo "2. Copia della documentazione html nella directory IPFIRE della tua home..."
        else
          echo "2. Copying html documentation into IPFIRE directory in your home..."
	fi
	cp ../doc ~/IPFIRE -r
	
	
	if [ "${LANG}" == "it_IT" ]; then
		echo  -n "3. Compilazione del mailer..."
	else
		echo -n "3. Building mailer..."
	fi
	gcc -o mailer/SMTPclient send-mail-1.2.0/*.c &>/dev/null
	echo -e " \e[1;32mOK\e[0m"
		
	if [ -x ~/IPFIRE/mailer ]; then
		
		if [ "${LANG}" == "it_IT" ]; then
		     echo  -n "4. Copia dell'eseguibile del mailer..."
		else
	             echo -n "4. Copying mailer executable..."
		fi
		cp mailer/SMTPclient ~/IPFIRE/mailer/
		echo -e "\e[1;32m\tOK\e[0m."
	else
		echo -e "\e[1;31m\t~/IPFIRE/mailer directory does not exist!\e[0m\n"
	fi

	if [ "${LANG}" == "it_IT" ]; then
		echo -e "   Seleziono l'\e[1;32mitaliano\e[0m come lingua per l'interfaccia di IPFIRE-wall.\n"
		echo -e "   Si modifichi il file nella directory \e[1;32mIPFIRE\e[0m denominato \e[1;32moptions\e[0m"
 		echo -e "   per ripristinare la lingua predefinita (inglese), commentando o rimuovendo la riga \"LANGUAGE_FILENAME\".\n"
 		
 		mv ~/IPFIRE/options.it ~/IPFIRE/options
	fi
	
	
# COMPILAZIONE USERSPACE
	if [ "${LANG}" == "it_IT" ]; then
		echo -e "5. \e[1;32mCompilazione\e[0m di IPFIRE-wall... (Makefile)... \nAspetta.. potrebbe impiegarci un po'...\n"
	else
		echo -e "5. \e[1;32mBuilding\e[00m IPFIRE-wall... (Makefile)... it might take some time...\e[0m\n"
	fi
	
	make &>/dev/null
	
	if [ "${LANG}" == "it_IT" ]; then
		echo -e "Puoi eseguire IPFIRE digitando \e[1;32m./ipfire\e[00m da questa directory o semplicemente"
		echo -e "\e[1;32mipfire\e[00m se l'amministratore ha precedentemente installato l'eseguibile nel sistema."
		echo -e "Ricorda di leggere la documentazione nella tua cartella \e[1;32mhome/IPFIRE/doc\e[0m, iniziando"	
		echo -e "da \e[1;32mindex.html\e[0m."
		echo -e "\nRicorda anche che, affinche' IPFIRE-wall sia utilizzabile, l'amministratore"
		echo -e "deve avere gia' effettuato l'installazione dei moduli del kernel e deve averli"
		echo -e "gia' caricati in memoria. Contattalo se non sei sicuro..."
		echo ""
		echo -e  "\e[1;32mBuon divertimento\e[00m!!"
		echo ""
		echo -e "\e[1;36mGiacomo S.\e[00m giugno 2005-marzo 2006"
		echo -e "\e[1;33mdelleceste@gmail.com\e[00m"
		echo -e "Visita \e[1;31mwww.giacomos.it/ipfire\e[00m e dintorni\n"
		echo ""
		echo -e "Leggi attentamente il file \e[1;32mreadme\e[0m e la documentazione nella tua home directory"
		echo -e "dentro la cartella \e[1;32mIPFIRE\e[0m.\n\n"
	else
		echo -e "You can execute IPFIRE typing \e[1;32m./ipfire\e[0m from the current directory, or "
		echo -e "simply \e[1;32mipfire\e[00m if root user has installed the executable in your system, together with the kernel modules. Contact him if you are not sure..."
		echo -e "Read documentation in your \e[1;32mhome/IPFIRE/doc\e[00m directory, beginning from"
		echo  -e "\e[1;32mindex.html\e[00m."
		echo -e "\e[1;32mEnjoy\e[00m!!" 
		echo ""
		echo -e "\e[1;36mGiacomo S.\e[00m june 2005-march 2006"
		echo -e "\e[1;33mdelleceste@gmail.com\e[00m"
		echo -e "Visit \e[1;31mwww.giacomos.it/ipfire\e[00m and around..."
		echo ""
		echo -e "Now read \e[1;32mreadme\e[00m in your home/IPFIRE folder..."
		echo ""
	fi

	if [ "${USER}" == "root" ]; then
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "\e[1;31mINSTALLAZIONE DA ROOT...\e[0m"
		else
			echo -e "\e[1;31mROOT INSTALLATION\e[00m"
		fi
		
		
		if [ -e ~/IPFIRE/allowed ]; then
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "Non installo le regole di permesso predefinite per root: file gia' presente...\e[0m\n"
			else
				echo -e "\e[1;35mNot installing default root permission ruleset: file already present!\e[0m\n"
			fi			
		else
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "Installo la versione in italiano delle regole di permesso predefinite per \e[1;31mroot\e[0m...\n"
				cp IPFIRE/allowed.base.it ~/IPFIRE/
				cp IPFIRE/allowed.base.it ~/IPFIRE/allowed
			else
				echo -e "Installing the \e[1;31mroot\e[0m's default permission ruleset...\n"
				cp IPFIRE/allowed.base ~/IPFIRE/
				cp ~/IPFIRE/allowed.base ~/IPFIRE/allowed
			fi	
		fi
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Copio l'eseguibile \e[1;32mipfire\e[0m in \e[1;32m/sbin\e[0m...\e[0m\n"
		else
			echo -e "Copying \e[1;32mipfire\e[0m executable in \e[1;32m/sbin\e[0m directory...\n"
		fi
		
		cp ipfire /sbin
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Creo un collegamento simbolico a /sbin/ipfire in /usr/local/bin...\n"
		else
			echo -e "Creating a symbolic link to /sbin/ipfire in /usr/local/bin...\n"
		fi
		
		ln -sf /sbin/ipfire /usr/local/bin/ipfire
		
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Copio l'eseguibile del \e[1;32mmailer\e[0m in \e[1;32m/usr/local/bin\e[0m...\e[0m\n"
		else
			echo -e "Copying \e[1;32mmailer\e[0m executable in \e[1;32m/usr/local/bin\e[0m directory...\n"
		fi
		
		cp mailer/SMTPclient /usr/local/bin
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Copio il file icona in /usr/share/icons\e[0m...\e[0m\n"
		else
			echo -e "Copying \e[1;32micon file\e[0m in \e[1;32m/usr/share/icons\e[0m directory...\n"
		fi
		if [ ! -x /usr/share/icons/ipfire ]; then
			mkdir /usr/share/icons/ipfire
		fi
		cp icons/ipfire.png /usr/share/icons/ipfire

			
		if [ "${LANG}" == "it_IT" ]; then
			echo -e "Ora verranno compilati e installati i moduli del kernel.\n"
			echo -e "Vuoi proseguire? [n per terminare l'installazione, un qualsiasi altro tasto per continuare] (+ invio)\n"
		else
			echo -e "Now we are going to build and install kernel modules. "
			echo -e "Do you want to proceed? [n to cancel, any other key to go on] (+ return)\n"
		fi
		
		read response
		
		case "$response" in
		[nN]*)
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "\n\e[1;31mInstallazione dei moduli del kernel annullata!\e[00m\n\n"
			else
				echo -e "\n\e[1;31mKernel modules installation canceled!\e[00m\n\n"
			fi
			exit 1
			;;
		esac
		
		cd ../kernel
		make
		make install
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e -n "\nProvo a caricare e poi scaricare i moduli dalla memoria...\t"
		else 
			echo -e -n "\nTrying a sample kernel module loading...\t"
		fi

		modprobe ipfi && echo -e  "\e[1;32mOK\e[00m\n" || echo -e  "\e[1;31mNO!\e[00m\n"
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e -n "Ora scarico i moduli dalla memoria...\t"
		else 
			echo -e -n "Now unloading kernel modules...\t"
		fi
		
		modprobe -r ipfi && echo -e -n "\e[1;32mOK\e[00m\n" || echo -e -n "\e[1;31mNO!\e[00m\n"
		
		cd ..
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e -n "\nInstallazione conclusa.\n\n"
			echo -e "Nella cartella ipfi troverai uno script \"rc\" per l'avvio automatico."
			echo -e "Se lo desideri puoi modificarlo a piacere e collocarlo al posto\n" 
			echo -e "giusto a seconda della tua distribuzione."
			echo -e "\nDesideri che lo faccia io? [s oppure n] (+ invio)"
		else 
			echo -e -n "\nInstallation complete.\n\n"
			echo -e "In the \"ipfi\" folder you will find a \"rc\" script to automate"
			echo -e "startup. If you want you can copy it in your rc directories".
			echo -e "Do you want me to do it for you? [y or n] (+ return)"
		fi
		
		
		read response
		
		case "$response" in
		[sSyY]*)
			if [ "${LANG}" == "it_IT" ]; then
				echo -e "\nCopia del file di inizializzazione e creazione dei link...\e[00m\n\n"
			else
				echo -e "\nCopying init file and creating links...\n\n"
			fi
			
			cd ipfi
			
			if [ -x /etc/init.d ]; then
				cp rc.ipfire /etc/init.d
				chmod +x /etc/init.d/rc.ipfire	
			fi
			
			if [ -x /etc/rc0.d ]; then
				echo -e "link: /etc/init.d/rc.ipfire -> /etc/rc0.d/K30ipfire"
				ln -sf /etc/init.d/rc.ipfire /etc/rc0.d/K30ipfire
			fi
			
			if [ -x /etc/rc6.d ]; then
				echo -e "link: /etc/init.d/rc.ipfire -> /etc/rc6.d/K30ipfire"
				ln -sf /etc/init.d/rc.ipfire /etc/rc6.d/K30ipfire
			fi
			
			if [ -x /etc/rc2.d ]; then
				echo -e "link: /etc/init.d/rc.ipfire -> /etc/rc2.d/S80ipfire"
				ln -sf /etc/init.d/rc.ipfire /etc/rc2.d/S80ipfire
			fi
			
			if [ -x /etc/rc3.d ]; then
				echo -e "link: /etc/init.d/rc.ipfire -> /etc/rc3.d/S80ipfire"
				ln -sf /etc/init.d/rc.ipfire /etc/rc3.d/S80ipfire
			fi
			
			if [ -x /etc/rc.d ]; then
				echo -e "rc.ipfire -> directory \e[1;33mrc.d\e[0m\n"
				cp rc.ipfire /etc/rc.d
				chmod +x /etc/rc.d/rc.ipfire	
			fi			
		esac
		
		if [ "${LANG}" == "it_IT" ]; then
			echo -e  "\nInstallazione conclusa!\n"
			echo -e "\e[1;31mRileggi attentamente tutti i messaggi sopra riportati!!\e[0m\n"
			echo -e "Per avviare IPFIRE-wall, e' sufficiente digitare\n"
			echo -e "\e[1;32m/etc/init.d/rc.ipfire start\e[0m\n"
			echo -e "e poi ogni utente che avra' eseguito questo installer"
			echo -e "potra' avviare la sua istanza digitando"
			echo -e "\e[1;32mipfire\e[0m eventualmente seguito da opzioni.\n\n"
		else
			echo -e -n "\nInstallation complete!\n\n"
			echo -e "Read carefully all messages above!"
			echo -e "To start IPFIRE-wall, it's enough to type\n"
			echo -e "\e[1;32m/etc/init.d/rc.ipfire start\e[0m\n"
			echo -e "and then every user who executed this installer will be"
			echo -e "able to start his own instance typing"
			echo -e "\e[1;32mipfire\e[0m followed by options.\n\n"
		fi
		
	fi

