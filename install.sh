#!/bin/bash

KERNELSRCDIR=/usr/src/IPFIRE-wall/kernel
IPFIRE_KERNEL_USR_SRC_DIR=/usr/src/IPFIRE-wall
BASE_INSTALLDIR=/usr/share
BINDIR=/usr/bin
SHAREDOCDIR=/usr/share/doc
LIBDIR=/usr/lib
FORCE=false

CURRENT_DIR=`pwd`



if [ "$1" == "noask" ] || [ "$2" == "noask" ] || [ "$3" == "noask"  ]; then
  FORCE="true"
fi

ok()
{
	echo -e  "\t\e[1;32mOk\e[0m"
}

fail() 
{
	echo -e  "\n\e[1;31mFailed \e[1;31m:(\e[0m"
	exit 1
}

doc_message()
{
  echo -e  "\n\e[1;32m--------------------------------- FIREWALL INSTALLATION ------------------------------------------\e[0m\n"
  echo -e  "\n\e[1;32m*\e[0m Welcome to ipfire-wall installation.\n"
  echo -e  "\e[1;32m*\e[0m If you are running an \e[1;33mubuntu\e[0m or \e[0;33mdebian\e[0m system, remember to launch this script with the"
  echo -e  "\e[1;32m*\e[0m \e[1;37;4mdebian\e[0m option, i.e.: \"./install.sh debian\"\n"
  echo -e  "\e[1;32m*\e[0m For installation details, please visit \n  http://www.giacomos.it/iqfire/installation.html\n"
  echo -e  "\e[1;32m*\e[0m ipfire-wall project home page and documentation: \n  http://www.giacomos.it/ipfire/index.html"
  echo -e  "\e[1;32m*\e[0m iqfire-wall related graphical interface home page and documentation:\n  http://www.giacomos.it/iqfire/index.html"
  echo -e  "\e[1;32m*\e[0m project hosted on http://sourceforge.net/projects/ipfire-wall"
  
  echo -e  "\e[1;32m\e[0m "
  echo -e  "\e[1;32m*\e[0m (C) 2005-2009 Giacomo S. delleceste@gmail.com"
}

fail_gcc_check() 
{
	echo -e  "\n\e[1;31m*\e[0m compiler version check failed."
	echo -e "\e[1;31m*\e[0m This means that you have upgraded (or downgraded?) your compiler since you"
	echo -e "\e[1;31m*\e[0m installed the system, or that you have built the kernel with a compiler "
	echo -e "\e[1;31m*\e[0m having a different version from the current one."
	echo -e "\e[1;31m*\e[0m Cannot continue: ipfire-wall's kernel module must be compiled with the same"
	echo -e "\e[1;31m*\e[0m gcc compiler used to build you running linux kernel."
	exit 1
}

fail_unloading_module()
{
	echo -e "   \e[1;31m* failed: \e[1;4;35mhint\e[0m: close ipfire-wall or iqfire-wall if running and run again the script\e[0m\n" 
	exit 1
}

create_rc_links()
{
			
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
		cp ipfi/rc.ipfire /etc/rc.d
		chmod +x /etc/rc.d/rc.ipfire	
	fi			
}


remove_rc_links()
{

	if [ -x /etc/init.d/rc.ipfire ]; then
		echo -e "/etc/init.d/rc.ipfire"
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

}

if [ `ps -ef | grep "\biqfire\b" | grep -v grep | wc -l` -ne "0" ]; then
          echo -e "\n\e[1;31m* \e[0m the program \"iqfire\" is running. Please close the application and try again.\n"
          exit 1
fi

if [ $CURRENT_DIR == $IPFIRE_KERNEL_USR_SRC_DIR ]; then
  echo -e "\n\e[1;31m* \e[0mPlease move the directory " $CURRENT_DIR " into a place different from"
  echo -e "\e[1;31m* \e[0m/usr/src and execute there this script again."
  echo -e "\e[1;31m* \e[0m"$IPFIRE_KERNEL_USR_SRC_DIR " cannot be used to install ipfire-wall, since "
  echo -e "\e[1;31m* \e[0mit's for ipfire-wall private use. Thank you.\n"
  echo -e "* For example, you can execute \"\e[0;32mmv" $IPFIRE_KERNEL_USR_SRC_DIR $HOME"/\e[0m\" and then"
  echo -e "* execute the script again from the new location.\n"
  exit 1
fi

case "$1" in
uninstall)
if [ `id -u` -ne 0 ]; then
	
	if [ "${FORCE}" == "false" ]; then
	  echo -e  "\nDo you want to remove installation files? [Y|n]"	
	  read response
	  case "$response" in
	  [nN])
	  exit 1
	  ;;
	  esac
	fi
    	
    	echo -e  -n   "1. Removing iqfirewall installation files...\t"
    	(cd iqfire && make uninstall && ok) || fail
    	
    	echo -e -n    "2. Removing iqfirewall (listener) installation files...\t"
    	(cd iqfire-listener && make uninstall && ok) || fail
    	
    	echo -e -n    "3. Removing ipfire share install dir: \"/usr/share/ipfire\"...\t"
    	if [ -x /usr/share/ipfire ]; then
    	(rm -rf /usr/share/ipfire/ && ok) || fail
    	fi
    	
    	echo -e -n    "4. Removing iqfire share install dir: \"/usr/share/iqfire\"...\t"
    	if [ -x /usr/share/iqfire ]; then
    	(rm -rf /usr/share/iqfire/ && ok) || fail
    	fi
    	
    	echo -e -n    "5. Removing startup scripts..."
    	remove_rc_links || fail
    	
    	echo -e -n    "6. Removing ipfire executable from /usr/bin..."
    	if [ -x /usr/bin/ipfire ]; then
    		(rm /usr/bin/ipfire && ok) || fail
    	fi
    	
    	echo -e -n  "7. Removing ipfire/iqfire menu entries..."
    	if [ -e /usr/share/applications/ipfire.desktop ]; then
    		(rm /usr/share/applications/ipfire.desktop && ok ) || fail
    	fi
    	
    	if [ -e /usr/share/applications/iqfire.desktop ]; then
    		(rm /usr/share/applications/iqfire.desktop && ok ) || fail
    	fi
    	
    	if [ -e /usr/share/applications/iqfire-root-gnome.desktop ]; then
    		(rm /usr/share/applications/iqfire-root-gnome.desktop && ok ) || fail
    	fi
    	
    	if [ -e /usr/share/applications/iqfire-root-kde.desktop ]; then
    		(rm /usr/share/applications/iqfire-root-kde.desktop && ok ) || fail
    	fi
    	
    	echo -e  "8. Unloading kernel module, if loaded (and existing...)"
    	modprobe -r ipfi 
    	
	echo -e  "9. Removing script \"ipfire-kernel-rebuild\" from /usr/bin"
	if [ -e /usr/bin/ipfire-kernel-rebuild ]; then
	   (rm -f /usr/bin/ipfire-kernel-rebuild && ok ) || fail
	fi
	
	echo -e  "\e[1;32m*\e[0m Successfully removed ipfirewall and all its components."
	echo ""
   	echo -e  "\e[1;32m*\e[0m Manually remove the users' home configuration directories"
   	echo -e  "  (called \".IPFIRE\") or any icons you might have created."
exit 0


else
	echo -e  "\e[1;31mOnly root can uninstall iqFirewall :(\e[0m\n"
	
fi   	
    	
;;
esac

# qmake-qt4 or qmake?
# qmake-qt4 exists, use it. If not, assume qmake is version number 4

QMAKE=`which qmake-qt4` 
if [ "${QMAKE}" != "/usr/bin/qmake-qt4" ]; then
  QMAKE=/usr/bin/qmake
fi


if [ `id -u` -eq 0 ]; then

	doc_message
	if [ "${FORCE}" == "false" ]; then
	  echo -e  "\nDo you want to proceed? [Y|n]"
	  read response
      
	  case "$response" in
	  [nN])
	  exit 1
	  ;;
	  esac
    	fi
# CLEAN ?
    	if [ "$1" == "clean" ] || [ "$2" == "clean" ]; then
    		echo -e -n  "* Cleaning ipfire directory..."
    		(cd ipfi && make clean && ok ) || fail
    		echo -e -n  "* Cleaning iqfire directory..."
    		(cd iqfire && $QMAKE && make clean && ok ) || fail
		echo -e -n  "* Cleaning iqfire natural language directory..."
		(cd iqfire/natural_language && $QMAKE && make clean && ok ) || fail
    		echo -e -n  "* Cleaning iqfire-listener directory..."
    		(cd iqfire-listener && $QMAKE && make clean && ok ) || fail
    		echo -e -n  "* Cleaning kernel directory..."
    		(cd kernel && make clean && ok ) || fail
    	fi
    	
# check that the compiler version used to build the kernel exactly matches the version of the 
# current gcc compiler:
	echo -e  "* Performing pre installation tasks:"
	echo -e	 "  - checking that the compiler version used to build the kernel matches the current gcc version..."
	echo -e -n "    - building the tester:"
	(cd kernel/gcc-check && gcc -o gcc_version_check gcc_version_check.c && ok) || fail_gcc_check
	echo -e  "    - checking versions..."
	(kernel/gcc-check/gcc_version_check "`cat /proc/version`" && ok && rm -f kernel/gcc-check/gcc_version_check) || fail
# IPFIRE-wall
    	echo -e  "* \e[1;36mBuilding ipfirewall, please wait...\e[0m"
    	
    	echo -e -n "1. \e[1;33mEntering directory ipfi\e[0m "
    	(cd ipfi && ok && pwd) || fail
    	
	echo -e  "2. Building ipfire_common library...\n"
	(cd ipfi && make commonlib && echo -e  "\e[1;32mOk, built ipfirewall common library\e[0m") ||exit 1
	
	echo -e -n  "3. Installing ipfire_common library in " ${LIBDIR}
	(cd ipfi && cp libipfire_common.so ${LIBDIR} && ok) || fail
 		
	echo -e -n  "4. Executing ldconfig on " ${LIBDIR}
	(ldconfig ${LIBDIR} && ok) || fail
    
    	echo -e -n  "5. Compiling ipfirewall...\t"
    	(cd ipfi && make  && echo -e  "\e[1;32mOk, built ipfirewall.\e[0m") || exit 1
 		
	echo -e -n  "6a. Removing previously installed ipfire executable (if installed in /usr/local/bin)..."
	if [ -x /usr/local/bin/ipfire ]; then
    		(rm -f /usr/local/bin/ipfire && ok ) || fail
    	else
    		echo -e "no ipfire executable found in /usr/local/bin"
    	fi
 	
	echo -e -n  "6b. Installing ipfirewall...into " ${BINDIR}
    	(cd ipfi && cp ipfire ${BINDIR} && ok ) || fail
    	
    	
    	
    	echo -e -n  "7a. Installing startup script...\t"
    	
	if [ -x /etc/init.d ]; then
    		(cd ipfi && cp rc.ipfire /etc/init.d && chmod +x /etc/init.d/rc.ipfire && ok) || fail
    	fi
    	
	echo -e -n  "7b. Installing startup links...\t"
    	create_rc_links && ok || fail
 		
 	echo -e -n  "8. Installing ipfire documentation...in " ${BASE_INSTALLDIR}/ipfire/doc
    	
    	if [ ! -x ${BASE_INSTALLDIR}/ipfire/doc  ]; then
                 mkdir -p -m 755 ${BASE_INSTALLDIR}/ipfire/doc
        fi
        
        (install -d -m 755  doc/ ${BASE_INSTALLDIR}/ipfire/doc && ok) || fail
        
        echo -e "8b. Creating a symbolic link to ipfire documentation in"
 	echo -e "    /usr/share/doc/ipfire..."
 	(install -d -m 755 ${SHAREDOCDIR}/ipfire && \
        ln -sf ${BASE_INSTALLDIR}/ipfire/doc ${SHAREDOCDIR}/ipfire && ok) || fail
        
        echo -e -n  "9. Installing ipfire icon(s)..."
        if [ ! -d /usr/share/ipfire/icons ]; then
        	(mkdir -p /usr/share/ipfire/icons && cp ipfi/icons/ipfire-console.png /usr/share/ipfire/icons && ok ) || fail
        else
        	cp  ipfi/icons/ipfire-console.png /usr/share/ipfire/icons && ok || fail
        fi
        
        echo -e -n  "10. Installing ipfire menu entry..."
#      if [ ! -x /usr/share/applications/ipfire.desktop ]; then
        	(cp ipfi/ipfire.desktop /usr/share/applications && ok ) || fail
#       fi
    	
    	
    	echo -e  "\n* \e[1;36mBuilding the kernel module...\e[0m"
	echo -e    "\n* installing a copy of the kernel sources into " $IPFIRE_KERNEL_USR_SRC_DIR
	echo -e -n "  and the script ipfire-kernel-rebuild"
	
	# make a copy of the kernel sources in /usr/src/IPFIRE-wall/kernel to rebuild them fastly if needed
	
	if [ ! -x $IPFIRE_KERNEL_USR_SRC_DIR ]; then
	   (mkdir -p $IPFIRE_KERNEL_USR_SRC_DIR && ok) || fail
	fi
	
	(cp -r kernel common $IPFIRE_KERNEL_USR_SRC_DIR && ok) || fail
	(cp ipfire-kernel-rebuild /usr/bin/ && ok) || fail
	
	echo -e -n  "1. Changing directory: going into kernel sources..."
	(cd kernel && ok) || fail
	echo -e -n "Gone into: "
	pwd
	
	echo -e -n  "2. Building the kernel module..."
	(cd kernel && make) || fail
	echo -e "   Successfully installed the kernel module\n"
	
	echo -e  "3. Installing the kernel module..."
	(cd kernel && make install) || fail
	echo -e "   Successfully installed the kernel module\n"
	
	echo -e  -n "4. Trying a sample kernel module loading..."
	(modprobe ipfi && ok) || fail
	
	echo -e  -n "5. Trying a sample kernel module unloading..."
	(modprobe -r ipfi && ok) || fail_unloading_module
	
	echo -e ""	
	echo -e "\e[1;32m:)) \e[0mSuccessfully installed the kernel module and"
	echo -e "    all the tools to run your console interface personal firewall!"
	echo -e ""
	echo -e "\e[1;4;32mNOTES\e[0m:"
	echo -e "\e[1;32m* \e[0mTo start the firewall, type as root:"
	echo -e "\e[0m  /etc/init.d/rc.ipfire start\e[0;37m <+ return>."
	
	echo -e "\e[1;32m* \e[0mTo stop the firewall, type as root:"
	echo -e "\e[0m  /etc/init.d/rc.ipfire stop\e[0;37m <+ return>."
	echo -e ""
	echo -e "\e[1;32m* \e[0mEach user can start the firewall interface by the"
	echo -e "  start menu clicking the entry located at:"
	echo -e "  \e[1;30m[start] -> Internet -> IqFirewall Network Firewall\e[0m"
	
	
# IQFIREWall
        echo -e  "\n* \e[1;36mBuilding iqfirewall...\e[0m"
 		
	echo -e -n  "1. Changing directory: going into iqFirewall natural language's\t"
	
	(cd iqfire/natural_language && ok) || fail
	
	echo -e -n  "1b. Compiling iqFirewall natural language's\t"
	(cd iqfire/natural_language && ${QMAKE} natural_language.pro && ok) || fail
	(cd iqfire/natural_language && make && echo -e  "\e[1;32mSuccessfully built natural language library\e[0m") || fail
	
	echo -e -n  "1b. Installing iqFirewall natural language\t"

	(cd iqfire/natural_language && make install && echo -e  "\e[1;32mSuccessfully installed natural language library\e[0m") || fail
	
 	echo -e -n  "2. Changing directory: going into iqFirewall's\t"
 	(cd iqfire && ok) || fail
 	
 	pwd
    	
    	echo -e  "3. Compiling iqFirewall, please wait..."
    	echo -e "3a. Generating Makefile..."
    	
    	if [ "$1" == "debian" ] || [ "$2" == "debian" ]; then
    		(cd iqfire && ${QMAKE} iqfire-debian.pro && ok)
    	else
    		(cd iqfire && ${QMAKE} iqfire.pro && ok)
    	fi
    	
    	echo -e "3b. Compiling the sources..."
    	(cd iqfire && make && echo -e  "\e[1;32mSuccessfully built iqfirewall\e[0m") || fail

    	
	echo -e  "4. Installing iqfirewall in " ${BASE_INSTALLDIR}/iqfire "..."
	# re execute qmake inside sub directories

	(cd iqfire && make install && echo -e  "\e[1;32mSuccessfully installed iqfirewall\e[0m") \
 		|| exit 1
 	
	echo -e -n  "4. Installing iqfirewall administrator's launchers..."
	
	which kdesu && (echo -e -n "\e[1;32m*\e[0m  \"kdesu\" found: using it to launch iqfire-wall as root"  \
		&& cp iqfire/iqfire-root-kde.desktop /usr/share/applications/ && ok || fail)  \
		|| (which gksu && (echo -e -n "\e[1;32m*\e[0m  \"gksu\" found: using it to launch iqfire-wall as root"  \
		&& cp iqfire/iqfire-root-gnome.desktop /usr/share/applications/ && ok || fail) )
	
	
	echo -e -n  "5. Creating documentation symbolic links in /usr/share/doc/iqfire...\t"
	
	(install -d -m 755 ${SHAREDOCDIR}/iqfire && \
	ln -sf ${BASE_INSTALLDIR}/iqfire/doc /usr/share/doc/iqfire && ok) || fail
	
# iqfire-listener
 
	echo -e  "\n* \e[1;36mBuilding iqfire-listener (a part of iqfirewall)...\e[0m"
	echo -e -n  "1. Changing directory: going into iqfire-listener's\t"
 	(cd iqfire-listener && ok) || fail
 	
 	pwd
    	
    	echo -e  "2. Compiling iqfire-listener..."
    	echo -e "2a. Generating Makefile..."
    	(cd iqfire-listener && $QMAKE iqfire-listener.pro && ok)
    	echo -e "2b. Compiling the sources..."
    	(cd iqfire-listener && make && echo -e  "\e[1;32mSuccessfully built iqfire-listener\e[0m") || fail
    	echo -e "3. Installing iqfire-listener"
    	(cd iqfire-listener && make install && ok ) || fail
	
	
	echo -e  "\n* \e[1;36mCleaning destination installation directories and setting correct permissions"
	
	echo -e "\e[1;32m-\e[0m Removing CVS directories..."
	find ${BASE_INSTALLDIR}/ipfire -name "CVS" -type d -exec rm -rf '{}' \;
	find ${BASE_INSTALLDIR}/iqfire -name "CVS" -type d -exec rm -rf '{}' \;
	echo -e "done removing CVS directories.\n"
	
	echo -e "\e[1;32m* \e[0mSetting the right permissions for directories (755):"
	find ${BASE_INSTALLDIR}/ipfire -type d -exec chmod 755 '{}' \;
	find ${BASE_INSTALLDIR}/iqfire -type d -exec chmod 755 '{}' \;

	echo -e "\e[1;32m* \e[0mSetting the right permissions for regular files (644):"
	echo -e "-  html and css files:"
	find ${BASE_INSTALLDIR}/ipfire -type f -name "*.html" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/iqfire -type f -name "*.css" -exec chmod 644 '{}' \;


	echo -e "-  txt files:"
	find ${BASE_INSTALLDIR}/ipfire -type f -name "*.txt" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/iqfire -type f -name "*.txt" -exec chmod 644 '{}' \;

	echo -e "-  png, jpg, jpeg, bmp... files:"
	find ${BASE_INSTALLDIR}/ipfire -type f -name "*.jpg" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/ipfire -type f -name "*.jpeg" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/ipfire -type f -name "*.png" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/ipfire -type f -name "*.bmp" -exec chmod 644 '{}' \;
	
	find ${BASE_INSTALLDIR}/iqfire -type f -name "*.jpg" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/iqfire -type f -name "*.jpeg" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/iqfire -type f -name "*.png" -exec chmod 644 '{}' \;
	find ${BASE_INSTALLDIR}/iqfire -type f -name "*.bmp" -exec chmod 644 '{}' \;
	
	echo -e "\e[1;32m* \e[0mSetting the right read/write permissions for dictionary files"
	chmod a+rw ${BASE_INSTALLDIR}/iqfire/natural_language/dictionary -R
	echo -e ""
	
	echo -e ""	
	echo -e "\e[1;32m:)) \e[0mSuccessfully installed the kernel module, the"
	echo -e "    console based \e[1;4;37mipfire-wall\e[0m and the graphical "
	echo -e "    user interface \e[1;4;37miqfire-wall\e[0m"
	echo -e ""
	echo -e "----------------------------------------------------------------------------------"
	echo -e "\e[1;4;33mIMPORTANT\e[0m: Should you upgrade your kernel (installing a new kernel image or"
	echo -e "           rebuilding the kernel), run \e[0;32mipfire-kernel-rebuild\e[0m as root to rebuild the"
	echo -e "           ipfire-wall kernel module."
	echo -e "           For this purpose, a copy of the kernel sources has been installed into"
	echo -e "           the directory \e[1;4;37m"$KERNELSRCDIR"\e[0m. Do not remove it."
	echo -e "----------------------------------------------------------------------------------"
	echo -e ""
	echo -e "\e[1;4;32mNOTES\e[0m:"
	echo -e "\e[1;32m* \e[0mTo start the firewall, type as root:"
	echo -e "\e[0m  /etc/init.d/rc.ipfire start\e[0;37m <+ return>."
	
	echo -e "\e[1;32m* \e[0mTo stop the firewall, type as root:"
	echo -e "\e[0m  /etc/init.d/rc.ipfire stop\e[0;37m <+ return>."
	echo -e ""
	echo -e "\e[1;32m* \e[0mEach user can start the firewall interface by the"
	echo -e "  start menu clicking the entry located at:"
	echo -e "  \e[1;30m[start] -> Internet -> IqFirewall Network Firewall\e[0m"
	echo -e ""
	echo -e "\e[1;32m* \e[0mTo autostart the firewall execution at the user"
	echo -e "  session startup (with KDE or GNOME), start IQFirewall, go to"
	echo -e "  \e[1;30mSettings menu -> Configure the Firewall Interface ->"
	echo -e "  tick \"Automatically start with your desktop session\"\e[0m."
	echo -e ""
	
	
	
else
	echo -e  "\e[1;31mOnly root can install iqFirewall :(\e[0m\n"
	exit 1
	
fi
