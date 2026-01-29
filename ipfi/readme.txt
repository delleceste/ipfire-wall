IPFIRE-wall README: read carefully until the end!!
README di IPFIRE-wall: leggi fino alla fine!

Note a partire dalla versione 0.99, vedasi sourceforge.net
From version 0.99 on, please read Change Log and Notes on http://sourceforge.net/projects/ipfire-wall

CONTENTS:
-doc: documentation related to the project. There you'll find information about compiling
 and running IPFIRE.
-ipfi: userspace stuff.
-kernel: kernel modules. 
-from version 0.91 on, `options' file in each user's home directory has been enriched
 by many detailed comments. Moreover, the default permission ruleset, represented
 by the `allowed' file, contains a list of rules which makes IPFIRE usable immediately.
 This file should be unique in the system and so should be copied only in root's IPFIRE
 directory. In the package, such base file is called `allowed.base'.
 Root installation ("make install") will copy `allowed.base' into /root/IPFIRE, renaming it into 
 `allowed' and so making it active. Normal users will have to copy it manually from package
 `ipfi/IPFIRE' directory, if they want, but root installation is enough.
 
 Note that it is mandatory that root build and install kernel modules first, 
 and that ipfire be started up before unprivileged users can turn on their
 interface.


- Reading the text file `installation' in this directory is recommended to have IPFIRE-wall
  installed correctly.

CONTENUTI:
-doc: documentazione sul progetto: compilazione del software e utilizzo di IPFIRE.
-ipfi: sorgenti della parte in spazio utente.
-kernel: moduli del kernel.
-dalla versione 0.91, il file `options' predefinito (che viene copiato dal 'make install'
 nella propria home directory), e' corredato da dettagliati commenti, mentre il file
 delle regole di permesso esplicito, `allowed' (anche esso presente nella home
 directory), contiene un insieme di regole che da sole consentono un funzionamento
 minimale e sicuro del filtro di pacchetti IPFIRE. Vedi sotto per maggiori dettagli.
 Questo file dovrebbe essere unico nel sistema e posizionato ad esempio nella
 cartella `IPFIRE' nella home di root. Nel pacchetto, questo file dei permessi di
 base e' stato chiamato `allowed.base'.
 L'installazione da root ("make install") copia in /root/IPFIRE il file di base e lo attiva
 chiamandolo `allowed'. Gli utenti normali invece, che non hanno accesso in scrittura sulla
 home dell'amministratore, avranno di norma il file dei permessi vuoto.
 A mano possono in ogni caso sempre copiare il file `allowed.base' rinominandolo,
 anche se questo non e' necessario ai fini del funzionamento.
 
 Si sottolinea che, affinche' IPFIRE-wall funzioni, e' necessaria l'installazione 
 dei moduli del kernel da root e il loro caricamento in memoria prima che ciascun
 utente possa avviare la propria interfaccia di IPFIRE-wall.

- Si raccomanda di leggere attentamente il file `installation' presente in questa 
  stessa cartella prima di procedere all'installazione del software.
 
 (C) 2005 Giacomo Strangolino.
 mailto: delleceste@gmail.com

 Visit www.giacomos.it/ipfire for software and documentation updates.

Free Sofware!

A Graphical interface should be developed soon by Mauro Francesconi.
(http://web.infinito.it/utenti/m/mauro.francesconi/)

* NOTE ABOUT KERNEL > 2.6.14
IPFIRE-wall, since version 0.91 supports kernel 2.6.14, in which netlink implementation
has been changed.
Release 0.91 has an improved version of the function which prints rules loaded, making 
them more readable for user.

* NOTES ABOUT `allowed.base' permission policy database.

The file provided with version 0.91 in the subdirectory `IPFIRE' of
userspace sources folder (`ipfi'), guarantees full rights to let all
packets out from this machine, and so all connections generated
by this node, thanks to stateful connection. Inside, only secure shell
server connections are allowed. Have a look at the file anyway!
Frequent connection scenarios are supported by a specific rule
(i.e. connections towards www, dns, loopback...).

* NOTES ABOUT VERSION 0.92
  
  - Corrected state tables counters.
  
  - Added read/write locks on dynamic kernel lists ( IMPORTANT! ).
  
  - Addded 'mailer' to userspace interface (using "SMTPclient" by
    Ralf S. Engelschall and Davide Libenzi, see send-mail-1.2.0
    subdirectory of ipfi folder or mailer.c for details). IPFIRE
    can now periodically send an email reporting its status and
    actions. Send-mail (SMTPclient) must be built and installed
    on the system, and 'options' file must be provided with lines
    enabling mailer. Another 'options' file will be located inside
    'mailer' subdirectory of IPFIRE folder and will store configuration
    settings for the mailer.
    
  - Added a pair of fields to kernel statistics structure: a time
    field to store kernel module load time and a field to keep track
    of the default policy being used.
    
  - Changed default logfile position: home directory/IPFIRE/ipfire.log for 
    each user. This avoids setting write rights to ipfire log in
    var/log previous default directory.

| ============================================== |
	IMPORTANT UPDATE: v 0.95!
| ============================================== |

* NOTES ABOUT VERSION 0.95

 - Linked lists are now synchronized with timer routines: RCU lists together with spin locks
   have been used to ensure stability against concurrency and at the same time allow a
   good performance (thanks to RCU lists). See kernel Documentation/RCU for details.
   
 - Code now is compiled by gcc 4.0.
 
 - New modifications need to be tested as usual! ;-)

= = = = = = = = = = = = = = = = = - version 0.96 - = = = = = = = = = = = = = = 
* NOTES ABOUT VERSION 0.96

 - Kernel: ipfire_state struct has been corrected: packet id is no more 
           a short int but an unsigned long.
           See kernel/ipfi_machine.h and ipfi/ipfire_userspace.h
 
 - User:
 	- Languages available: each user can personalize IPFIRE-wall
 	  changing each message into his own language.
 	  Just build a file like the "it" example, where each line 
 	  starts with the original english string, then an '=' follows
 	  and then the string in your language.
 	  Language strings are dynamically allocated at startup, giving the
 	  greatest flexibility in personalizing ipfire languages.
 	  Italian pack is already available! See installation instructions
 	  for details.
 	  
 	- Error messages have been improved and more useful help is given
 	  when errors happen.
 	  
 	- Kernel statistics have a new field indicating the packet analysis
 	  rate in number of packets per day, hour, minute and second.
 	  
 	- Option `quiet_daemon' has been corrected and now works fine.  
 	
 	- There is an automated installer in english and italian!
 	  See installation file in this directory for details.

| ============================================== |
	IMPORTANT UPDATE: v 0.97 (03 07 2006)!
| ============================================== |

  - Kernel: an important correction in 'ipfi_machine.c' prevents dereferencing an unallocated 
            object (ifa_list, defined in inetdevice.h) in some particular circumstances, e. g. 
            when running dhclient on a host where ipfire is loaded.
            A correction was made to the state machine: icmp stateful rules now are working.
            Remember that for ICMP protocol checks are performed only on IP and interfaces.
            This version supports kernel 2.6.17.3.
            
  - User: a little correction prevents the user interface from printing a 'keyword END not valid
          at line N' when loading the rules from the configuration files.

  - The `rc.ipfire' script has been updated and now allows two more options to force the shutdown or
    restart of the IPFIRE-wall module (with the administrative profile).
    See the `installation' file on the current directory.


| ============================================== |
|	IMPORTANT UPDATE: v 0.98 (08 10 2006)!   |
| ============================================== |

This version was used to run the demo at the Udine Linux Day 2006,
on the october 28!

    - Kernel: 
            - supports kernel 2.6.18.
            - changed into GFP_ATOMIC some kmalloc calls which 
              were wrongly invoked with GFP_KERNEL.
            
            - Silent modality, which was just a matter of avoiding printing
              by the userspace interface, is now a command sent on the netlink
              socket to tell the kernel module not to pass the packet information
              to the userspace listener.
              At the beginning, the old choice was made to let the userspace interface
              log the packets on file also if the console prints were disabled.
              Using the program, it has been revealed that logging is not so important
              as an option if the one who runs the interface is not the administrator:
              the user had his own interface logging the packets on a file on which he
              had write rights, and so easy to modify by a malicious hand.
              On the other side, an administrator who wants to log on a file, has
              to run his own interface and let it log.
              To keep the logging on file enabled and the console logging disabled
              (the old option), one has now to press "-" (disable console logging,
              leaving enabled the kernel/user communication: old way) or "+"
              (enable the console printing).
              
            
              
    - Userspace: see 'Kernel' section for the new functionality of the verbose/silent
                 printing.
                 
===================================================
 VERSION 0.98.1
===================================================

                 - TCP flags were not correctly written to the file when inserted by means of
                   the 'insert new rule' wizard. Fixed and tested with ACK, NULL, FIN, XMAS scans.
		 
		 - The automatic installer no longer overwrites the mailer options file in the IPFIRE
		   directory in the user's home if it already exists. Just the executable is built and
		   copied into the IPFIRE/mailer directory of the user's home itself.

- DOCUMENTATION:
	The IPFIRE-wall html documentation is no more included inside the downloaded package.
	Instead, in the `doc/ipfire/' directory you will find just the introductory html index
	of the documentation which has all the necessary links to the web pages of the documentation.
	This avoids the download of a large IPFIRE-wall package and at the same time lets the 
	documentation always refer to the latest version available on the Internet.

	Moreover, on the same included html page you will find, on its top right, the links to 
	download two new documentation papers:

	- an installation and first-execution guide (in italian, PDF document), and
	- an IPFIRE-wall presentation, in the open document format (Openoffice.org 2).
	  Such presentation is the one shown during the IPFIRE-wall discussion at the Linux Day 
	  at Udine, on the 28 of October 2006.
              
- FINALLY:
	      	 - This is the version presented at the Linux Day 2006 at Udine, october, 28.
           	 :)) 

==================================================
VERSION 0.98.3                IMPORTANT UPDATE!
==================================================

Kernel:

	Supports kernel 2.6.19.

	Introduced rcu_barrier() at module cleanup to avoid rcu callbacks be
	interrupted on exit. [IMPORTANT UPDATE!]

	Removed the manual configuration of kernel state tables timeout and 
	introduced a state-based timing of such tables, also for NAT tables.
	This means that a connection being in a setup state will have a timeout
	shorter than an established one.
	The default timeouts have been taken from the netfilter implementation.

	syn_lifetime = 2  MINS;
	synack_lifetime = 60  SECS;
	est_lifetime = 5  DAYS;
	close_wait_lifetime = 60  SECS;
	fin_wait_lifetime = 2  MINS;
	last_ack_lifetime =  30  SECS;
	time_wait_lifetime = 2  MINS;
	close_lifetime = 10  SECS;
	udp_new_lifetime = 30  SECS;
	udp_lifetime = 180  SECS;
	icmp_lifetime = 180  SECS;

	In a future release, it will be possible to change manually these values.
	
	
Kernel/user interface:
	Each state and NAT table has a timeout associated.
	Now it is possible to know its value:
	- pressing F5 you will see each state table with its timeout;
	- pressing F6 you will see the DNAT active connections with their timeout;
	- pressing F4 you will be able to watch SNAT active connection with the associated lifetime.

	The F6 and F4 functions represent a totally new feature with respect to the previous version,
	while the possibility to watch the remaining lifetime of a table entry is a simple add on to
	the old F5 functionality.

-------------------------------------------------------------------------------------------------------


==================================================
VERSION 0.98.4                UPDATE!  March 2007.
==================================================

Kernel: Added support for version 2.6.20.
	- Corrected a little bug that used to send in userspace also the packets
	  pre/post routed although the silent modality had been chosen.


User Interface:
	- Added a new submenu, accessed by the combination CTRL-B, which allows the
	  user to easily add an address to block by its name.
	  This menu can show the list of blocked web addresses, and provides an 
	  interface to add and remove new entries.
	
	- The TCP flags representation has been changed: instead of the full name
	  SYN, ACK, RST, PSH, URG, FIN, the user interface, for the sake of brevity,
	  will now just print the corresponding initial letters, i.e. 
	  S, A, R, P, U, F, respectively. The Urgent flag will be printed in dark red
	  color, from this version on.

	- The length of the rule name has been extended to support 24 characters instead
	  of the 19 of the previous versions.


Documentation: 
	- the web documentation is being updated and corrected. This process will
	  continue after this release.
	  Until now, practically the firts 14 topics of the documentation text (see ipfirewall
	  documentation index) has been updated.
	  The remaining pages, together with the new screenshots, are still being revised.
	  Keep an eye on them to stay up to date and be able to use the software at its maximum
	  capabilities.

=====================================================
VERSION 0.98.5                UPDATE!  June, 6, 2007.
=====================================================

Kernel/User interface:

	- changed the counters for the statistics from `unsigned long' to `unsigned long long'.

Installer:
	- the automatic installer now does not overwrite the `~/IPFIRE/options' file if it already exists.

Kernel:

	- added support for the current linux kernel, version 2.6.21.
	- corrected a bug in the comparison of two log entries in ipfi_log.c: now there should be
	  less packets logged on the console with the log level set to 1.
	  The comparison between the `response' field was wrong.
	
Documentation:

	- corrected the web links in the documentation index.




=====================================================
VERSION 0.98.7			February, 26, 2008
=====================================================
Support for kernel 2.6.24. (Many changes)
IQFIREwall support.


* TODO:
In translation, it could be more efficient if in direct DNAT/SNAT translation
a list of already seen packets was first consulted. Actually, rules are scanned
first in direct DNAT/SNAT and then dynamic tables are visited to update
timers. Moreover, timers are updated only in direct translation, that is just
in the direction of the initiating flow. That is, if A sends initiates a communication
with B and then just B sends packets to A, the timeout could occur. This can be easily
adjusted, if needeed.


* DISCLAIMER:

This software, although quite tested, is not yet guaranteed to be safe
and stable. Stable versions will be marked as 1.0 and above.
Note that this work consists of a part which runs in kernel space.
Instabilities there could lead to system crashes and cause loss of data.
Let me know if thou experience such problems.
Check frequently www.giacomos.it/ipfire for updates and up to date docs.
Currently ipfire-wall is being heavily tested in its filtering functions, to taste
its stability qualities.
Soon details will be published in the "test" section of the documentation/web page.
A heavy NAT testing is not so easy to do now for me, since I have not an available
scenario to apply network translation.
Since version 0.95 an important correction has solved some concurrency related
problems. Such version anyway should be tested with NAT and MASQUERADING.
Thanks if someone will help!

IPFIRE-wall has been tested on Linux kernel >= 2.6.12, debian (www.debian.org)
and slackware (www.slackware.org) distributions.

=========================================================

Since version 0.99 visit http://sourceforge.net/projects/ipfire-wall
			 http://wwww.giacomos.it/iqfire/

=========================================================

Giacomo Strangolino.
