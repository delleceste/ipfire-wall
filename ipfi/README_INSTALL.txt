a. REQUIREMENTS:


- GNU C compiler (gcc)
- GNU GLIBC (C standard libraries and development libraries)

- KERNEL sources configured for the running kernel. Versions tested >= 2.6.12
  - In the kernel configuration Networking->Networking Options->
	Network Packet Filtering->`Network Packet Filtering' must be enabled.
    No other Network Packet Filtering options should be needed.

NOTE:
- The kernel code will not compile on kernels of the 2.4 series.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

b. Installation

IPFIREwall userspace interface.


 
- - - NEW INSTALLER - - -

- INSTALL

Download and read the installation and first utilization guide (in italian)
at http://www.giacomos.it/ipfire

Change into 'ipfi' directory
Simply execute ./install.sh

Normal user and root installations are treated differently in an automatical way.
The installer builds the executable IPFIRE-wall user interface and installs files needed.

Root installation also builds kernel modules and installs them into the running
kernel. Then copies initialization scripts in the appropriate directories.

So, root first has to run ./ipfire-installer.sh, then

each user has to run the same script once, to have its own profile installed.

If root installation has proceeded with the default options, each user should be
able to start IPFIRE-wall by simply typing 

`ipfire' 

at the shell.

See the documentation in `doc' directory for further information, command line options
and configuration issues.
Don'tcha forget to read carefully the file `readme.txt' in the current directory too!


- UNINSTALL

To uninstall IPFIRE, simply type "./ipfire-installer.sh uninstall"
This will remove init links, if created, and IPFIRE directory in your home.

- - - 

NOTE: installer will start in the language detected in the "LANG" environment
variable. Available languages are italian and english.

If you are italian and the installer starts in english, just set the LANG
variable like this:

export LANG=it_IT

The installer language affects the whole IPFIRE language installation.
To change language at a later time, edit the "options" file in your
home/IPFIRE folder.

Go on reading readme until the end!

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

- - - OLD INSTALLATION METHOD (DEPRECATED) - - -
 
1. INTERFACE. 
 
Type 'make' to build sources.

Each user then type 'make install'. This copies files needed into home folder.
If root made install before you, ipfirewall executable should be ready in '/sbin/ipfire'

Ruleset is empty.

Examples can be found in 'examples' directory.

Don't care if permission errors occur when user is not root.

Anyway, avoid following this method for the installation of ipfire.
It is no more supported. Use the automatic installer instead.

2. ANALYZER.

cd into 'analyzer' dir.

type 'make'. Execute from local directory file just created.

3.STARTUP SCRIPT

rc.ipfire is a startup script. Copy it in /etc/rc.d (slackware-like) or
/etc/init.d/ (debian - like).
The installer can do this for you.

If you use a slackware-like distribution, you will need to add the line
`/etc/init.d/rc.ipfire start' to the file /etc/rc.local to have ipfire-wall
automatically started at boot time.

LOADING IPFIRE-wall BY HAND using the rc script.

Then you can load ipfire doing 
`/etc/init.d/rc.ipfire start'
and stop doing
`/etc/init.d/rc.ipfire stop'
and restart...
`/etc/init.d/rc.ipfire restart'

Normally if a user is running ipfirewall, then the commands `stop' and
`restart' will not work, even if you are root, because no more than one
instance of ipfire can be running at the same time.
If you want to force the shutdown or restart of your ipfire-wall, then use

`/etc/init.d/rc.ipfire force_stop'
and 
`/etc/init.d/rc.ipfire force_restart'.

These commands will first kill the running instance of ipfire-wall and then
stop or restart the kernel module and the administrative configuration.

To run the `rc.ipfire' script you should be the root user.


Modify command line options in rc.ipfire as you like.

Giacomo Strangolino.

jacum@libero.it
