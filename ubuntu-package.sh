#!/bin/bash

COPY='cp -f'
COPYDIR='cp -rf'

echo -e  "\n\e[1;32m*\e[0m Creation of debian/ubuntu package\e[0m"

ok()
{
	echo -e  "\t\e[1;32mOk\e[0m"
}

fail() 
{
	echo -e  "\n\e[1;31mFailed \e[1;31m:(\e[0m"
	exit 1
}


if [ "$1" == "" ] || [ "$2" == "" ]; then
  echo -e -n  "\e[1;31m*\e[0m Arguments required: source_dir package_destination_dir"
  fail
fi

if [ ! -x $1 ]; then
  echo -e "\e[1;31m*\e[0m \""$1"\" directory missing: it must exist and contain the control directory with the control files inside."
  fail
fi

SRC=$1
DST=$2

echo -e "\e[1;32m*\e[0m creating ubuntu package in \""$2"\" from source \""$1"\"."

# test that source directory exists */

if [ ! -x $1 ]; then
  echo -e "\e[1;31m*\e[0m source directory \""$1\"" does not exist."
  fail
fi

# create destination directory if not existing */
if [ ! -x $2 ]; then
  echo -e  "\e[1;33m* \e[0m directory \""$2\"" does not exist: creating it " && mkdir $2 || fail
fi

# data
if [ ! -x $2/DEBIAN ]; then
  echo -e  "\e[1;33m* \e[0m directory \""$2"/DEBIAN\" does not exist: creating it " && mkdir -p $2/DEBIAN || fail
fi

# copy control files.
echo ""
echo -e -n "- Copying control files from \""$1"/DEBIAN\" to \""$2"\".." && $COPYDIR $1/DEBIAN $2 && ok || fail
echo -e "\e[1;35m*\e[0m Remember to edit control file, preinst, postinst and so on...\n"

# copy debian-binary file

if [ ! -e $1/debian-binary ]; then
  echo -e "\e[1;31m*\e[0m missing \""$1"/debian-binary\" file. It must be present inside \""$1" main directory."
  fail
else
  echo -e -n "- copying debian-binary file..." && cp $1/debian-binary $2 && ok || fail
fi

echo -e "\n\n- Populating main directory:\n"

# copy data file
DATADIR=$2
ETCDIR=$DATADIR/etc
USRDIR=$DATADIR/usr
SHAREDIR=$USRDIR/share
BINDIR=$USRDIR/bin
LIBDIR=$USRDIR/lib
KSRCDIR=$USRDIR/src/ipfire-wall
INITDIR=$ETCDIR/init.d

if [ ! -x $INITDIR ]; then
  echo -e -n "\e[1;33m* \e[0m directory \""$INITDIR"\" does not exist: creating it " && mkdir -p $INITDIR && ok  || fail
fi

if [ ! -x $USRDIR ]; then
  echo -e -n  "\e[1;33m* \e[0m directory \""$USRDIR"\" does not exist: creating it " && mkdir $USRDIR && ok  || fail
fi

if [ ! -x $SHAREDIR ]; then
  echo -e  -n "\e[1;33m* \e[0m directory \""$SHAREDIR"\" does not exist: creating it " && mkdir $SHAREDIR && ok  || fail
fi

if [ ! -x $BINDIR ]; then
  echo -e -n  "\e[1;33m* \e[0m directory \""$BINDIR"\" does not exist: creating it " && mkdir $BINDIR && ok  || fail
fi

if [ ! -x $LIBDIR ]; then
  echo -e -n  "\e[1;33m* \e[0m directory \""$LIBDIR"\" does not exist: creating it " && mkdir $LIBDIR && ok || fail
fi

if [ ! -x $KSRCDIR ]; then
  echo -e -n  "\e[1;33m* \e[0m directory \""$KSRCDIR"\" for kernel sources does not exist: creating it " && mkdir -p $KSRCDIR && ok || fail
fi

# Populate ETCDIR

echo -n "  - populating \""$ETCDIR"\"..." && $COPY ipfi/rc.ipfire $INITDIR && ok || fail

# Populate BINDIR

echo  -n "  - populating \""$BINDIR"\"..." && $COPY ipfi/ipfire $BINDIR && $COPY iqfire/iqfire $BINDIR && $COPY iqfire-listener/iqfire-listener $BINDIR && ok || fail

# Populate LIBDIR

echo  -n "  - populating \""$LIBDIR"\"..." && $COPY ipfi/libipfire_common.so $LIBDIR && \
  $COPY iqfire/natural_language/libnatural_language.so*  $LIBDIR  ok || fail

# Populate SHAREDIR

echo  -n "  - populating \""$SHAREDIR"\"..."

if [ ! -x $SHAREDIR/applications ]; then
  echo  -n -e  "\e[1;33m* \e[0m directory \""$SHAREDIR"/applications\" does not exist: creating it " && mkdir $SHAREDIR/applications && ok  || fail
fi

# iqfire-root(gnome or kde).desktop are installed (one or the other) by the postinst install script.
# So there is no need to include it here.

$COPY iqfire/iqfire.desktop $SHAREDIR/applications && \
$COPY ipfi/ipfire.desktop $SHAREDIR/applications && ok || fail

if [ ! -x $SHAREDIR/ipfire ]; then
  echo -n -e  "\e[1;33m* \e[0m directory \""$SHAREDIR"/ipfire\" does not exist: creating it " && mkdir $SHAREDIR/ipfire  && ok || fail
fi

if [ ! -x $SHAREDIR/iqfire ]; then
  echo -n -e  "\e[1;33m* \e[0m directory \""$SHAREDIR"/iqfire\" does not exist: creating it " && mkdir $SHAREDIR/iqfire && ok  || fail
fi

if [ ! -x $SHAREDIR/ipfire/config ]; then
  echo -n -e  "\e[1;33m* \e[0m directory \""$SHAREDIR"/ipfire/config\" does not exist: creating it " && mkdir $SHAREDIR/ipfire/config && ok  || fail
fi

echo -n -e "   - ipfire configuration" && $COPYDIR ipfi/IPFIRE $SHAREDIR/ipfire/config && ok  || fail

if [ ! -x $SHAREDIR/ipfire/doc ]; then
  echo -n -e  "\e[1;33m* \e[0m directory \""$SHAREDIR"/ipfire/doc\" does not exist: creating it " && mkdir $SHAREDIR/ipfire/doc && ok || fail
fi

echo -n -e "   - ipfire documentation" && $COPYDIR doc/ipfire/* $SHAREDIR/ipfire/doc && ok  || fail

echo -n -e "   - ipfire icons " && $COPYDIR ipfi/icons $SHAREDIR/ipfire && ok  || fail

# iqfire 

if [ ! -x $SHAREDIR/iqfire/config ]; then
  echo -n -e  "\e[1;33m* \e[0m directory \""$SHAREDIR"/iqfire/config\" does not exist: creating it " && mkdir $SHAREDIR/iqfire/config && ok  || fail
fi

echo -n -e "   - iqfire configuration: " && $COPY iqfire/*.desktop $SHAREDIR/iqfire/config/ && ok  || fail

echo -n -e "   - iqfire documentation (html: info, manual, help): " && $COPYDIR iqfire/doc $SHAREDIR/iqfire && ok || fail

echo -n -e "   - iqfire icons: " && $COPYDIR iqfire/icons $SHAREDIR/iqfire && ok || fail

echo  -n "  - populating \""$KSRCDIR"\", the ipfire-wall kernel source directory"

$COPYDIR kernel/ $KSRCDIR && ok || fail

CURRENTDIR=`pwd`
echo -n -e "   - cleaning directory \""$KSRCDIR"\"... " && cd $KSRCDIR/kernel && make distclean && ok && cd $CURRENTDIR || fail

# remove CVS directories, if present

echo -e "\e[1;32m*\e[0m Removing CVS directories..."
find $2 -name "CVS" -type d -exec rm -rf '{}' \;
echo -e "done removing CVS directories.\n"

echo -e "\e[1;32m*\e[0m Removing backup files, if present (*~):"
find $2 -name "*~" -type f -exec rm -f '{}' \;
echo "done removing backup files.\n"

echo -e "\e[1;32m* \e[0mSetting the right permissions for directories (755):"
find $2 -type d -exec chmod 755 '{}' \;

echo -e "\e[1;32m* \e[0mSetting the right permissions for regular files (644):"
echo -e "-  html and css files:"
find $2 -type f -name "*.html" -exec chmod 644 '{}' \;
find $2 -type f -name "*.css" -exec chmod 644 '{}' \;

echo -e "-  c, c++, h, pro files (if present):"
find $2 -type f -name "*.c" -exec chmod 644 '{}' \;
find $2 -type f -name "*.h" -exec chmod 644 '{}' \;
find $2 -type f -name "*.cpp" -exec chmod 644 '{}' \;
find $2 -type f -name "*.pro" -exec chmod 644 '{}' \;

echo -e "-  txt files:"
find $2 -type f -name "*.txt" -exec chmod 644 '{}' \;

echo -e "-  png, jpg, jpeg, bmp... files:"
find $2 -type f -name "*.jpg" -exec chmod 644 '{}' \;
find $2 -type f -name "*.jpeg" -exec chmod 644 '{}' \;
find $2 -type f -name "*.png" -exec chmod 644 '{}' \;
find $2 -type f -name "*.bmp" -exec chmod 644 '{}' \;




# Print final warnings and messages
echo -e "\n\e[0;37m ------------------------------- \e[1;32mMESSAGES\e[0m: --------------------------------------\e[0m\n"
echo -e "\e[1;35m*\e[0m remember to edit control file, preinst, postinst and so on..."
echo -n -e "\e[1;35m*\e[0m size of \""$2\"" directory (in kilobytes):  " && du -s $2






