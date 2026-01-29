#!/bin/bash

COPY='cp -f'
COPYDIR='cp -rf'

echo -e  "\n\e[1;32m*\e[0m Creation of debian/ubuntu package \e[4msource\e[0m"
echo -e "\e[1;33m*\e[0m This script must be placed in IPFIRE-wall main directory"

QMAKE=`which qmake-qt4`
if [ $QMAKE == "/usr/bin/qmake-qt4" ]; then
  QMAKE=/usr/bin/qmake-qt4
else
  QMAKE=/usr/bin/qmake
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

echo -e "\e[1;32m*\e[0m creating ubuntu package \e[4msource\e[0m in \""$2"\" from source directory \""$1"\"."

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
USRDIR=$DATADIR/usr
SRCDIR=$USRDIR/src/ipfire-wall

if [ ! -x $USRDIR ]; then
  echo -e -n  "\e[1;33m* \e[0m directory \""$USRDIR"\" does not exist: creating it " && mkdir $USRDIR && ok  || fail
fi

if [ ! -x $SRCDIR ]; then
  echo -e -n  "\e[1;33m* \e[0m directory \""$SRCDIR"\" for ipfire sources does not exist: creating it " && mkdir -p $SRCDIR && ok || fail
fi

$COPYDIR copyright doc install.sh iqfire kernel iqfire-listener ipfi LICENSE $SRCDIR && ok || fail

echo -e "\e[1;32m* \e[0mCleaning sources..."
echo -e "  - \e[0;32;4mipfi directory\e[0m"

(cd $SRCDIR/ipfi && make clean && ok) || fail

echo -e "  - \e[0;32;4miqfire directory\e[0m"

echo -e "    (qmake command: \""$QMAKE"\")"

(cd $SRCDIR/iqfire && $QMAKE && make distclean && ok) || fail

echo -e "  - \e[0;32;4miqfire-listener directory\e[0m"

(cd $SRCDIR/iqfire-listener && $QMAKE &&  make distclean && ok) || fail

echo -e "  - \e[0;32;4mkernel directory\e[0m"

(cd $SRCDIR/kernel && make distclean && ok) || fail

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






