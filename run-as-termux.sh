#!/bin/sh

# Add this file on you /sdcard directory on you android Phone
# Enable Debug Mode and ADB, connect you phone on PC, Download ADB Tools
# Run "adb shell" and on adb shell run "sh /sdcard/run-as-termux.sh"
# Enjoy termux, but with restrictions to access some folders like /sdcard

TERMUX_PACKAGE=com.termux
TERMUX_PATH=$ANDROID_DATA/data/$TERMUX_PACKAGE
TERMUX_TMPDIR=$TERMUX_PATH/files/usr/tmp
FNAME=$TERMUX_TMPDIR/$TERMUX_PACKAGE-$$
SCRIPT=$FNAME.sh
RCFILE=$FNAME.bashrc
ENVFILE=$FNAME.env
INITFILE=$FNAME.init
TERMUX_BASH=$TERMUX_PATH/files/usr/bin/bash
export TERMUX_PACKAGE TERMUX_PATH TERMUX_TMPDIR SCRIPT RCFILE ENVFILE INITFILE TERMUX_BASH

run-as $TERMUX_PACKAGE sh -c "cat > $ENVFILE" <<EOF
TERMUX_PACKAGE=$TERMUX_PACKAGE
TERMUX_PATH=$TERMUX_PATH
TERMUX_UID=$TERMUX_UID
TERMUX_APP_PID=$TERMUX_APP_PID
TMPDIR=$TERMUX_TMPDIR
SHELL=$TERMUX_PATH/files/usr/bin/bash
COLORTERM=truecolor
HISTCONTROL=ignoreboth
PREFIX=$TERMUX_PATH/files/usr
TERMUX_IS_DEBUGGABLE_BUILD=1
TERMUX_VERSION=0.118.0
LD_PRELOAD=$TERMUX_PATH/files/usr/lib/libtermux-exec.so
HOME=$TERMUX_PATH/files/home
LANG=en_US.UTF-8
TERMUX_APK_RELEASE=GITHUB
TERM=xterm-256color
SHLVL=1
PATH=$TERMUX_PATH/files/usr/bin
EOF

run-as $TERMUX_PACKAGE sh -c "cat > $RCFILE" <<EOF
#!$TERMUX_BASH
rm -f $RCFILE > /dev/null 2>&1
unset RCFILE > /dev/null 2>&1
. $ENVFILE
if [[ "\$(echo \$TERMUX_UID | xargs)" == "" ]]; then
	TERMUX_UID=\$(cmd package list packages -U $TERMUX_PACKAGE | rev | cut -d':' -f1 | rev)
fi
if [[ "\$(echo \$TERMUX_APP_PID | xargs)" == "" ]]; then
	TERMUX_APP_PID=\$(pgrep -o -u \$TERMUX_UID | xargs)
	if [[ "\$(echo \$TERMUX_APP_PID | xargs)" == "" ]]; then
		TERMUX_APP_PID=\$\$
	fi
fi
export TERMUX_PACKAGE TERMUX_PATH TERMUX_UID TERMUX_APP_PID TMPDIR SHELL COLORTERM HISTCONTROL PREFIX TERMUX_IS_DEBUGGABLE_BUILD TERMUX_VERSION LD_PRELOAD HOME LANG TERMUX_APK_RELEASE TERM SHLVL PATH
APP_ENV=/proc/\$(pgrep -o -P \$TERMUX_APP_PID)/environ
if [ -f \$APP_ENV ]; then
	. \$APP_ENV
fi
rm -f $ENVFILE > /dev/null 2>&1
unset ENVFILE > /dev/null 2>&1
EOF

run-as $TERMUX_PACKAGE sh -c "cat > $INITFILE" <<EOF
#!$TERMUX_BASH
rm -f $INITFILE > /dev/null 2>&1
unset INITFILE > /dev/null 2>&1
. $RCFILE
cd ~
EOF

run-as $TERMUX_PACKAGE sh -c "cat > $SCRIPT" <<EOF
#!/bin/sh
rm -f $SCRIPT
unset SCRIPT > /dev/null 2>&1
[[ -x $TERMUX_BASH ]] && $TERMUX_BASH --rcfile $RCFILE --init-file $INITFILE $@
rm -f $RCFILE $ENVFILE $INITFILE > /dev/null 2>&1
unset RCFILE ENVFILE INITFILE > /dev/null 2>&1
EOF

run-as $TERMUX_PACKAGE chmod +x $SCRIPT $RCFILE $ENVFILE $INITFILE
run-as $TERMUX_PACKAGE $SCRIPT
run-as $TERMUX_PACKAGE rm -f $SCRIPT $RCFILE $ENVFILE $INITFILE > /dev/null 2>&1
unset TERMUX_PACKAGE TERMUX_PATH TERMUX_TMPDIR FNAME SCRIPT RCFILE ENVFILE INITFILE TERMUX_BASH > /dev/null 2>&1
