# android ebpf dev

## tested env

- Android 10 with arm64/x86_64 kernel 4.14

- Android 12 with arm64 kernel 5.10

## install termux.apk

```
% gh run list --repo termux/termux-app -L 5
STATUS  NAME                                                              WORKFLOW                 BRANCH  EVENT  ID          ELAPSED  AGE
✓       Added: Start termux app docs support at https://termux.dev/do...  Build                    master  push   2532010124  3m49s    14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Unit tests               master  push   2532010122  2m35s    14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Validate Gradle Wrapper  master  push   2532010120  18s      14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Validate Gradle Wrapper  master  push   2531825064  17s      14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Build                    master  push   2531825063  4m37s    14d

% gh run download 2532010124 -p "*android-7-github-debug_arm64-v8a" --repo termux/termux-app
% adb install -r termux*.apk
```

## make run-as-termux.sh

```
walleye:/ #adb shell
walleye:/ #cat /data/local/tmp/run-as-termux.sh
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
```

## install proot env

```
# /data/local/tmp/run-as-termux.sh
# Tsinghua mirror
# https://mirrors.ustc.edu.cn/repogen/
~ $ termux-change-repo


# Install proot-distro
~ $ apt update && apt install -y proot-distro
~ $ apt install ca-certificates wget gnupg curl python  -y

~ $ proot-distro install ubuntu
~ $ proot-distro login ubuntu
# commented out the line "session optional pam_keyinit.so force revoke" in all the files under "/etc/pam.d/":
root@localhost:/etc/apt# uname -a
Linux localhost 5.4.0-faked #1 SMP PREEMPT Tue Mar 30 05:16:27 UTC 2021 aarch64 aarch64 aarch64 GNU/Linux
root@localhost:/# vim /etc/pam.d/su-l
root@localhost:/# vim /etc/pam.d/login
root@localhost:/# vim /etc/pam.d/runuser-l
root@localhost:/# exit

# need relogin
~ $ proot-distro login ubuntu
root@localhost:/# apt update && apt install ca-certificates apt-transport-https wget gnupg curl lsb-release python3-bpfcc python3 python3-pip -y
root@localhost:/# wget https://github.com/iovisor/bcc/raw/master/tools/execsnoop.py
root@localhost:/# chmod a+x execsnoop.py
# https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary
root@localhost:/# apt install sudo bpftrace bpftool bcc bpfcc-tools linux-headers-$(uname -r)
```

##  sources.list of proot env

ubuntu:

```
# cat /etc/apt/sources.list
deb [signed-by="/usr/share/keyrings/ubuntu-archive-keyring.gpg"] http://ports.ubuntu.com/ubuntu-ports jammy main universe multiverse
deb [signed-by="/usr/share/keyrings/ubuntu-archive-keyring.gpg"] http://ports.ubuntu.com/ubuntu-ports jammy-updates main universe multiverse
deb [signed-by="/usr/share/keyrings/ubuntu-archive-keyring.gpg"] http://ports.ubuntu.com/ubuntu-ports jammy-security main universe multiverse
```

debian:

```
# cat /etc/apt/sources.list
deb [signed-by="/usr/share/keyrings/debian-archive-keyring.gpg"] http://deb.debian.org/debian bullseye main contrib
deb [signed-by="/usr/share/keyrings/debian-archive-keyring.gpg"] http://deb.debian.org/debian bullseye-updates main contrib
deb [signed-by="/usr/share/keyrings/debian-archive-keyring.gpg"] http://security.debian.org/debian-security bullseye-security main contrib
```

## patch android kernel

TBD

check kernel config:

```
% adb shell zcat /proc/config.gz | grep PROBE
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_GENERIC_IRQ_PROBE=y
CONFIG_KPROBES=y
CONFIG_UPROBES=y
CONFIG_KRETPROBES=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
# CONFIG_NET_TCPPROBE is not set
# CONFIG_TEST_ASYNC_DRIVER_PROBE is not set
CONFIG_GENERIC_CPU_AUTOPROBE=y
CONFIG_TIMER_PROBE=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_PROBE_EVENTS=y
# CONFIG_KPROBES_SANITY_TEST is not set

% adb shell zcat /proc/config.gz | grep CONFIG_IKCONFIG
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
```

don't setup `CONFIG_IKHEADERS=m` for android 5.10(or other ACK), it will break the compilation process on modulers.order check:

```
 Checking the list of modules:
--- common/android/gki_aarch64_modules	2022-07-07 07:03:16.994494975 +0000
+++ android-kernel/out/android12-5.10/common/modules.order	2022-07-07 07:13:37.442139765 +0000
@@ -0,0 +1 @@
+kernel/kheaders.ko
ERROR: modules list out of date
Update it with:
cp android-kernel/out/android12-5.10/common/modules.order common/android/gki_aarch64_modules
```


check probe symbols:

```
% adb root

% adb shell cat /proc/kallsyms | grep probe_user
0000000000000000 T __probe_user_read
0000000000000000 W probe_user_read
0000000000000000 T __probe_user_write
0000000000000000 W probe_user_write
0000000000000000 r __ksymtab_probe_user_read
0000000000000000 r __ksymtab_probe_user_write
0000000000000000 r __kstrtab_probe_user_read
0000000000000000 r __kstrtab_probe_user_write

% adb shell cat /proc/kallsyms | grep probe_kernel
0000000000000000 T __probe_kernel_read
0000000000000000 W probe_kernel_read
0000000000000000 T __probe_kernel_write
0000000000000000 W probe_kernel_write
0000000000000000 r __ksymtab_probe_kernel_read
0000000000000000 r __ksymtab_probe_kernel_write
0000000000000000 r __kstrtab_probe_kernel_read
0000000000000000 r __kstrtab_probe_kernel_write

% adb shell cat /proc/kallsyms | grep probe_read
0000000000000000 T bpf_probe_read
0000000000000000 T bpf_probe_read_user
0000000000000000 T bpf_probe_read_str
0000000000000000 r bpf_probe_read_proto
0000000000000000 r bpf_probe_read_user_proto
0000000000000000 r bpf_probe_read_str_proto

% adb shell cat /proc/kallsyms | grep probe_write
0000000000000000 T bpf_probe_write_user
0000000000000000 T uprobe_write_opcode
0000000000000000 r bpf_probe_write_user_proto
0000000000000000 d bpf_get_probe_write_proto._rs
```

## test for debina rootfs

```
 % adb push /Users/android/Downloads/debian /data/local/tmp/
 % adb shell mkdir -p /data/local/tmp/debian/lib/modules/4.14.175-g1aec57a92e09-dirty/build/
 % adb push kernel-headers/* /data/local/tmp/debian/lib/modules/4.14.175-g1aec57a92e09-dirty/build
 % git clone https://github.com/tiann/eadb
 % adb push eadb/assets/ /data/local/tmp/
 % adb root
 % adb shell
 
/data/local/tmp # chmod 777 /data/local/tmp/run*
/data/local/tmp # chmod 777 /data/local/tmp/device*
 
/data/local/tmp # mkdir -p debian/proc/
/data/local/tmp # mkdir -p debian/sys/
/data/local/tmp # mkdir -p debian/sys/fs/bpf/
/data/local/tmp # mkdir -p debian/sys/kernel/debug/
/data/local/tmp # mkdir -p debian/sys/kernel/tracing/
/data/local/tmp # mkdir -p debian/tmp/
/data/local/tmp # mkdir -p debian/etc/apt/preferences.d/

/data/local/tmp # /data/local/tmp/run
root@localhost:/# cat  /etc/apt/sources.list
deb https://mirrors.ustc.edu.cn/debian bullseye main
root@localhost:/# apt update && apt install wget curl bpftrace bpftool bcc bpfcc-tools -y
root@localhost:/# wget https://raw.githubusercontent.com/iovisor/bcc/master/tools/execsnoop.py
root@localhost:/# chmod 777 execsnoop.py
root@localhost:/# python3 execsnoop.py
```


TBD

## test for ubuntu rootfs

install ubuntu rootfs:

push ubuntu rootfs to device to unzip:

```
adb push ubuntu-aarch64-pd-v3.0.1.tar.xz /data/local/tmp/
adb shell tar xJf /data/local/tmp/ubuntu-aarch64-pd-v3.0.1.tar.xz -C /data/local/tmp/ubuntu
```

change ubuntu mirror:

```
adb root
# ./run
# apt update && apt install gnupg ca-certificates apt-transport-https -y
# apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 871920D1991BC93C

# echo "#中科大源
deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-security main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-security main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy main universe restricted
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy main universe restricted" > sources.list

# cp -f sources.list /etc/apt/sources.list

# cat sources.list.ustc

deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-security main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-security main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy main universe restricted
# deb-src https://mirrors.ustc.edu.cn/ubuntu-ports/ jammy main universe restricted

# cat sources.list.tsinghua

deb https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
# deb-src https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
deb https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy-security main restricted universe multiverse
# deb-src https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy-security main restricted universe multiverse
deb https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
# deb-src https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
deb https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy main universe restricted
# deb-src https://mirrors.tsinghua.edu.cn/ubuntu-ports/ jammy main universe restricted

```

## test with frida

```
% cat loadProg10.js
var loadProg = new NativeFunction(Module.findExportByName("libbpf_android.so", "_ZN7android3bpf8loadProgEPKc"), 'int', ['pointer']);
loadProg(Memory.allocUtf8String("/system/etc/bpf/netd.o"))
loadProg(Memory.allocUtf8String("/data/local/tmp/bpf/example.o"))
```

```
% cat loadProg.js
var loadProg = new NativeFunction(Module.findExportByName("libbpf_android.so", "_ZN7android3bpf8loadProgEPKcPbS2_"), 'int', ['pointer', 'pointer']);
var critical = Memory.alloc(4)
critical.writeInt(1)
loadProg(Memory.allocUtf8String("/data/local/tmp/bpf/example.o"), critical)
```


## test execsnoop.py

![1657013870994.png](https://img1.imgtp.com/2022/07/05/1YcbnGJ0.png)


## ref

https://www.jianshu.com/p/e9873d92ebbd

http://security.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20211016_all.deb

http://ports.ubuntu.com/pool/main/o/openssl/openssl_3.0.2-0ubuntu1_arm64.deb

https://forums.kali.org/showthread.php?48217-SSH-Bash-Required-key-not-available

https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md

https://bowers.github.io/eBPF-Hello-World/

https://ubuntu.pkgs.org/20.04/ubuntu-updates-main-arm64/linux-headers-5.4.0-92-generic_5.4.0-92.103_arm64.deb.html
http://ports.ubuntu.com/pool/main/l/linux/linux-headers-5.4.0-92-generic_5.4.0-92.103_arm64.deb
https://ubuntu.pkgs.org/20.04/ubuntu-updates-main-arm64/linux-headers-5.4.0-92_5.4.0-92.103_all.deb.html
http://ports.ubuntu.com/pool/main/l/linux/linux-headers-5.4.0-92_5.4.0-92.103_all.deb

https://source.android.com/devices/architecture/kernel/bpf

https://github.com/libbpf/libbpf/blob/master/.github/actions/vmtest/action.yml

https://www.aisp.sg/cyberfest/document/CRESTConSpeaker/eBPF.pdf

https://gist.github.com/goisneto/4e0a9c7c8cf6f6fc86fb96b454384c57

https://github.com/tiann/eadb

https://github.com/ehids/ecapture

https://blog.seeflower.dev/archives/139/

https://github.com/iovisor/bcc/issues/3175

https://android.googlesource.com/kernel/common/+/refs/heads/android11-5.4/build.config.gki_kprobes

https://android.googlesource.com/kernel/goldfish/+/refs/heads/android-goldfish-4.14-dev

https://android.googlesource.com/kernel/goldfish/+/refs/heads/android-goldfish-4.14-dev/kernel/trace/bpf_trace.c

https://android.googlesource.com/kernel/goldfish/+/refs/heads/android-goldfish-4.14-dev/mm/maccess.c

https://source.android.com/devices/architecture/kernel/android-common

https://android.googlesource.com/kernel/common/+refs

https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/include/uapi/linux/bpf.h

https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/trace/bpf_trace.c

https://android.googlesource.com/kernel/build/+/refs/heads/master-kernel-build-2021/build.sh

https://github.com/termux/proot-distro/releases/download/v1.2-ubuntu-focal-rootfs/ubuntu-focal-core-cloudimg-arm64-root-2020.12.10.tar.gz

https://github.com/termux/proot-distro/releases/download/v3.0.1/ubuntu-aarch64-pd-v3.0.1.tar.xz

https://github.com/termux/proot-distro/releases/tag/v3.0.1

https://github.com/microsoft/WSL/issues/5526
