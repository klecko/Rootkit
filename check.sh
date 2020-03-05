#!/bin/bash

error () {
	echo -e "$1"
	exit 1
}

MODULE_NAME="rootkit"
CLIENT_NAME="client"
TESTFILE_NAME="h1d3m3"

echo "My PID is $$"

# Check unhide
which unhide &> /dev/null || error "Unhide is required to test process hiding. Run apt install unhide"

# Check if rootkit is present
lsmod | grep $MODULE_NAME &> /dev/null || error "Rootkit is not present or it is hidden"

# Check if client is here
ls $CLIENT_NAME &> /dev/null || error "Client not available"

# MODULE HIDING
echo "Checking module hiding"
echo "6" | ./client a &> /dev/null || echo "Error trying to hide module"
lsmod | grep $MODULE_NAME &> /dev/null && echo "Rootkit module was hidden but it is still visible to lsmod"

# HIDDEN FILES
# Create test file
echo "Checking hile hiding"
touch $TESTFILE_NAME

# Hide test file
echo "1${TESTFILE_NAME}" | ./client asd &> /dev/null
if [ $? -eq 0 ]; then
	ls | grep $TESTFILE_NAME &> /dev/null && echo "Test file $TESTFILE_NAME was hidden but it's still visible"

	# Unhide test file
	echo "2${TESTFILE_NAME}" | ./client a &> /dev/null || echo "Error trying to unhide test file $TESTFILE_NAME"
	ls | grep $TESTFILE_NAME &> /dev/null || echo "Test file $TESTFILE_NAME was unhidden but it is not visible"
else
	echo "Error trying to hide file test file $TESTFILE_NAME"
fi

rm $TESTFILE_NAME

# HIDDEN PROCESSES
echo "Checking PID hiding"
ps $$ &> /dev/null || error "Process not found with ps ???"

# Hide
echo "3$$" | ./client a &> /dev/null
if [ $? -eq 0 ]; then
	ps $$ &> /dev/null && echo "Process $$ was hidden but it's still visible"

	# Unhide checks
	check_unhide () {
		echo "Running unhide $1"
		unhide_output=`sudo unhide $1 2> /dev/null` || echo -e "Unhide $1 found something:\n$unhide_output \n"
	}

	check_unhide brute
	check_unhide procall
	check_unhide sys

	# Unhide
	echo "4$$" | ./client a &> /dev/null || echo "Error trying to unhide PID $$"
	ps $$ &> /dev/null || echo "Process $$ was unhidden but it is not visible"

else
	echo "Error trying to hide PID $$"
fi

echo "7" | ./client a &> /dev/null || echo "Error trying to unhide module"
lsmod | grep $MODULE_NAME &> /dev/null || echo "Rootkit module was unhidden but it is not visible to lsmod"


echo "FINISHED"


