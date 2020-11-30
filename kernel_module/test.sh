#!/bin/bash

echo
test_path="/home/TestAudit"
command="ls"

insmod AuditModule.ko

cd $test_path
echo "${test_path}# ${command}"
($command)
echo

cd /home/test/FileAudit/kernel_module
rmmod AuditModule.ko

curr_path=$(pwd)
if [ "$1"x == "c"x ]
then
    echo "${curr_path}# dmesg -c"
    dmesg -c
else
    echo "${curr_path}# dmesg"
    dmesg
fi
echo
