#!/bin/sh

function readiness
{
    output=`netstat -tunlp | tail -n 4 | awk '{print $4}'`
    echo $output | grep 443 && echo $output | grep 22
}

function liveness
{
    output=`netstat -tunlp | tail -n 4 | awk '{print $4}'`
    echo $output | grep 443 && echo $output | grep 22
}

if [ "$1" == "readiness" ]
then
    readiness
else
    liveness
fi
