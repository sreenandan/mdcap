#!/bin/sh

function readiness
{
    output=`netstat -tunlp | tail -n 2 | awk '{print $4}'`
    echo $output | grep 8000 && echo $output | grep 3000
}

function liveness
{
    output=`netstat -tunlp | tail -n 2 | awk '{print $4}'`
    echo $output | grep 8000 && echo $output | grep 3000
}

if [[ "$1" == "readiness" ]]
then
    readiness
else
    liveness
fi