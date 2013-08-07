#!/bin/bash

PID=`lsof | grep 10443 | grep LISTEN | awk '{print$2}'`
echo "killing ${PID}"

kill "${PID}"
