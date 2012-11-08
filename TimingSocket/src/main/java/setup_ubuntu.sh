#!/bin/bash

sudo cpufreq-set -c0 -f 3.1Ghz
sudo cpufreq-set -c1 -f 3.1Ghz
sudo cpufreq-set -c2 -f 3.1Ghz
sudo cpufreq-set -c3 -f 3.1Ghz

cat /proc/cpuinfo | grep 'cpu MHz'
