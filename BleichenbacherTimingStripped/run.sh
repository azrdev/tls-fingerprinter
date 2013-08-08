
#!/bin/bash

/etc/init.d/network-manager stop

ret=1

while [ $ret -ne 0 ]
do
	ifconfig eth0 192.168.0.2
	#ifconfig eth0
	sleep 5
	echo -n "Starting attack. "
	date 

	mvn exec:java > log.log
	ret=$?

	ifconfig eth0 192.168.3.20
	#ifconfig eth0
	route add default gw 192.168.3.2
	echo "nameserver 192.168.3.2" > /etc/resolv.conf
	#netstat -rn

	mail -s "timing log: Result: $ret" schinzel@colonwq.org < log.log 
	/etc/init.d/postfix restart
	postqueue -f

	exit 1

	sleep 15
done

echo -n "success!!  "
date
/etc/init.d/network-manager start

