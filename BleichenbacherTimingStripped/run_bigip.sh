
#!/bin/bash

ret=1

while [ $ret -ne 0 ]
do
	echo -n "Starting attack. "
	date 

	mvn exec:java > log.log
	ret=$?

	cp log.log "`date --rfc-3339=ns`.log"

	# mail -s "timing log: Result: $ret" schinzel@colonwq.org < log.log 

done

echo -n "success!!  "
date

