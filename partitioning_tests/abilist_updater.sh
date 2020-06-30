#!/bin/bash



filename=test.out
grep "undefined reference" $filename | awk '{print $7}' | awk -F '$' '{print $2}' | awk -F "'" '{print $1}' | sort | uniq | xargs -L 1 printf "fun:%s=uninstrumented\n" $1
grep "undefined reference" $filename | awk '{print $7}' | awk -F '$' '{print $2}' | awk -F "'" '{print $1}' | sort | uniq | xargs -L 1 printf "fun:%s=discard\n" $1
