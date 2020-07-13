#!/bin/bash


filename=httpd.out.novfa
grep "undefined reference" $filename | awk '{print $7}' | awk -F "'" '{print $2}' | sort | uniq | xargs -L 1 printf "fun:%s=uninstrumented\n" $1
grep "undefined reference" $filename | awk '{print $7}' | awk -F "'" '{print $2}' | sort | uniq | xargs -L 1 printf "fun:%s=discard\n" $1
