#!/bin/bash
sen_ratio=0
size_array=5000000

rm micro1.sweep.log

#./bm_largest_num_vanilla 0 $size_array $sen_ratio | grep "Number of seconds" | awk '{print $4}' 2>&1 | tee -a micro1.sweep.log

echo '==================' >> micro1.sweep.log

while [ $sen_ratio -lt 100 ]; do
    let sen_ratio=sen_ratio+1
    ./bm_largest_num 0 $size_array $sen_ratio | grep "Number of seconds" | awk '{print $4}' 2>&1 | tee -a micro1.sweep.log
    sleep 1
done

echo '==================' >> micro1.sweep.log

size_array=10000

while [ $sen_ratio -lt 100 ]; do
    let sen_ratio=sen_ratio+1
    ./bm_largest_num 1 $size_array $sen_ratio | grep "Number of seconds" | awk '{print $4}' 2>&1 | tee -a micro1.sweep.log
    sleep 1
done


