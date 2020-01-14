#!/bin/bash

rm memory.log
while true; do free -g >> memory.log; sleep 5; done

