#! /bin/bash
./run.sh $1 $2 | grep '^Timings' | sed 'N;s/\n/ /;s/Timings Server: \([.0-9]\+\) sec.*\([0-9]\+\) passwords) Timings Client: \([.0-9]\+\) sec.*/\2 \1 \3/g'
