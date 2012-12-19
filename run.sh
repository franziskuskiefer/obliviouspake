#! /bin/bash
for ((i=2;i<=$2;i++))
	do
		./ospake $1 $i
	done
