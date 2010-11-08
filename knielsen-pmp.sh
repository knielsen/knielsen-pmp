#!/bin/bash
nsamples=500
sleeptime=0.01

mkdir -p $HOME/.pmp
pid=""
while [ "$pid" = "" ] ; do
    pid=$(pidof mysqld)
done
MAP_FILE="$HOME/.pmp/pmp-maps-$$.map"
cat /proc/$pid/maps > "$MAP_FILE"

for x in $(seq 1 $nsamples)
  do
    get_stacktrace $pid
    sleep $sleeptime
  done | \
resolve-stack-traces.pl -g "$MAP_FILE" | \
#tee "$HOME/.pmp/pmp.log" | \
awk '
  BEGIN { s = ""; } 
  /Thread: [0-9]+/ { print s; s = ""; } 
  /^\#/ { if (s != "" ) { s = s "," $4} else { s = $4 } } 
  END { print s }' | \
sort | uniq -c | sort -r -n -k 1,1
