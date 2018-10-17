#!/bin/bash

set -xeuo pipefail

close_connections() {
    CONNS=$(ss -nptau -o state established | tail -n +2 | awk '{print $4 $6}' | \
                sed -E 's/^.+:([0-9]+).+pid=([0-9]+).+$/\1:\2/g' | xargs)
    for conn in ${CONNS}; do
        pid=${conn#*:}
        port=${conn%:*}
        fd=$(lsof -np ${pid} | grep "(ESTABLISHED)" | awk '{print $4}' | \
                 sed -E 's/([0-9]+).*/\1/g')
        # Si esto no va, probar con shutdown(${fd}, 0)
        ./test ${pid} ${fd}
    done
}

while true; do
    sleep 15
    close_connections
done
