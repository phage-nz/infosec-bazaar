#!/bin/bash
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6

cd /home/ubuntu/misp-feeds

python3 /home/ubuntu/misp-feeds/feed_manager.py
PIDS[0]=$!

trap "kill ${PIDS[*]}" SIGINT

wait
