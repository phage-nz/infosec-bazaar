#!/bin/bash
find /opt/dionaea/var/dionaea/bistreams/* -type f -name '*.tar.gz' -mtime +7 -exec rm {} \;

date=$(date -d "yesterday" '+%Y-%m-%d')
bistreams=/opt/dionaea/var/dionaea/bistreams/$date
if [ -d "$bistreams" ]; then
  tar -czf - -C $bistreams . > /opt/dionaea/var/dionaea/bistreams/$date.tar.gz
  rm -rf $bistreams
fi
