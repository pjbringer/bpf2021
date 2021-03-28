#!/bin/sh

INDEX=docs/external/index.txt
if [ ! -r "$INDEX" ] ; then
    echo "Missing $INDEX" 1>&2
fi

cd $(dirname "$INDEX")
grep -v "^ *#" $(basename "$INDEX") | while read line; do
    echo "$DNAME"
    if [ ! -f "$DNAME" ] ; then
        curl -O "$DURL";
    fi
done
