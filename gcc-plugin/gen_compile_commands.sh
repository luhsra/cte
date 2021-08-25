#!/usr/bin/env bash

OUT=compile_commands.json

printf "[\n" > $OUT
for f in *.cc; do
    obj=${f%.cc}.o
    printf '{ "directory": "%s", "file": "%s", "command": "%s" },\n' \
           "$PWD" "$f" "$(make -n "$obj" | head -n 1)" >> $OUT
done
printf "]\n" >> $OUT
