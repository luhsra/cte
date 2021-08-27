#!/usr/bin/env bash

# Call this from the source directories

OUT=compile_commands.json

shopt -s nullglob

printf "[\n" > $OUT
for f in {*.c,*.cc}; do
    obj=${f%.c*}.o
    printf '{ "directory": "%s", "file": "%s", "command": "%s" },\n' \
           "$PWD" "$f" "$(make -n --always-make "$obj" | head -n 1)" >> $OUT
done
printf "]\n" >> $OUT
