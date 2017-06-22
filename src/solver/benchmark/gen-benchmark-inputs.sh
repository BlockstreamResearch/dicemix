#!/bin/sh
mkdir -p output

for bits in 64 128 192 256 320 384 448 512 1024
do
    for n in 5 10 20 30 40 50 60 70 80 90 100
    do
        ./gen-input.sage "$bits" "$n" > "output/$bits-$n.txt"
    done
done
