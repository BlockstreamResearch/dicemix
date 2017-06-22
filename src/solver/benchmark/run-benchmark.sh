#!/bin/sh

cd output

echo ";5;10;20;30;40;50;60;70;80;90;100" > results.csv
for p in 64 128 192 256 320 448 512 1024
do
    echo -n "$p;" >> results.csv
    for n in 5 10 20 30 40 50 60 70 80 90 100
    do
        time --format="%U;" ./solver < "$p-$n.txt" 2>&1 > /dev/null | tr -d '\n' >> results.csv
    done
    echo '' >> results.csv
done
