#!/bin/bash

cd output

echo "bits\msgs|5|10|20|30|40|50|60|70|80|90|100|" > results.md
echo "---|---|---|---|---|---|---|---|---|---|---|---|" >> results.md
for p in 64 128 192 256 320 448 512 1024
do
    echo -n "$p|" >> results.md
    for n in 5 10 20 30 40 50 60 70 80 90 100
    do
        gtime --format="%Us|" ./solver < "$p-$n.txt" 2>&1 > /dev/null | tr -d '\n' >> results.md
    done
    echo '' >> results.md
done
