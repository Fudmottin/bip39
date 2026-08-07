#!/bin/sh

for suit in c d h s; do
   for rank in a 2 3 4 5 6 7 8 9 10 j q k; do
      printf '%s\n' "${rank}${suit}"
   done
done | ./build/debug/seeds --cards-only --words 12

