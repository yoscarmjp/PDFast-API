#!/bin/bash

start_time=$(date +%s)

g++ main.cpp src/cpp/*.cpp -lm -lpthread -lredis++ -lssl -lcrypto -lhiredis -std=c++20 -o app
if [ $? -ne 0 ]; then
    echo "\e[31m"
    echo "     ┏                                    ┓"
    echo "     ┃       ❌ Compilation failed!       ┃"
    echo "     ┗                                    ┛"
    echo "\e[0m"
    exit 1
fi


end_time=$(date +%s)
elapsed_time=$((end_time - start_time))

msg="Compilation finished: ${elapsed_time}s elapsed."
len=${#msg}
border=$(printf "%${len}s" | tr ' ' ' ')

echo "     ┏ $border ┓"
echo "     ┃ $msg ┃"
echo "     ┗ $border ┛"
