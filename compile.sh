#!/bin/bash

start_time=$(date +%s)

g++ main.cpp src/cpp/*.cpp -Wall -Werror -pedantic -lm -lpthread -lredis++ -lssl -lcrypto -lhiredis -std=c++20 -o app

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

# This script compiles the whole C++ project with G++
# And it returns 2 possible messages depending if the compilation was successful or not

#    ┏                                    ┓
#    ┃       ❌ Compilation failed!       ┃
#    ┗                                    ┛

#    ┏                                    ┓
#    ┃ Compilation finished: 20s elapsed. ┃
#    ┗                                    ┛