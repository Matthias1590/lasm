#!/bin/bash

set -xe

# Assemble
make lasm
./lasm test.s

# Link
cc -o test test.c out.o

# Run
rm *.o
./test
