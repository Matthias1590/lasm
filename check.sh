#!/bin/bash

set -xe

# Assemble
nasm -felf64 check.s

# Dump
objdump -d check.o
