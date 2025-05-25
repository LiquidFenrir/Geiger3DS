#!/bin/bash

cmake -S . -B $1 -G Ninja
cmake --build $1
