#!/bin/bash

if [ -n "$(gofmt -l .)" ]; then
    echo 'Please run "go fmt ./..." to format the code'
    exit 1
fi
