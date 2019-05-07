#!/bin/bash

#### Replace with binary package
# Get SCION executables ready
sudo chown scion:scion -R ./bin
sudo chmod +x ./bin/*
# Add python dependencies
pip3 install --user -r env/pip3/requirements.txt
mkdir -p ./gen-cache
#### 

