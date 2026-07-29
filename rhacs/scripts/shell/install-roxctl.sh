#!/bin/sh

arch="$(uname -m | sed "s/x86_64//")"; arch="${arch:+-$arch}"
curl -L -f -o roxctl "https://mirror.openshift.com/pub/rhacs/assets/4.9.2/bin/Linux/roxctl${arch}"
chmod +x roxctl
