#!/bin/sh

# arch="$(uname -m | sed "s/x86_64//")"; arch="${arch:+-$arch}"
curl -L -f -o ocm  https://github.com/openshift-online/ocm-cli/releases/download/v1.0.14/ocm-linux-amd64
chmod +x ocm
./ocm version
