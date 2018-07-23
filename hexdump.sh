#!/bin/bash

### convenience script for dumping binary input as hex
### dump is 4 bytes per line for relation to RFC 2131 Figure 1

od -Ax -w4 -t x1z "$@"
