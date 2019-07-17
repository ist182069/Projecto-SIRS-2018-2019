#!/bin/bash
set -e

symkey=${1}
pubkeypath=${2}

echo ${symkey} > symkey.bin
openssl rsautl -encrypt -inkey ${pubkeypath} -pubin -in symkey.bin
rm symkey.bin