#!/bin/bash
set -e

encsymkeypath=${1}
privkeypath=${2}

openssl rsautl -decrypt -inkey ${privkeypath} -in ${encsymkeypath}
rm ${encsymkeypath}