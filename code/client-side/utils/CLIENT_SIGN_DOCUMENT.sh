#!/bin/bash
set -e

documentpath=${1}
privkeypath=${2}

openssl dgst -sha256 -sign ${privkeypath} -out ${documentpath}.sig ${documentpath}