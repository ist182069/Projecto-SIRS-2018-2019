#!/bin/bash
set -e

documentpath=${1}
documentsigpath=${2}
privkeypath=${3}

openssl dgst -sha256 -verify ${privkeypath} -signature ${documentsigpath} ${documentpath}