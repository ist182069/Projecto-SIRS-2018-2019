#!/bin/bash
set -e

# Sign some data using a private key
# openssl rsautl -sign -in file -inkey key.pem -out sig

#Recover the signed data
#openssl rsautl -verify -in sig -inkey key.pem

# Generate 32 bytes (256-bit) secret
secret=$(openssl rand -base64 32)

# Generate Symmetric Key
aesoutput=$(openssl enc -aes-256-cbc -k ${secret} -P -pbkdf2 -md sha256)
key=${aesoutput:26:64}
iv=${aesoutput:95}

echo "key="${key}
echo "iv="${iv}