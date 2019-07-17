#!/bin/bash
set -e


# NOT NEEDED WRITE OPERATIONS:
# generate an RSA key for the server (not needed anymore)
# openssl genrsa -out sirs-server.key 2048
# Get server public key from server private key
# openssl rsa -in sirs-server.key -pubout -out sirs-server.pubkey

# RELEVANT READ OPERATIONS:
# output private, public, and other information
# openssl rsa -in sirs-server.key -noout -text
# generate a simple certificate signing request (passphrase: 123456 or none)
# openssl req -new -key sirs-server.key -out sirs-server.csr
# look at CSR contents (signature algorithm: sha256WithRSAEncryption)
# openssl req -in sirs-server.csr -noout -text

# PLEASE, DISCARD ANYTHING ABOVE THIS COMMENT.

# "confs/" directory is assumed to exist already, with both the CA and server configs in there
# clean previous file structure
[ -e ca ] && rm -r ca/
[ -e cli-signing-ca ] && rm -r cli-signing-ca/
[ -e server ] && rm -r server/


# create initial file structure
# ref: https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
# keys in ca and client signing ca are in PKCS#1 format
mkdir ca/
mkdir cli-signing-ca/
# keys in server are in PKCS#8 format
mkdir server/



# WRITE OPERATIONS:

# (building client-side trust anchor: authenticate server)
# Generate CA Key and CA self-signed Certificate
openssl genrsa -out ca/sirs-ca.key 2048
openssl req -new -x509 -key ca/sirs-ca.key -out ca/sirs-ca.crt -config confs/ca_crt_config.conf

# (building server-side trust anchor: authenticate clients)
# Generate Client-Signing-Certificate, which will be another self-signed CA by itself,
# but will be shared with the client through a secure and authenticated socket, so client
# will be granted certainty that this certificate is coming from the server
openssl genrsa -out cli-signing-ca/sirs-cli-signing-ca.key 2048
openssl req -new -x509 -key cli-signing-ca/sirs-cli-signing-ca.key -out cli-signing-ca/sirs-cli-signing-ca.crt -config confs/cli-signing-ca_crt_config.conf

# Generate Server Keys and Server Certificate Signing Request (CSR)
# Use the csr config file to generate both a certificate signing request
# and a private key for the server
openssl req -new -out sirs-server.csr -config confs/server_crt_config.conf
mv sirs-server.csr sirs-server.key server/


# Sign and release a new certificate for the server, signed by the ca
openssl x509 -req -in server/sirs-server.csr -sha1 -CA ca/sirs-ca.crt -CAkey ca/sirs-ca.key -CAcreateserial -out server/sirs-server.crt
rm server/sirs-server.csr