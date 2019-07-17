#!/bin/bash
set -e

client_cert=${1}
client_cert_base_name=$(basename ${client_cert})
client_cert_base_name_no_ext="${client_cert_base_name%.*}"

# Sign and release a new certificate for the client, signed by client signing CA we built in the very beginning
openssl x509 -req -in ${client_cert} -sha1 -CA cli-signing-ca/sirs-cli-signing-ca.crt -CAkey cli-signing-ca/sirs-cli-signing-ca.key -CAcreateserial -out clients/client_certs/${client_cert_base_name_no_ext}.crt
openssl x509 -pubkey -noout -in clients/client_certs/${client_cert_base_name_no_ext}.crt  > clients/client_certs/${client_cert_base_name_no_ext}.pubkey