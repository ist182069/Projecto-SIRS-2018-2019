#!/bin/bash
set -e
this_script_dir=${1}

# Generate Client Keys and Client Certificate Signing Request (CSR)
# Use the csr config file to generate both a certificate signing request
# and a private key for the client
openssl req -new -out sirs-client.csr -config ${this_script_dir}/conf_client/client_crt_config.conf
# Get client public key from client private key
openssl rsa -in sirs-client.key -pubout -out sirs-client.pubkey

mv sirs-client.pubkey ${this_script_dir}/mycerts/
mv sirs-client.key ${this_script_dir}/mycerts/
mv sirs-client.csr ${this_script_dir}/mycerts/

# After this step, the client application is now ready to send the CSR through the secure channel
# and receive afterwards the "client.crt" file, signed by the server
