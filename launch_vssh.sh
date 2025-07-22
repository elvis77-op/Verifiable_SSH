#!/bin/bash

docker run --rm --device /dev/sgx/enclave --device /dev/sgx/provision -v vssh_keys:/root/enc_keys/ -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket -it verifiable_ssh