#!/bin/bash

docker run --rm -it --network=host -v sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf verifier