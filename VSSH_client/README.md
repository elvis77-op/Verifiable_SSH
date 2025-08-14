# VSSH_client

## Work flow
VSSH_client consists of two components: Attestation client and SSH client. When Attestation client recieve approved message from Attestation server, it will automately trigger SSH client.

### Attestation service


### SSH service


## Prerequisites
- Intel CPU with SGX and TDX support
- DCAP driver and related software stack
- Linux environment (this project has worked successfully with Ubuntu 22.04 LTS)

## Deployment
Note: Note: Please make sure that you have completed the server-side key generation and the setup of VSSH client (refer to ../README.md) before Verifier deployment
- 