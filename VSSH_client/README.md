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
Note: Note: Please make sure that you have completed [signing key generation](../README.md#Deployment) before VSSH client deployment
1. Edit config.py
   
2. Prepare customized scripts in ./scripts folder with template files in it

3. Run the following command to initialize VSSH_client and get the value of mrenclave and mrsigner
```bash
bash ../VSSH_client/build_vssh.sh
bash ../VSSH_client/launch_vssh.sh
```

## Usage
- ```bash bash launch_vssh.sh ``` to launch
- ```bash bash clean_vssh.sh ``` to clean previously stored ssh key pairs (dont recommended when VSSH connection is established)

tips: Every changes to the code of VSSH_client will result in different mrenclave value, in which you need to get the latest one to complete quote verification