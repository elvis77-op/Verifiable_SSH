# Verifier (Attestation Service)
## Prerequisites
- Docker service installed
- linux os (successfully tested with Ubuntu 24.04)

## Deployment
Note: Please make sure that you have completed the server-side key generation and the setup of VSSH client (refer to ../README.md) before Verifier deployment
1. Run the following command and assign "mrenclave" and "mrsigner" values (printed in console) to corresponding variables of config.py
```bash
bash ../VSSH_client/clean_vssh.sh
bash ../VSSH_client/build_vssh.sh
bash ../VSSH_client/launch_vssh.sh
```
2. Define config.py according to comment next to each variable

3. Run the following conmmand to update sgx_enclave_policy.json (required to verify SGX quote)
```bash
python policy_update.py
```

4. Define the pccs server address in sgx_default_qcnl.conf and modify other config (except "use_secure_cert" = "false" ) based on local environment 

5. Define proxy and no_proxy in Dockerfile to help build the docker image (optional)

## Usage
- ```bash bash build_verifier.sh ``` to build docker image
- ```bash bash launch_verifier.sh ``` to launch verifier (ctl-c to stop)

