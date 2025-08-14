# Verifier (Attestation Service)
## Prerequisites
- Docker service installed
- linux os (successfully tested with Ubuntu 24.04)

## Deployment
Note: Note: Please make sure that you have completed [server-side key generation](../README.md#Deployment) and [setup of VSSH client](../VSSH_client/README.md#Deployment) before Verifier deployment

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
To install a local pccs service, refer to [PCCS installtion](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/main/QuoteGeneration/pccs)

5. Define proxy and no_proxy in Dockerfile to help build the docker image (optional)

6. Be causious that when you modify the signing key paths, you may need to sync these changes in config.py

## Usage
- ```bash bash build_verifier.sh ``` to build docker image
- ```bash bash launch_verifier.sh ``` to launch verifier (ctl-c to stop)

