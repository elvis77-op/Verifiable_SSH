# Verifiable SSH
a SSH-based service that provides the only access to TD (Trust Domain) VM using a SSH client protected by an SGX (Software Guard Extenstions) enclave, where multi-party could verify the boot process of TD VM and the launch of VSSH client.

## Overview

VSSH consists of three components: VSSH client, VSSH server and Attestation service.
VSSH client running in a container protected by SGX enclave, acting as a standard SSH client that only recieves index to call corresponding command in SSH server. VSSH server is a standard SSH server in TD VM, but can only be accessed by VSSH client with its own SSH private key. Attestation Service/Verifiers running in each of the multi-party verification participants. Based on the verification results, participants can run a customized consensus to determine whether VSSH client and server are protected by SGX and TDVM, therefore trustworthy.


### Key Features

- SGX enclave and TDX for security
- Docker for easier deployment
- Mounted volume for data persistence
- SSH key verification for trustworthy
- Attestation service for verifiable

## Architechture
![Architecture.png](images/architecture.png)
## System Flow

```mermaid
sequenceDiagram
    box rgb(200,200,200,0.5) SGX enclave
        participant VSSH as VSSH client
    end
    actor ADMIN as Operator
    actor VF as Third-party Verifiers

    rect rgb(230,230,230,0.5)
        ADMIN->>+VSSH: Launch VSSH client
        Note over VSSH: Generate SGX quote
        VSSH->>VF: Send SGX quote
        Note over VF: Verify SGX quote
        VF-->>VSSH: VSSH client verified
        Note over VSSH: Generate ssh keypair
        Note over VSSH: Keep private key in SGX enclave
        VSSH->>VF: Send public key
        Note over VF: 1. Prepare a template TD VM
        Note over VF: 2. Include the public key (in TDVM)
        Note over VF: 3. Disable password login for SSH (in TDVM)
        Note over VF: 4. keep hashed guest image as reference
        VF->>ADMIN: Send TDVM image
        create participant BOOT as initrd
        ADMIN->>BOOT: Early boot with TDVM image
        Note over BOOT: Generate TD quote
        BOOT->>VF: Send TD quote
        Note over VF: Verify TD quote 
        destroy VF
        VF-->>BOOT: Send hashed guest image
        Note over BOOT: Check whether guest image matches the hash
        create participant TDVM as VSSH server (in TDVM)
        BOOT->>TDVM: Boot guest image
        destroy BOOT
        BOOT->>BOOT: Finish booting
        ADMIN->>VSSH: TDVM created
        Note over VSSH: Load customized programs
        VSSH->>TDVM: Transfer customized programs
        TDVM-->>VSSH: VSSH connection established
    end 

    
    loop 
        destroy ADMIN
        ADMIN->>VSSH: Select an index
        alt Capture STOP Sign
        Note over VSSH: Terminate process
        else
        Note over VSSH: Index certain program
        end
        VSSH->>TDVM: Request executing
        Note over TDVM: Execute corresponding program
        TDVM->>VSSH: Return execution ouput

    end
    
```

## Prerequisites

- Intel CPU with SGX and TDX support
- DCAP driver and related software stack
- Linux environment (this project has worked successfully with Ubuntu 22.04 LTS)

## Deployment 
Note: Please operate step 1- in a fully trusted environment


1. Clone the repository:
```bash
git clone https://github.com/elvis77-op/Verifiable_SSH.git
cd Verifiable_SSH
```

2. Generate Signing key pair for Verifier(need a python compilor):
```bash
python key_generate.py
```

3. Refer to <VSSH_client/README.md>

4. Refer to <Verifier/README.md>

## Usage


## Environment clean up
```bash
./clean_vssh.sh
```
## Current Phase
- [x] Basic connection of VSSH client and VSSH server
- [ ] Quote Verification for VSSH client
- [ ] Quote Verification for early boot of TD VM
  
## Future Work


### Security Enhancements
- [x] Remove insecure command-line arguments
- [ ] Add Quete Verification and Remote Attestation
  
### Feature Additions
- [ ] Add configuration for custom ssh command
  
### Architectural Improvements
- [ ] Create a configuration system for deployment flexibility

## Design Considerations for Future Versions

### Current Limitations