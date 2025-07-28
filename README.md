# Verifiable SSH
a SSH-based service that provides the only access to TD(Trust Domain) VM using an SGX (Software Guard Extenstions) enclave as SSH client, where multi-party could verify the initialization of TD VM and the setup of VSSH

## Overview

This service acts as an agent to execute custom shell command in TD VM, allowing multi-party to verify it based on its measurements. For the security consideration, another agent that get the access to measurements of the initializaion of TD VM is also needed.

### Key Features

## Architechture
(architecture.png)

## System Flow

sequenceDiagram
      participant TDVM as TD VM
      box rgb(230,230,230) SGX enclave
            participant VSSH as VSSH
      end
      actor ADMIN as Administrator
      actor VF as Third-party Verifiers

      alt initialization
      rect rgb(200,230,230,0.5)
            ADMIN->>+VSSH: Setup
            Note over VSSH: Generate SGX quote
            VSSH->>VF: Send SGX quote
            Note over VSSH: Generate ssh keypair
            VSSH->>ADMIN: Send public key
            Note over ADMIN: Include public key and disable password login in VM image
            ADMIN->>VF: Send hashed VM image
            ADMIN->>+TDVM: Setup
            Note over TDVM: Generate TD quote
            TDVM->>VF: Send TD quote
            Note over VSSH: Load customed scripts 
            VSSH->>TDVM: Transfer customed scripts
      end

      else connection established
            loop 
                  VSSH->>TDVM: Trigger preinstalled program
                  Note over TDVM: Execute corresponding program
                  alt Capture STOP Sign
                  Note over VSSH: Terminate process
                  end
            end
      end


## Prerequisites

- Intel CPU with SGX and TDX support
- DCAP driver and related software stack
- Linux environment (this project has worked successfully with Ubuntu 22.04 LTS)

## Deployment

1. Clone the repository:
```bash
git clone https://github.com/elvis77-op/Verifiable_SSH.git
cd Verifiable_SSH
```

2. Add proxy in Dockerfile (optional)

3. Define the address and port of TDVM in main.sh

4. Build the project:
```bash
chmod +x *.sh
./build_vssh.sh
```
5. Run the project:
```bash
./launch_vssh.sh
```

## Environment clean up
```bash
./clean_vssh.sh"
```

## Future Work

### Security Enhancements
- [ ] Remove insecure command-line arguments
- [ ] Add Quete Verification and Remote Attestation
  
### Feature Additions
- [ ] Add configuration for custom ssh command
  
### Architectural Improvements
- [ ] Create a configuration system for deployment flexibility

## Design Considerations for Future Versions

### Current Limitations