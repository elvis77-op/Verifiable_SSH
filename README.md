# Verifiable SSH

## Overview

### Key Features

## System Flow

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
    run "./clean_vssh.sh"

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