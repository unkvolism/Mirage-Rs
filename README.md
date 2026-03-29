# Mirage-Rs

Mirage-Rs is a Rust-based reimplementation of the Mirage technique, leveraging Virtualization-Based Security (VBS) enclaves to stage, protect, and execute payloads across VTL boundaries.

This project demonstrates how sensitive data (such as shellcode) can be encrypted ("sealed") inside a VTL1 enclave and later decrypted ("unsealed") into VTL0 memory for execution, effectively bypassing traditional memory inspection and detection mechanisms.


<p align="center">
  <img src="https://i.imgur.com/BJnOW6b.png" alt="pic" width="100%"/>
</p>

---

## Overview

Mirage-Rs abuses the trust boundary between Virtual Trust Levels (VTL0 and VTL1) by:

1. Creating a VBS enclave
2. Loading a vulnerable enclave image
3. Initializing enclave communication
4. Using enclave-provided functions to:
   - Seal (encrypt) arbitrary data into VTL1
   - Unseal (decrypt) data back into VTL0
5. Executing the unsealed payload in RWX memory
6. Cleaning up traces by overwriting memory

---

## Technique Details

The core idea behind Mirage is leveraging VBS enclaves as a trusted encryption/decryption oracle:

- **Seal operation**: Moves data from VTL0 → VTL1 (encrypted blob)
- **Unseal operation**: Moves data from VTL1 → VTL0 (plaintext restored)

Because the enclave operates in VTL1, its memory is protected from inspection by standard user-mode and even many kernel-mode security solutions.

---

## Execution Flow

1. **Enclave Creation**
   - Uses `CreateEnclave` with `ENCLAVE_TYPE_VBS`

2. **Image Loading**
   - Loads a vulnerable enclave DLL (`prefs_enclave_x64.dll`)

3. **Initialization**
   - Calls the enclave's `Init` routine via `CallEnclave`

4. **Payload Staging**
   - Shellcode is sealed into enclave memory (VTL1)

5. **Execution**
   - Payload is unsealed into RWX memory (VTL0)
   - Execution is triggered via function pointer

6. **Cleanup**
   - Memory is overwritten using a secondary sealed buffer

---


## References

- https://github.com/akamai/Mirage  
- https://github.com/JayGLXR/RustyMirage  

---
