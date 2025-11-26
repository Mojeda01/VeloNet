# VeloNet

[![Language](https://img.shields.io/badge/c%2B%2B-20-blue)](#build)
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM%20%2B%20HKDF-7D4896)](#dependencies)
[![Status](https://img.shields.io/badge/status-experimental-orange)](#status)
[![Website](https://img.shields.io/badge/marco--oj.no-000000?style=flat&logo=google-chrome&logoColor=white)](https://marco-oj.no)


VeloNet is a small C++20 backend that builds an encrypted transport layer for images.

It:

- ingests raw uploads and stores them under a sharded `data/images/**` tree
- exposes simple APIs for listing images and loading bytes by UUID
- manages cryptographic master keys
- provides AES-256-GCM + HKDF utilities for secure transport tokens

This repo focuses only on the C++ pipeline and crypto primitives.

## Status

Experimental but wired end-to-end:

- file flow from `uploads/` → `data/images/**`
- UUID-based lookup and raw image reads
- token generation and basic request validation
- master key generation and persistence
- AES-GCM encrypt/decrypt and HKDF session key derivation
- a single `testFullPipeline()` entrypoint in `main.cpp` that exercises the whole path

APIs and layout may change as the higher-level protocol and HTTP layer are built.

## Components

All implementation lives in the `.cpp` files:

- `FileManager.cpp`  
  Processes the `uploads/` directory, assigns UUIDs, and moves files into
  `data/images/<shard>/uuid.ext`.

- `webAPI.cpp`  
  Backend helpers: list stored images, validate tokens, and load image bytes by UUID.

- `TokenGenerator.cpp`  
  Cryptographically secure token generation and directory handling for persistent tokens.

- `KeyManagement.cpp`  
  Master key generation, hex rendering for debug, and saving/loading `data/master.key`.

- `EncryptionProc.cpp`  
  AES-256-GCM wrapper and HKDF-SHA256 session key derivation for the transport layer.

- `main.cpp`  
  Integration harness that runs `testFullPipeline()`.

## Dependencies

- C++20 compiler (g++/clang++)
- OpenSSL 3 (EVP, RAND, HKDF)
- Boost (UUID)
- CMake ≥ 3.16

Paths for OpenSSL and Boost are configured in `CMakeLists.txt`; adjust them for your system.

## Build

From the VeloNet directory:

```
bash
cmake -S . -B build
cmake --build build
```

This produces an executable (e.g. `build/velonet`).


