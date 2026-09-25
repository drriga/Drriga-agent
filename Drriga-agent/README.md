# 🛡️ drriga-agent

[![Rust](https://img.shields.io/badge/Language-Rust%20(no__std)-orange.svg)](https://www.rust-lang.org/)
[![C](https://img.shields.io/badge/Kernel-C%20(WDK)-blue.svg)](https://learn.microsoft.com/en-us/windows-hardware/drivers/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**crac-agent** is an enterprise-grade, hybrid user-mode and kernel-mode anti-cheat reference architecture. Designed with a modular workspace approach, it leverages low-level system security primitives to counter advanced memory manipulation, manual mapping, and JIT/JVM tampering without triggering false positives.

---

## 🏗️ Architecture Overview

The system implements a multi-layered defense strategy, maintaining secure communication between the user-mode agent and the Ring 0 kernel driver via authenticated IOCTLs.

```text
+-------------------------------------------------------+
|                 User-Mode Agent (Rust)                |
|  +-----------------+  +----------------------------+  |
|  |   main.rs       |  |  secure_session.rs         |  |
|  | (Orchestration) |  |  (AES-GCM + Nonce / Seq)   |  |
|  +--------+--------+  +--------------+-------------+  |
|           |                          |                |
|           v                          v                |
|  +-----------------+  +----------------------------+  |
|  | vad_scanner.rs  |  |  jvm_integrity.rs          |  |
|  | (VAD / RWX Scan)|  |  (Bytecode SHA256 / JIT)   |  |
|  +--------+--------+  +--------------+-------------+  |
+--------------------------------------|----------------+
                                       |
                       (HMAC-Authenticated IOCTL / IPC)
                                       |
+--------------------------------------v----------------+
|                Kernel-Mode Driver (Ring 0 / C)        |
|                  [ CrAcDriver.c / .h ]                |
+-------------------------------------------------------+

--------------------------------------------------------------------------------

drriga-agent/
├── Cargo.toml                 # Rust workspace and dependency configurations
├── README.md                  # Project documentation
├── driver/                    # Ring 0 Kernel Component
│   ├── CrAcDriver.c           # Kernel-side logic and system callbacks
│   └── CrAcDriver.h           # Kernel-user shared definitions and IOCTL codes
└── src/                       # User-Mode Agent Components (Rust)
    ├── main.rs                # Hybrid event-driven & periodic main loop
    ├── secure_session.rs      # Cryptographic session manager (ECDH / AES-GCM)
    ├── vad_scanner.rs         # Virtual Address Descriptor (VAD) & RWX analyzer
    ├── jvm_integrity.rs       # JVM bytecode hashing & structural JIT validator
    └── driver_comm.rs         # Secure communication bridge with kernel driver

-------------------------------------------------------------------------------------------------------------------


🚀 Key Modules & Features
1. Secure Session Manager (secure_session.rs)
Replaces hardcoded keys with runtime-derived secrets.

Utilizes AES-GCM encryption combined with monotonic sequence numbers to prevent replay attacks and secure heartbeat telemetry.

2. VAD-Based Memory Scanner (vad_scanner.rs)
Performs event-driven and periodic scans using VirtualQueryEx.

Targets committed PAGE_EXECUTE_READWRITE (RWX) and PAGE_EXECUTE_WRITECOPY regions to detect manual mapping, reflective DLL injection, and unbacked shellcode.

Cross-validates findings with JIT memory boundaries to prevent false positives.

3. JVM Integrity & JIT Validation (jvm_integrity.rs)
Bytecode Verification: Computes SHA256 hashes of immutable class files against known safe baselines.

JIT Structural Validation: Avoids fragile static hashing for dynamic code caches. Instead, it validates execution entry points, prologue patterns, and structural bounds to detect hooks without crashing under legitimate JIT optimizations.

4. Authenticated Driver Communication (driver_comm.rs)
Establishes a secure communication channel between the user-mode agent and the kernel driver.

Uses HMAC + Nonce signatures on IOCTL packets to prevent control-code spoofing and unauthorized third-party driver interactions.

⚠️ Disclaimer
This repository is published solely for educational purposes, research, and security architecture reference. It demonstrates low-level system programming concepts, memory analysis techniques, and defensive architecture design under Windows.

📄 License
Distributed under the MIT License. See LICENSE for more information.