<div align="center">
<p align="center">
  <img src="https://r2.erweima.ai/ai_lib/b684248261924d749a23e58f3743d395_1705165118134.jpeg" alt="Drriga-Agent Mimari Banner" width="100%">
</p>

  <p align="center">
  <img src="https://r2.erweima.ai/ai_lib/474f568b6d124e72af290e819e72a891_1705165166077.jpeg" alt="Drriga-Agent Teknoloji Görseli" width="100%">
</p>

# 🛡️ Drriga-Agent
### Enterprise-Grade Hybrid Anti-Cheat & Runtime Security Reference Architecture

<p align="center">
  <img src="https://img.shields.io/badge/Architecture-Hybrid%20(R3%20%2B%20R0)-blue?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Core-Rust%20(no__std)%20%2B%20C%2FWDK-orange?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows%20x64-lightgrey?style=for-the-badge" />
</p>

*A high-performance, low-level security framework combining a user-mode Rust agent (`no_std`) with a kernel-mode WDK driver for robust integrity validation and threat mitigation.*

</div>

---

## ⚡ Overview

**Drriga-Agent** is a state-of-the-art reference architecture designed to demonstrate advanced system security concepts and low-level anti-cheat engineering. By bridging user-mode runtime verification with ring-0 kernel enforcement, it provides a resilient defense against modern memory manipulation, code injection, and environment tampering.

---

## 🏗️ System Architecture

The project follows a decoupled, highly secure hybrid model:

```text
 ┌─────────────────────────────────────────────────────────┐
 │                   User-Mode Agent                       │
 │        (Rust `no_std` / Cryptography / VAD Scanner)     │
 └────────────────────────────┬────────────────────────────┘
                              │ HMAC-Authenticated IOCTLs
                              │ (AES-GCM Secure Session)
 ┌────────────────────────────▼────────────────────────────┐
 │                  Kernel-Mode Driver                     │
 │          (C / WDK / Ring 0 / Memory Inspection)         │
 └─────────────────────────────────────────────────────────┘
🚀 Core Features
🛡️ Hybrid Ring 3 / Ring 0 Integration: Seamless communication channel between the user-mode Rust core and kernel-mode WDK driver.

🔒 Cryptographic Session Management: Employs AES-GCM encryption alongside HMAC-authenticated IOCTLs to prevent packet tampering, replay attacks, and unauthorized driver communication.

🔍 VAD-Based Memory Scanning: Deep inspection of Virtual Address Descriptors (VAD) to detect hidden regions, unauthorized RWX memory allocations, and manual mapping artifacts.

☕ JVM / JIT Integrity Validation: Specialized heuristics and memory integrity checks targeting managed runtimes to safeguard application memory.

⚡ Rust no_std User-Mode Core: Lightweight, high-performance execution environment minimizing runtime overhead and external dependencies.

📂 Repository Structure
Plaintext
Drriga-agent/
├── 📁 driver/
│   ├── CrAcDriver.c          # Ring 0 Kernel Driver implementation (WDK)
│   └── CrAcDriver.h          # Kernel-mode headers and IOCTL definitions
├── 📁 src/
│   ├── main.rs               # User-mode entry point & orchestration
│   ├── driver_comm.rs        # Secure IOCTL communication wrapper
│   ├── secure_session.rs     # AES-GCM & HMAC session handler
│   ├── vad_scanner.rs        # VAD-based memory inspection engine
│   └── jvm_integrity.rs      # Runtime / JIT integrity verification
├── Cargo.toml                # Rust workspace & dependency manifest
├── LICENSE.md                # MIT Open Source License
└── README.md                 # Project documentation
🛠️ Technical Stack
Languages: Rust (no_std), C (Windows Driver Kit / WDK)

Target OS: Windows x64 (Windows 10 / 11)

Security Primitives: Symmetric Encryption (AES-GCM), Message Authentication (HMAC), Kernel Memory APIs, VAD Tree Walkers.

⚠️ Disclaimer
This project is published strictly as an educational reference architecture and open-source security demonstration. It is intended for developers, security researchers, and students exploring low-level systems programming, OS internals, and defensive security engineering.

📄 License
Distributed under the MIT License. See LICENSE.md for more information.
