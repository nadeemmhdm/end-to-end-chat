# 🛡️ Security Policy

## ⚠️ Educational & Research Disclaimer
**CipherCore** is an **open-source educational and research project** designed to explore browser-native client-side cryptography (`window.crypto.subtle`) and peer-to-peer WebRTC DataChannels.

> [!CAUTION]
> This application is **not** an audited, enterprise-certified communication tool. Do **not** use this software for mission-critical communications, protection against state-level adversaries, or life-sensitive data.

---

## 🔒 Supported Versions

Only the latest commit on the `main` branch deployed to [chat.qezvo.in](https://chat.qezvo.in/) is actively maintained.

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main` (latest)  | :white_check_mark: |
| legacy tags      | :x:                |

---

## 🛡️ Security Architecture & Threat Model

### In-Scope Protections
1. **Zero-Server Cryptography**:
   - Keys are derived locally in browser memory using **PBKDF2-HMAC-SHA256** with **600,000 rounds** (OWASP 2023+ recommendation).
   - All messages, voice notes, and file chunks are encrypted using **AES-256-GCM** with unique, non-repeating 96-bit IVs.
   - Ephemeral peer session keys are exchanged via **ECDH (Elliptic Curve Diffie-Hellman P-256)**, providing **Perfect Forward Secrecy (PFS)**.
2. **Zero-Knowledge Transport**:
   - WebRTC signaling servers only route encrypted session offers/answers. They **never** receive plaintext data or encryption keys.
3. **Strict Content Security Policy (CSP)**:
   - Restricts resource loading to vetted origins, preventing unauthorized script execution and data exfiltration.
4. **Memory Hygiene & Panic Mechanism**:
   - Cryptographic keys and state are cleared upon session close.
   - The Panic Killswitch (`Esc` key or UI button) overwrites key material, wipes local session storage, tears down WebRTC channels, and redirects away from the site.

### Out-of-Scope / Known Limitations
- **Compromised Endpoints**: Malware, rootkits, or keyloggers on user devices can capture plaintext prior to encryption.
- **Malicious Browser Extensions**: Rogue extensions with full DOM access can read user input fields. Users should run in Private/Incognito windows with extensions disabled.
- **Signaling Metadata**: While message payloads are fully encrypted end-to-end, network observers or STUN/TURN servers may observe IP addresses connecting to establish peer-to-peer paths (a standard characteristic of WebRTC). Using a trusted VPN or Tor bridges mitigates IP leakage.

---

## 🚨 Reporting a Vulnerability

If you discover a security issue, cryptographic flaw, or vulnerability in CipherCore:

1. **Do not open a public GitHub issue** with sensitive exploit details.
2. Please disclose responsibly by contacting the maintainer via:
   - **GitHub Security Advisories**: Submit a private advisory directly on [https://github.com/nadeemmhdm/end-to-end-chat/security/advisories](https://github.com/nadeemmhdm/end-to-end-chat/security/advisories)
   - Or email the repository maintainer with detailed reproduction steps.
3. **Include in your report**:
   - Detailed description of the vulnerability.
   - Step-by-step reproduction instructions or proof-of-concept (PoC).
   - The potential security impact and browser environment tested.
4. **Resolution Timeline**:
   - We strive to acknowledge vulnerability reports within **48 hours** and deploy patches to [chat.qezvo.in](https://chat.qezvo.in/) promptly.

---

## 🧪 Cryptographic Benchmark & Self-Audit

You can independently verify the cryptographic performance and AEAD integrity directly in your browser:
- Visit the hardware-accelerated benchmark suite: [https://chat.qezvo.in/audit.html](https://chat.qezvo.in/audit.html)
- Inspect source code: [audit.html](audit.html) and [js/crypto.js](js/crypto.js)
