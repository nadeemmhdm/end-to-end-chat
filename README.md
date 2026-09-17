# 🛡️ CipherCore | Zero-Server End-to-End Encrypted (E2EE) Chat

A high-security, high-privacy, serverless peer-to-peer web chat application built with vanilla JavaScript, HTML5, and CSS3. Designed for zero-configuration hosting on **GitHub Pages**.

---

## 🌟 Key Features

- 🔐 **Zero-Server Architecture**: 100% client-side operation. No databases, no telemetry, no message logs.
- 🔑 **Auto-Generated 16-Character Cryptographic Passwords**: Built-in CSPRNG (`crypto.getRandomValues`) key generator with Shannon entropy meter (~102 bits).
- 🛡️ **End-to-End Encryption (E2EE)**:
  - **AES-GCM 256-bit** authenticated encryption (AEAD) with fresh 96-bit IV per message.
  - **PBKDF2** key derivation with 600,000 rounds of SHA-256 (OWASP compliant).
  - **Ephemeral ECDH (P-256)** key exchange providing **Perfect Forward Secrecy (PFS)**.
- ⏱️ **Self-Destructing / Ephemeral Messages**: Configurable countdown burn timers (10s, 30s, 1m, 5m, 1h) with animated visual progress bars.
- 📁 **E2EE File & Media Transfer**: In-browser client-side chunked AES-GCM file encryption and streaming via WebRTC DataChannels.
- 🎙️ **Encrypted Voice Notes**: In-browser audio recording directly encrypted on-the-fly.
- 🔢 **Signal-Style 60-Digit Safety Numbers**: Cryptographic fingerprint blocks for verifying immunity to Man-In-The-Middle (MITM) attacks.
- 🚨 **Panic Killswitch (`Esc` key or Button)**: Instantly overwrites cryptographic memory with zeroes, destroys WebRTC peer sessions, purges the DOM, and redirects to DuckDuckGo.
- 🧮 **Decoy Mode**: Camouflage calculator disguise with secret unlock code (`1337 =`).
- 🕶️ **Anti-Shoulder-Surfing Blur**: Automatically obscures chat messages whenever the browser tab or window loses focus.
- 🎨 **Modern Cyber Glassmorphism UI**: High-contrast, responsive layout with Boxicons and multi-theme switcher (Obsidian Stealth, Cyber Violet, Electric Cyan).

---

## 🚀 How to Host on GitHub Pages (Zero-Server)

1. Create a new repository on GitHub (e.g., `ciphercore-chat`).
2. Push or upload all files in this directory to your repository:
   - `index.html`
   - `audit.html`
   - `manifest.json`
   - `css/style.css`
   - `js/crypto.js`
   - `js/webrtc.js`
   - `js/app.js`
3. In your GitHub repository:
   - Navigate to **Settings** → **Pages**.
   - Under **Build and deployment** > **Source**, choose **Deploy from a branch**.
   - Select your `main` or `master` branch and folder `/ (root)`.
   - Click **Save**.
4. Your encrypted chat application will be live at `https://<your-username>.github.io/<repo-name>/`.

---

## 🔒 Threat Model & Architecture

Read the full technical whitepaper and execute the hardware-accelerated benchmark suite in [audit.html](file:///c:/Users/nadee/JC-Nadeem%20M-700d/Test%20Sites/end%20to%20end/audit.html).
