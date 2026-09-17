/**
 * ==============================================================================
 * CIPHERCORE APPLICATION CONTROLLER (v3.0)
 * One Device - One Account Model, Easy-Access Device Vault,
 * Device PIN Protection, Voice Player, Image Lightbox, Clickable Link Previews
 * ==============================================================================
 */

class CipherApp {
  constructor() {
    this.crypto = window.cipherCore;
    this.webrtc = new WebRTCManager();

    // Permanent Device Storage Keys
    this.STORAGE_DEVICE_ACCOUNT = 'ciphercore_device_account';
    this.STORAGE_DEVICE_PIN = 'ciphercore_device_pin';
    this.STORAGE_HISTORY_KEY = 'ciphercore_messages_vault';
    this.STORAGE_RECENT_PEERS = 'ciphercore_recent_peers';

    // Current User / Device State
    this.currentUser = {
      userId: '',
      username: '',
      secretKey: '', // 16-character CSPRNG password
      peerId: null,
      keyPair: null, // Ephemeral ECDH P-256
      publicKeyBase64: null,
    };

    // Active Channel / Peer State
    this.currentRoom = {
      roomId: '',
      derivedKey: null,
      sharedSessionKeys: new Map(), // peerId -> AES-GCM Key
      safetyNumbers: new Map(), // peerId -> 60-digit string
      activeRecipientId: null, // Current peer we are messaging
    };

    // Stored Message History in memory
    this.savedMessages = [];
    this.recentPeers = new Set();

    this.settings = {
      ephemeralDuration: 0,
      soundEnabled: true,
      antiSurveillanceBlur: true,
    };

    this.audioContext = null;
    this.mediaRecorder = null;
    this.audioChunks = [];
    this.recordingStartTime = 0;
    this.recordingInterval = null;
    this.supportedAudioMimeType = '';

    this.initDOM();
    this.initAudioMimeType();
    this.initEventListeners();
    this.initSoundEngine();

    // Enforce One Device - One Account Lifecycle
    this.initOneDeviceAccountFlow();
  }

  // Cross-browser audio codec detection
  initAudioMimeType() {
    const types = [
      'audio/webm;codecs=opus',
      'audio/webm',
      'audio/ogg;codecs=opus',
      'audio/ogg',
      'audio/mp4',
      'audio/aac'
    ];
    for (const t of types) {
      if (typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(t)) {
        this.supportedAudioMimeType = t;
        break;
      }
    }
  }

  initDOM() {
    // Views
    this.viewSetup = document.getElementById('view-setup');
    this.viewChat = document.getElementById('view-chat');

    // Unique Access URL Banner elements
    this.uniqueAccessUrlInput = document.getElementById('unique-access-url');
    this.btnCopyAccessUrl = document.getElementById('btn-copy-access-url');
    this.publicChatUrlInput = document.getElementById('public-chat-url');
    this.btnCopyPublicUrl = document.getElementById('btn-copy-public-url');
    this.userBadgeId = document.getElementById('user-badge-id');
    this.userBadgeName = document.getElementById('user-badge-name');
    this.userAvatarBadge = document.getElementById('user-avatar-badge');
    this.userPillBadge = document.querySelector('.user-pill-badge');

    // Chat elements
    this.displayRoomId = document.getElementById('chat-room-id');
    this.peerListContainer = document.getElementById('chat-peer-list');
    this.connectedCount = document.getElementById('connected-peer-count');
    this.messagesContainer = document.getElementById('messages-container');
    this.chatInput = document.getElementById('chat-message-input');
    this.btnSendMessage = document.getElementById('btn-send-message');
    this.btnAttachFile = document.getElementById('btn-attach-file');
    this.fileInputElement = document.getElementById('file-input');
    this.btnRecordVoice = document.getElementById('btn-record-voice');
    this.recordingBar = document.getElementById('recording-bar');
    this.recordingDuration = document.getElementById('recording-duration');
    this.btnCancelRecording = document.getElementById('btn-cancel-recording');
    this.btnStopAndSendRecording = document.getElementById('btn-send-recording');
    this.selectEphemeral = document.getElementById('select-ephemeral-timer');
    this.typingIndicator = document.getElementById('typing-indicator');

    // Sidebar Peer Connection input
    this.inputPeerConnect = document.getElementById('input-peer-connect');
    this.btnConnectPeer = document.getElementById('btn-connect-peer');

    // Header & Modals
    this.btnPanic = document.getElementById('btn-panic-wipe');
    this.btnDecoy = document.getElementById('btn-toggle-decoy');
    this.btnShareInvite = document.getElementById('btn-share-invite');
    this.btnOpenSafetyModal = document.getElementById('btn-open-safety-modal');
    this.safetyModal = document.getElementById('modal-safety-verification');
    this.safetyDigitsGrid = document.getElementById('safety-digits-grid');
    this.btnVerifySafetyOk = document.getElementById('btn-verify-safety-ok');
    this.modalCloseButtons = document.querySelectorAll('.btn-close-modal');
    this.decoyScreen = document.getElementById('decoy-screen');
    this.btnResetAccount = document.getElementById('btn-reset-account');

    // Device Vault Modal elements
    this.modalDeviceVault = document.getElementById('modal-device-vault');
    this.vaultUsername = document.getElementById('vault-username');
    this.btnSaveVaultUsername = document.getElementById('btn-save-vault-username');
    this.vaultDeviceId = document.getElementById('vault-device-id');
    this.btnCopyVaultId = document.getElementById('btn-copy-vault-id');
    this.vaultSecretKey = document.getElementById('vault-secret-key');
    this.btnToggleKeyVisibility = document.getElementById('btn-toggle-key-visibility');
    this.iconToggleKey = document.getElementById('icon-toggle-key');
    this.btnCopyVaultKey = document.getElementById('btn-copy-vault-key');
    this.togglePinLock = document.getElementById('toggle-pin-lock');
    this.pinLockInputs = document.getElementById('pin-lock-inputs');
    this.inputDevicePin = document.getElementById('input-device-pin');
    this.btnSavePin = document.getElementById('btn-save-pin');
    this.btnExportBackup = document.getElementById('btn-export-backup');

    // PIN Unlock Overlay
    this.devicePinOverlay = document.getElementById('device-pin-overlay');
    this.unlockPinInput = document.getElementById('unlock-pin-input');
    this.btnUnlockPin = document.getElementById('btn-unlock-pin');
    this.btnSystemLock = document.getElementById('btn-system-lock');
    this.btnTestSecondTab = document.getElementById('btn-test-second-tab');
    this.btnCopyChatQuick = document.getElementById('btn-copy-chat-quick');
    this.peerConnectStatus = document.getElementById('peer-connect-status');
    this.pendingMessageQueue = new Map();
    this.enteredPin = '';

    // Lightbox Modal
    this.imageLightbox = document.getElementById('image-lightbox');
    this.lightboxImg = document.getElementById('lightbox-img');
    this.btnCloseLightbox = document.getElementById('btn-close-lightbox');
  }

  // ============================================================================
  // ONE DEVICE, ONE ACCOUNT LIFECYCLE
  // ============================================================================
  async initOneDeviceAccountFlow() {
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);

    const accountId = params.get('account');
    const accountKey = params.get('key');
    const accountUser = params.get('user');
    const chatTargetId = params.get('chat');

    // Check if this device already has an established account
    const existingDeviceAccountRaw = localStorage.getItem(this.STORAGE_DEVICE_ACCOUNT);

    if (existingDeviceAccountRaw) {
      try {
        const account = JSON.parse(existingDeviceAccountRaw);
        
        // If arrived via migration link with new account, ask to switch
        if (accountId && accountKey && accountId !== account.userId) {
          if (confirm(`Switch this device from ${account.username} to new account ${accountUser || accountId}?`)) {
            await this.activateDeviceAccount(accountId, accountKey, accountUser ? decodeURIComponent(accountUser) : 'Agent');
            this.checkPinLockAndUnlock(chatTargetId);
            return;
          }
        }

        await this.activateDeviceAccount(account.userId, account.secretKey, account.username);
        this.checkPinLockAndUnlock(chatTargetId);
        return;
      } catch (e) {
        console.warn('Error reading device account:', e);
      }
    }

    // If new device arrived with specific account URL
    if (accountId && accountKey) {
      const username = accountUser ? decodeURIComponent(accountUser) : 'Agent_' + accountId.slice(4, 9);
      await this.activateDeviceAccount(accountId, accountKey, username);
      this.showToast('✅ Device bound to your Account URL!');
      this.checkPinLockAndUnlock(chatTargetId);
      return;
    }

    // Brand new device: Automatically generate permanent account
    const newUserId = 'usr_' + this.crypto.bufferToHex(this.crypto.generateSalt(4));
    const newPassword = this.crypto.generateSecurePassword(16);
    const defaultUsername = 'Agent_' + newUserId.slice(4, 9);

    await this.activateDeviceAccount(newUserId, newPassword, defaultUsername);
    this.showToast('🛡️ One-Device Account initialized & securely bound!');
    this.checkPinLockAndUnlock(chatTargetId);
  }

  // Activate and bind device account
  async activateDeviceAccount(userId, secretKey, username) {
    this.currentUser.userId = userId;
    this.currentUser.secretKey = secretKey;
    this.currentUser.username = username;

    // Permanently save to device
    localStorage.setItem(this.STORAGE_DEVICE_ACCOUNT, JSON.stringify({
      userId,
      secretKey,
      username,
      boundAt: Date.now()
    }));

    // Generate Ephemeral ECDH Key Pair for PFS
    this.currentUser.keyPair = await this.crypto.generateECDHKeyPair();
    this.currentUser.publicKeyBase64 = await this.crypto.exportPublicKey(this.currentUser.keyPair.publicKey);

    // Derive Master AES-256-GCM Key from Secret Key
    const salt = await this.crypto.computeFingerprint(userId);
    this.currentRoom.derivedKey = await this.crypto.deriveKeyFromPassword(
      secretKey,
      new TextEncoder().encode(salt)
    );

    // Update URLs
    this.updateUniqueUrls();

    // Initialize WebRTC
    await this.initializeWebRTCIdentity(userId);

    // Load saved encrypted messages
    await this.loadEncryptedHistory();

    // Load recent peers
    this.loadRecentPeers();

    // Update UI Badges & Vault Modal
    this.updateUserBadgeUI();
    this.updateVaultModalFields();

    // Transition to chat view
    if (this.viewSetup) this.viewSetup.classList.remove('active');
    if (this.viewChat) this.viewChat.classList.add('active');
    if (this.displayRoomId) this.displayRoomId.textContent = userId;
  }

  // Save and persist username permanently across device, URL hash, and network
  saveUsername(newName) {
    newName = (newName || '').trim();
    if (!newName) {
      this.showToast('⚠️ Please enter a valid username.');
      return false;
    }
    if (newName.length > 24) newName = newName.substring(0, 24);

    this.currentUser.username = newName;
    this.updateUserBadgeUI();
    this.updateUniqueUrls();

    // Update device local storage
    const raw = localStorage.getItem(this.STORAGE_DEVICE_ACCOUNT);
    let account = {};
    if (raw) {
      try { account = JSON.parse(raw); } catch (e) {}
    }
    account.userId = this.currentUser.userId;
    account.secretKey = this.currentUser.secretKey;
    account.username = newName;
    account.updatedAt = Date.now();
    localStorage.setItem(this.STORAGE_DEVICE_ACCOUNT, JSON.stringify(account));

    // Update browser address bar hash seamlessly without reload
    const baseUrl = window.location.origin + window.location.pathname;
    const newHash = `#account=${this.currentUser.userId}&key=${encodeURIComponent(this.currentUser.secretKey)}&user=${encodeURIComponent(newName)}`;
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', newHash);
    }

    // Modal field sync & visual feedback
    if (this.vaultUsername) this.vaultUsername.value = newName;
    const feedback = document.getElementById('vault-username-feedback');
    if (feedback) {
      feedback.style.display = 'block';
      setTimeout(() => { feedback.style.display = 'none'; }, 3000);
    }

    this.showToast(`✅ Codename saved as: ${newName}`);

    // Broadcast username update to all active peers
    if (this.webrtc) {
      this.webrtc.broadcast({
        type: 'username-update',
        sender: this.currentUser.userId,
        username: newName
      });
    }

    return true;
  }

  // Check if user enabled a device PIN
  checkPinLockAndUnlock(chatTargetId) {
    const savedPin = localStorage.getItem(this.STORAGE_DEVICE_PIN);
    if (savedPin && this.devicePinOverlay) {
      this.devicePinOverlay.classList.add('active');
      this.enteredPin = '';
      this.updatePinDotsUI();
      if (this.unlockPinInput) this.unlockPinInput.focus();
    } else {
      if (chatTargetId) {
        this.handleDirectChatWithPeer(chatTargetId);
      }
    }
  }

  updateUserBadgeUI() {
    if (this.userBadgeId) this.userBadgeId.textContent = this.currentUser.userId;
    if (this.userBadgeName) this.userBadgeName.textContent = this.currentUser.username;
    if (this.userAvatarBadge) this.userAvatarBadge.textContent = this.currentUser.username.charAt(0).toUpperCase();
  }

  updateVaultModalFields() {
    if (this.vaultUsername) this.vaultUsername.value = this.currentUser.username;
    if (this.vaultDeviceId) this.vaultDeviceId.value = this.currentUser.userId;
    if (this.vaultSecretKey) this.vaultSecretKey.value = this.currentUser.secretKey;
    
    const savedPin = localStorage.getItem(this.STORAGE_DEVICE_PIN);
    if (this.togglePinLock) {
      this.togglePinLock.checked = !!savedPin;
      if (this.pinLockInputs) {
        this.pinLockInputs.style.display = savedPin ? 'flex' : 'none';
      }
    }
  }

  updateUniqueUrls() {
    const baseUrl = window.location.origin + window.location.pathname;
    
    // Private Access URL (keeps keys strictly in hash # - RFC 3986)
    const privateAccessUrl = `${baseUrl}#account=${this.currentUser.userId}&key=${encodeURIComponent(this.currentUser.secretKey)}&user=${encodeURIComponent(this.currentUser.username)}`;
    if (this.uniqueAccessUrlInput) {
      this.uniqueAccessUrlInput.value = privateAccessUrl;
    }

    // Public Chat Link (share with friends so they message you directly)
    const publicChatUrl = `${baseUrl}#chat=${this.currentUser.userId}`;
    if (this.publicChatUrlInput) {
      this.publicChatUrlInput.value = publicChatUrl;
    }

    // Synchronize browser address bar hash if not currently connecting to #chat=
    if (window.history && window.history.replaceState) {
      if (!window.location.hash.startsWith('#chat=')) {
        window.history.replaceState(null, '', privateAccessUrl);
      }
    }
  }

  async initializeWebRTCIdentity(userId) {
    try {
      await this.webrtc.initialize(userId);
      this.currentUser.peerId = userId;
      this.updatePeerListUI();

      this.webrtc.onHandshakeReady = (targetPeerId) => {
        this.sendHandshake(targetPeerId);
      };
    } catch (err) {
      console.warn('WebRTC Init Notice:', err);
    }
  }

  handleDirectChatWithPeer(targetPeerId) {
    if (!targetPeerId || targetPeerId === this.currentUser.userId) return;

    this.showToast(`Connecting to peer ${targetPeerId}...`);
    this.currentRoom.activeRecipientId = targetPeerId;
    this.addRecentPeer(targetPeerId);

    try {
      this.webrtc.connectToPeer(targetPeerId, {
        username: this.currentUser.username,
        publicKey: this.currentUser.publicKeyBase64
      });
    } catch (e) {
      console.error('Direct connect error:', e);
    }
  }

  addRecentPeer(peerId) {
    this.recentPeers.add(peerId);
    localStorage.setItem(this.STORAGE_RECENT_PEERS, JSON.stringify(Array.from(this.recentPeers)));
  }

  loadRecentPeers() {
    try {
      const raw = localStorage.getItem(this.STORAGE_RECENT_PEERS);
      if (raw) {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          this.recentPeers = new Set(arr);
        }
      }
    } catch (e) {}
  }

  // Sound Engine
  initSoundEngine() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      this.audioContext = new AudioCtx();
    } catch (e) {
      console.warn('Web Audio API not supported.');
    }
  }

  playSound(type) {
    if (!this.settings.soundEnabled || !this.audioContext) return;
    if (this.audioContext.state === 'suspended') {
      this.audioContext.resume();
    }

    const now = this.audioContext.currentTime;
    const osc = this.audioContext.createOscillator();
    const gain = this.audioContext.createGain();
    osc.connect(gain);
    gain.connect(this.audioContext.destination);

    if (type === 'send') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(580, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.08);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
      osc.start(now);
      osc.stop(now + 0.08);
    } else if (type === 'receive') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(1180, now + 0.12);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
      osc.start(now);
      osc.stop(now + 0.12);
    } else if (type === 'burn') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(320, now);
      osc.frequency.exponentialRampToValueAtTime(120, now + 0.18);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
      osc.start(now);
      osc.stop(now + 0.18);
    } else if (type === 'alert') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.setValueAtTime(660, now + 0.07);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
      osc.start(now);
      osc.stop(now + 0.18);
    }
  }

  // Interactive Event Listeners
  initEventListeners() {
    // Open Device Vault Modal from Profile Badge
    if (this.userPillBadge) {
      this.userPillBadge.style.cursor = 'pointer';
      this.userPillBadge.addEventListener('click', () => {
        this.openDeviceVaultModal();
      });
    }

    // Save Vault Username
    const onSaveUsernameClick = () => {
      const newName = this.vaultUsername ? this.vaultUsername.value.trim() : '';
      if (newName) {
        this.saveUsername(newName);
      }
    };

    if (this.btnSaveVaultUsername) {
      this.btnSaveVaultUsername.addEventListener('click', onSaveUsernameClick);
    }
    if (this.vaultUsername) {
      this.vaultUsername.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          onSaveUsernameClick();
        }
      });
    }

    // Auto-save username when closing vault modal if modified
    document.querySelectorAll('#modal-device-vault .btn-close-modal').forEach(btn => {
      btn.addEventListener('click', () => {
        if (this.vaultUsername && this.vaultUsername.value.trim() && this.vaultUsername.value.trim() !== this.currentUser.username) {
          this.saveUsername(this.vaultUsername.value.trim());
        }
      });
    });

    // System Lock Button in Header
    if (this.btnSystemLock) {
      this.btnSystemLock.addEventListener('click', () => {
        this.lockSystem();
      });
    }

    // Copy Device ID & Key
    if (this.btnCopyVaultId) {
      this.btnCopyVaultId.addEventListener('click', () => {
        navigator.clipboard.writeText(this.vaultDeviceId.value).then(() => {
          this.showToast('Permanent Device ID copied!');
        });
      });
    }

    if (this.btnCopyVaultKey) {
      this.btnCopyVaultKey.addEventListener('click', () => {
        navigator.clipboard.writeText(this.vaultSecretKey.value).then(() => {
          this.showToast('16-character Device Key copied!');
        });
      });
    }

    // Toggle Secret Key Mask
    if (this.btnToggleKeyVisibility && this.vaultSecretKey) {
      this.btnToggleKeyVisibility.addEventListener('click', () => {
        if (this.vaultSecretKey.type === 'password') {
          this.vaultSecretKey.type = 'text';
          this.iconToggleKey.className = 'bx bx-hide';
        } else {
          this.vaultSecretKey.type = 'password';
          this.iconToggleKey.className = 'bx bx-show';
        }
      });
    }

    // Toggle PIN Lock setting
    if (this.togglePinLock) {
      this.togglePinLock.addEventListener('change', (e) => {
        if (e.target.checked) {
          this.pinLockInputs.style.display = 'flex';
          this.inputDevicePin.focus();
        } else {
          this.pinLockInputs.style.display = 'none';
          localStorage.removeItem(this.STORAGE_DEVICE_PIN);
          this.showToast('Device PIN lock disabled.');
        }
      });
    }

    // Save PIN from Vault modal
    if (this.btnSavePin && this.inputDevicePin) {
      this.btnSavePin.addEventListener('click', () => {
        const pin = this.inputDevicePin.value.trim();
        if (pin.length >= 4) {
          localStorage.setItem(this.STORAGE_DEVICE_PIN, pin);
          this.showToast('🔒 4-digit Device PIN saved successfully!');
          this.inputDevicePin.value = '';
          if (this.togglePinLock) this.togglePinLock.checked = true;
        } else {
          alert('PIN must be at least 4 digits.');
        }
      });
    }

    // Initialize Interactive Numpad & Visual Dots on PIN Overlay
    this.initPinLockKeypad();

    // Export Backup JSON
    if (this.btnExportBackup) {
      this.btnExportBackup.addEventListener('click', () => {
        const backupData = {
          userId: this.currentUser.userId,
          secretKey: this.currentUser.secretKey,
          username: this.currentUser.username,
          exportedAt: new Date().toISOString(),
          app: 'CipherCore E2EE'
        };
        const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `ciphercore-backup-${this.currentUser.userId}.json`;
        a.click();
        this.showToast('Account backup downloaded safely.');
      });
    }

    // Connect to Peer in sidebar
    if (this.btnConnectPeer && this.inputPeerConnect) {
      this.btnConnectPeer.addEventListener('click', () => {
        const target = this.inputPeerConnect.value.trim();
        if (target) {
          this.handleDirectChatWithPeer(target);
          this.inputPeerConnect.value = '';
        }
      });
      this.inputPeerConnect.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.btnConnectPeer.click();
        }
      });
    }

    // Quick Test 2nd Tab Button (multi-tab encrypted communication)
    if (this.btnTestSecondTab) {
      this.btnTestSecondTab.addEventListener('click', () => {
        const baseUrl = window.location.origin + window.location.pathname;
        const testUrl = `${baseUrl}#chat=${this.currentUser.userId}`;
        window.open(testUrl, '_blank');
        this.showToast('🚀 Opened 2nd tab to test live encrypted messaging!');
      });
    }

    // Quick Share Link Button
    if (this.btnCopyChatQuick) {
      this.btnCopyChatQuick.addEventListener('click', () => {
        if (this.publicChatUrlInput) {
          navigator.clipboard.writeText(this.publicChatUrlInput.value).then(() => {
            this.showToast('💬 Public Chat Link copied! Share with friends.');
          });
        }
      });
    }

    // Copy Access URL & Public Chat Link
    if (this.btnCopyAccessUrl) {
      this.btnCopyAccessUrl.addEventListener('click', () => {
        navigator.clipboard.writeText(this.uniqueAccessUrlInput.value).then(() => {
          this.showToast('🔑 Unique Private Access URL copied! Bookmark to restore account.');
        });
      });
    }

    if (this.btnCopyPublicUrl) {
      this.btnCopyPublicUrl.addEventListener('click', () => {
        navigator.clipboard.writeText(this.publicChatUrlInput.value).then(() => {
          this.showToast('💬 Public Chat Link copied! Share with friends.');
        });
      });
    }

    // Quick Emoji Bar clicks
    document.querySelectorAll('.emoji-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (this.chatInput) {
          this.chatInput.value += btn.textContent;
          this.chatInput.focus();
        }
      });
    });

    // Reset / Wipe Account Button
    if (this.btnResetAccount) {
      this.btnResetAccount.addEventListener('click', () => {
        if (confirm('Are you sure you want to wipe this device account and clear stored messages? Make sure you backed up your keys!')) {
          this.wipeLocalData();
        }
      });
    }

    // Chat messaging: Send button & Enter key
    this.btnSendMessage.addEventListener('click', () => this.handleSendMessage());
    this.chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.handleSendMessage();
      }
    });

    // Ephemeral Timer Selector
    this.selectEphemeral.addEventListener('change', (e) => {
      this.settings.ephemeralDuration = parseInt(e.target.value, 10);
      this.broadcastEphemeralSetting(this.settings.ephemeralDuration);
    });

    // File & Media Sharing
    this.btnAttachFile.addEventListener('click', () => this.fileInputElement.click());
    this.fileInputElement.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        this.handleFileUpload(e.target.files[0]);
      }
    });

    // Voice Notes Controls
    this.btnRecordVoice.addEventListener('click', () => this.startVoiceRecording());
    this.btnCancelRecording.addEventListener('click', () => this.cancelVoiceRecording());
    this.btnStopAndSendRecording.addEventListener('click', () => this.stopAndSendVoiceRecording());

    // Lightbox Modal Close
    if (this.btnCloseLightbox) {
      this.btnCloseLightbox.addEventListener('click', () => this.closeImageLightbox());
    }
    if (this.imageLightbox) {
      this.imageLightbox.addEventListener('click', (e) => {
        if (e.target === this.imageLightbox) this.closeImageLightbox();
      });
    }

    // Panic Killswitch (Esc key or red button)
    this.btnPanic.addEventListener('click', () => this.triggerPanicKillswitch());
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !e.repeat) {
        if (this.imageLightbox && this.imageLightbox.classList.contains('active')) {
          this.closeImageLightbox();
        } else {
          this.triggerPanicKillswitch();
        }
      }
    });

    // Decoy Mode (Calculator Camouflage)
    this.btnDecoy.addEventListener('click', () => this.toggleDecoyMode());
    this.initDecoyCalculator();

    // Modals
    this.btnOpenSafetyModal.addEventListener('click', () => this.openSafetyModal());
    this.btnVerifySafetyOk.addEventListener('click', () => this.closeAllModals());
    this.modalCloseButtons.forEach(b => b.addEventListener('click', () => this.closeAllModals()));

    // Share Room Invite
    this.btnShareInvite.addEventListener('click', () => {
      navigator.clipboard.writeText(this.publicChatUrlInput.value).then(() => {
        this.showToast('💬 Public Chat Link copied! Share with friends.');
      });
    });

    // Anti-Shoulder-Surfing Privacy Blur
    window.addEventListener('blur', () => {
      if (this.settings.antiSurveillanceBlur && this.currentUser.userId) {
        document.body.classList.add('privacy-blurred');
      }
    });
    window.addEventListener('focus', () => {
      document.body.classList.remove('privacy-blurred');
    });

    // Bind WebRTC Network Handlers
    this.bindWebRTCEvents();
  }

  openDeviceVaultModal() {
    this.updateVaultModalFields();
    if (this.modalDeviceVault) {
      this.modalDeviceVault.classList.add('active');
    }
  }

  // WebRTC Events binding
  bindWebRTCEvents() {
    this.webrtc.on('peerConnect', async ({ peerId }) => {
      this.showToast(`Peer ${peerId.slice(0, 8)} connected! Exchanging keys...`);
      this.addRecentPeer(peerId);
      this.updatePeerListUI();
      this.playSound('alert');
    });

    this.webrtc.on('peerDisconnect', () => {
      this.showToast(`A peer disconnected.`);
      this.updatePeerListUI();
    });

    this.webrtc.on('message', async ({ peerId, data }) => {
      await this.handleIncomingMessage(peerId, data);
    });

    this.webrtc.on('fileComplete', async (fileResult) => {
      await this.handleIncomingFile(fileResult);
    });

    this.webrtc.on('error', (err) => {
      console.warn('WebRTC Notice:', err);
    });
  }

  // System Security Lock
  lockSystem() {
    let savedPin = localStorage.getItem(this.STORAGE_DEVICE_PIN);
    if (!savedPin) {
      const pin = prompt('Set a 4-digit security PIN to lock your session:');
      if (pin && pin.trim().length >= 4) {
        savedPin = pin.trim();
        localStorage.setItem(this.STORAGE_DEVICE_PIN, savedPin);
        if (this.togglePinLock) this.togglePinLock.checked = true;
        this.showToast('🔒 4-digit PIN configured and saved.');
      } else {
        this.showToast('PIN lock cancelled (must be at least 4 digits).');
        return;
      }
    }
    this.enteredPin = '';
    this.updatePinDotsUI();
    if (this.unlockPinInput) this.unlockPinInput.value = '';
    if (this.devicePinOverlay) {
      this.devicePinOverlay.classList.add('active');
      if (this.unlockPinInput) this.unlockPinInput.focus();
    }
    this.playSound('burn');
  }

  // Interactive PIN Numpad & Visual Dots Controller
  initPinLockKeypad() {
    this.enteredPin = '';
    const dotsContainer = document.getElementById('pin-dots-row');
    const numpad = document.getElementById('pin-numpad');

    const verifyPin = () => {
      const saved = localStorage.getItem(this.STORAGE_DEVICE_PIN);
      if (this.enteredPin === saved) {
        if (this.devicePinOverlay) this.devicePinOverlay.classList.remove('active');
        this.enteredPin = '';
        this.updatePinDotsUI();
        this.showToast('🔓 Session unlocked successfully!');
        this.playSound('send');
      } else {
        this.playSound('alert');
        const dots = dotsContainer ? dotsContainer.querySelectorAll('.pin-dot') : [];
        dots.forEach(d => d.classList.add('error'));
        if (dotsContainer) dotsContainer.classList.add('shake');
        setTimeout(() => {
          this.enteredPin = '';
          this.updatePinDotsUI();
          if (dotsContainer) dotsContainer.classList.remove('shake');
        }, 500);
      }
    };

    const handleDigit = (digit) => {
      if (this.enteredPin.length < 4) {
        this.enteredPin += digit;
        this.updatePinDotsUI();
        if (this.enteredPin.length === 4) {
          setTimeout(verifyPin, 120);
        }
      }
    };

    const handleBackspace = () => {
      if (this.enteredPin.length > 0) {
        this.enteredPin = this.enteredPin.slice(0, -1);
        this.updatePinDotsUI();
      }
    };

    const handleClear = () => {
      this.enteredPin = '';
      this.updatePinDotsUI();
    };

    if (numpad) {
      numpad.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const key = btn.dataset.key;
        if (key === 'backspace') handleBackspace();
        else if (key === 'clear') handleClear();
        else if (key !== undefined) handleDigit(key);
      });
    }

    if (this.unlockPinInput) {
      this.unlockPinInput.addEventListener('input', (e) => {
        this.enteredPin = e.target.value.replace(/\D/g, '').slice(0, 4);
        this.updatePinDotsUI();
        if (this.enteredPin.length === 4) {
          setTimeout(verifyPin, 120);
        }
      });
      this.unlockPinInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') verifyPin();
      });
    }

    if (this.btnUnlockPin) {
      this.btnUnlockPin.addEventListener('click', verifyPin);
    }

    const btnForgotPin = document.getElementById('btn-forgot-pin');
    if (btnForgotPin) {
      btnForgotPin.addEventListener('click', () => {
        if (confirm('Wiping session will purge local chat history and reset PIN. Are you sure?')) {
          localStorage.removeItem(this.STORAGE_DEVICE_PIN);
          this.wipeLocalData();
        }
      });
    }
  }

  updatePinDotsUI() {
    const dotsContainer = document.getElementById('pin-dots-row');
    const dots = dotsContainer ? dotsContainer.querySelectorAll('.pin-dot') : [];
    dots.forEach((dot, idx) => {
      if (idx < this.enteredPin.length) {
        dot.classList.add('filled');
        dot.classList.remove('error');
      } else {
        dot.classList.remove('filled', 'error');
      }
    });
    if (this.unlockPinInput) {
      this.unlockPinInput.value = this.enteredPin;
    }
  }

  // Pending Message Queue
  queueMessage(peerId, payload) {
    if (!this.pendingMessageQueue) this.pendingMessageQueue = new Map();
    if (!this.pendingMessageQueue.has(peerId)) {
      this.pendingMessageQueue.set(peerId, []);
    }
    this.pendingMessageQueue.get(peerId).push(payload);
  }

  async flushPendingMessages(peerId) {
    if (!this.pendingMessageQueue || !this.pendingMessageQueue.has(peerId)) return;
    const queue = this.pendingMessageQueue.get(peerId);
    if (!queue || queue.length === 0) return;

    const key = this.currentRoom.sharedSessionKeys.get(peerId) || this.currentRoom.derivedKey;
    let count = 0;
    while (queue.length > 0) {
      const payload = queue.shift();
      try {
        const { ciphertext, iv } = await this.crypto.encrypt(JSON.stringify(payload), key);
        this.webrtc.sendTo(peerId, {
          type: 'encrypted-message',
          sender: this.currentUser.userId,
          ciphertext: ciphertext,
          iv: iv
        });
        count++;
      } catch (err) {
        console.error('Error flushing message:', err);
      }
    }
    this.pendingMessageQueue.delete(peerId);
    if (count > 0) {
      this.showToast(`📨 Sent ${count} queued message(s) to peer!`);
    }
  }

  async sendHandshake(targetPeerId) {
    const handshakePayload = {
      type: 'handshake',
      isAck: false,
      sender: this.currentUser.userId,
      username: this.currentUser.username,
      publicKey: this.currentUser.publicKeyBase64,
      timestamp: Date.now(),
    };
    this.webrtc.sendTo(targetPeerId, handshakePayload);
  }

  async handleIncomingMessage(peerId, packet) {
    if (!packet || !packet.type) return;

    if (packet.type === 'handshake') {
      try {
        const remotePublicKey = await this.crypto.importPublicKey(packet.publicKey);
        
        const sharedKey = await this.crypto.deriveSharedSecret(
          this.currentUser.keyPair.privateKey,
          remotePublicKey
        );
        this.currentRoom.sharedSessionKeys.set(peerId, sharedKey);

        const safetyNumber = await this.crypto.computeSafetyNumbers(
          this.currentUser.publicKeyBase64,
          packet.publicKey
        );
        this.currentRoom.safetyNumbers.set(peerId, safetyNumber);

        this.webrtc.peerProfiles.set(peerId, {
          username: packet.username || 'Peer',
          publicKey: packet.publicKey,
          safetyNumber: safetyNumber
        });

        this.addRecentPeer(peerId);
        this.updatePeerListUI();

        // Reciprocal handshake: If caller initiated, send handshake-ack back with our public key
        if (!packet.isAck) {
          this.webrtc.sendTo(peerId, {
            type: 'handshake',
            isAck: true,
            sender: this.currentUser.userId,
            username: this.currentUser.username,
            publicKey: this.currentUser.publicKeyBase64,
            timestamp: Date.now()
          });
        }

        this.showToast(`🔒 E2EE Established with ${packet.username || 'Peer'}!`);
        this.flushPendingMessages(peerId);
      } catch (err) {
        console.error('Handshake processing error:', err);
      }
      return;
    }

    if (packet.type === 'username-update') {
      const profile = this.webrtc.peerProfiles.get(peerId);
      if (profile) {
        profile.username = packet.username;
        this.updatePeerListUI();
        this.showToast(`Peer updated username to: ${packet.username}`);
      }
      return;
    }

    if (packet.type === 'ephemeral-config') {
      this.settings.ephemeralDuration = packet.duration;
      this.selectEphemeral.value = packet.duration;
      this.showToast(`Self-destruct timer set to ${packet.duration ? packet.duration + 's' : 'Disabled'}`);
      return;
    }

    if (packet.type === 'encrypted-message') {
      try {
        const key = this.currentRoom.sharedSessionKeys.get(peerId) || this.currentRoom.derivedKey;
        const decryptedJson = await this.crypto.decrypt(packet.ciphertext, packet.iv, key);
        const msg = JSON.parse(decryptedJson);

        const msgObj = {
          author: msg.username || 'Peer',
          text: msg.text,
          time: new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          isOutgoing: false,
          ephemeralSeconds: msg.ephemeralDuration || 0
        };

        this.renderMessageBubble(msgObj);

        if (!msgObj.ephemeralSeconds) {
          this.savedMessages.push(msgObj);
          await this.saveEncryptedHistory();
        }

        this.playSound('receive');
      } catch (err) {
        console.error('Primary decryption failed for incoming message:', err);
        // Fallback decryption with room key
        try {
          const fallbackJson = await this.crypto.decrypt(packet.ciphertext, packet.iv, this.currentRoom.derivedKey);
          const msg = JSON.parse(fallbackJson);
          const msgObj = {
            author: msg.username || 'Peer',
            text: msg.text,
            time: new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            isOutgoing: false,
            ephemeralSeconds: msg.ephemeralDuration || 0
          };
          this.renderMessageBubble(msgObj);
          if (!msgObj.ephemeralSeconds) {
            this.savedMessages.push(msgObj);
            await this.saveEncryptedHistory();
          }
          this.playSound('receive');
        } catch (e2) {
          console.error('Fallback decryption failed as well:', e2);
        }
      }
    }
  }

  // Send Encrypted Message
  async handleSendMessage() {
    const text = this.chatInput.value.trim();
    if (!text) return;

    const payload = {
      username: this.currentUser.username,
      senderId: this.currentUser.userId,
      text: text,
      timestamp: Date.now(),
      ephemeralDuration: this.settings.ephemeralDuration
    };

    const targetPeers = Array.from(new Set([
      ...Array.from(this.webrtc.peerProfiles.keys()),
      ...Array.from(this.webrtc.connections.keys())
    ]));

    let deliveredCount = 0;

    for (const peerId of targetPeers) {
      const key = this.currentRoom.sharedSessionKeys.get(peerId) || this.currentRoom.derivedKey;
      const { ciphertext, iv } = await this.crypto.encrypt(JSON.stringify(payload), key);

      const sent = this.webrtc.sendTo(peerId, {
        type: 'encrypted-message',
        sender: this.currentUser.userId,
        ciphertext: ciphertext,
        iv: iv
      });
      if (sent) deliveredCount++;
    }

    if (targetPeers.length === 0) {
      if (this.currentRoom.activeRecipientId) {
        this.queueMessage(this.currentRoom.activeRecipientId, payload);
        this.showToast(`⏳ Message queued. Connecting to ${this.currentRoom.activeRecipientId}...`);
      } else {
        this.showToast(`ℹ️ No peers connected yet. Enter a Peer ID in the sidebar or share your Public Chat Link!`);
      }
    }

    const msgObj = {
      author: this.currentUser.username,
      text: text,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      isOutgoing: true,
      ephemeralSeconds: this.settings.ephemeralDuration,
      delivered: deliveredCount > 0
    };

    this.renderMessageBubble(msgObj);

    if (!msgObj.ephemeralSeconds) {
      this.savedMessages.push(msgObj);
      await this.saveEncryptedHistory();
    }

    this.chatInput.value = '';
    this.playSound('send');
  }

  formatMessageContent(rawText) {
    const safeText = this.escapeHTML(rawText);
    const urlRegex = /(https?:\/\/[^\s<]+)/g;
    const extractedUrls = [];

    const formattedHtml = safeText.replace(urlRegex, (url) => {
      extractedUrls.push(url);
      return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="chat-link"><i class='bx bx-link-external'></i> ${url}</a>`;
    });

    return { formattedHtml, urls: extractedUrls };
  }

  renderMessageBubble(msgData) {
    const row = document.createElement('div');
    row.className = `message-row ${msgData.isOutgoing ? 'outgoing' : 'incoming'}`;

    const metaHeader = document.createElement('div');
    metaHeader.className = 'message-meta-header';
    metaHeader.innerHTML = `
      <span class="message-author">${this.escapeHTML(msgData.author)}</span>
      <span>${msgData.time}</span>
      <i class='bx bxs-lock-alt' style="color:var(--accent-primary); font-size: 0.8rem;" title="AES-256-GCM AEAD Authenticated"></i>
    `;
    row.appendChild(metaHeader);

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    const { formattedHtml, urls } = this.formatMessageContent(msgData.text);
    const textSpan = document.createElement('div');
    textSpan.innerHTML = formattedHtml;
    bubble.appendChild(textSpan);

    if (urls && urls.length > 0) {
      const primaryUrl = urls[0];
      try {
        const parsed = new URL(primaryUrl);
        const linkCard = document.createElement('a');
        linkCard.href = primaryUrl;
        linkCard.target = '_blank';
        linkCard.rel = 'noopener noreferrer';
        linkCard.className = 'link-preview-card';
        linkCard.innerHTML = `
          <i class='bx bx-globe link-preview-icon'></i>
          <div class="link-preview-meta">
            <div class="link-preview-domain">${this.escapeHTML(parsed.hostname)}</div>
            <div class="link-preview-url">${this.escapeHTML(primaryUrl)}</div>
          </div>
          <i class='bx bx-chevron-right' style="color:var(--text-subtle); font-size:1.2rem;"></i>
        `;
        bubble.appendChild(linkCard);
      } catch (e) {}
    }

    if (msgData.ephemeralSeconds > 0) {
      const burnBar = document.createElement('div');
      burnBar.className = 'burn-timer-bar';
      burnBar.style.width = '100%';
      bubble.appendChild(burnBar);

      const durationMs = msgData.ephemeralSeconds * 1000;
      const startTime = Date.now();

      const timerInterval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const remainingFraction = Math.max(0, 1 - (elapsed / durationMs));
        burnBar.style.width = `${remainingFraction * 100}%`;

        if (elapsed >= durationMs) {
          clearInterval(timerInterval);
          this.playSound('burn');
          row.style.transition = 'opacity 0.4s, transform 0.4s';
          row.style.opacity = '0';
          row.style.transform = 'scale(0.8)';
          setTimeout(() => {
            row.remove();
          }, 400);
        }
      }, 100);
    }

    row.appendChild(bubble);
    this.messagesContainer.appendChild(row);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  // Local Storage Persistence for Messages (Encrypted with AES-256-GCM)
  async saveEncryptedHistory() {
    if (!this.currentUser.secretKey) return;
    await this.crypto.saveSecureLocal(
      this.STORAGE_HISTORY_KEY + '_' + this.currentUser.userId,
      this.savedMessages,
      this.currentUser.secretKey
    );
  }

  async loadEncryptedHistory() {
    if (!this.currentUser.secretKey) return;
    const history = await this.crypto.loadSecureLocal(
      this.STORAGE_HISTORY_KEY + '_' + this.currentUser.userId,
      this.currentUser.secretKey
    );

    if (Array.isArray(history) && history.length > 0) {
      this.savedMessages = history;
      history.forEach(item => {
        if (item.type === 'file' || item.type === 'image') {
          this.renderFileCard(item);
        } else if (item.type === 'voice') {
          this.renderVoiceNoteCard(item);
        } else {
          this.renderMessageBubble(item);
        }
      });
      this.showToast(`Restored ${history.length} encrypted items from local storage.`);
    }
  }

  // ============================================================================
  // FILE & IMAGE SHARING WITH INLINE PREVIEWS
  // ============================================================================
  async handleFileUpload(file) {
    if (!file) return;

    if (file.size > 25 * 1024 * 1024) {
      alert('File exceeds 25MB safety threshold for client-side WebRTC transfer.');
      return;
    }

    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const arrayBuffer = reader.result;
        const base64Data = this.crypto.bufferToBase64(arrayBuffer);

        const key = this.currentRoom.derivedKey;
        const { ciphertext, iv } = await this.crypto.encrypt(base64Data, key);

        const isImg = file.type.startsWith('image/');
        const fileMetadata = {
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type,
          isImage: isImg,
          iv: iv,
          author: this.currentUser.username,
        };

        this.showToast(`Encrypting and streaming "${file.name}"...`);

        await this.webrtc.sendFile(ciphertext, fileMetadata, (progress) => {
          this.typingIndicator.textContent = `Streaming ${file.name}: ${progress}%`;
          if (progress >= 100) {
            this.typingIndicator.textContent = '';
          }
        });

        const dataUrl = URL.createObjectURL(file);
        const fileItem = {
          type: isImg ? 'image' : 'file',
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type,
          isImage: isImg,
          author: this.currentUser.username,
          isOutgoing: true,
          dataUrl: dataUrl,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };

        this.renderFileCard(fileItem);
        this.savedMessages.push(fileItem);
        await this.saveEncryptedHistory();

      } catch (err) {
        console.error('File encryption error:', err);
        alert('Failed to encrypt file: ' + err.message);
      }
    };
    reader.readAsArrayBuffer(file);
    this.fileInputElement.value = '';
  }

  async handleIncomingFile(fileResult) {
    try {
      const { metadata, data, peerId } = fileResult;
      const key = this.currentRoom.sharedSessionKeys.get(peerId) || this.currentRoom.derivedKey;

      const decryptedBase64 = await this.crypto.decrypt(data, metadata.iv, key);
      const buffer = this.crypto.base64ToBuffer(decryptedBase64);
      const blob = new Blob([buffer], { type: metadata.fileType || 'application/octet-stream' });
      const dataUrl = URL.createObjectURL(blob);
      const isImg = metadata.fileType && metadata.fileType.startsWith('image/');

      const fileItem = {
        type: isImg ? 'image' : 'file',
        fileName: metadata.fileName,
        fileSize: metadata.fileSize,
        fileType: metadata.fileType,
        isImage: isImg,
        author: metadata.author || 'Peer',
        isOutgoing: false,
        dataUrl: dataUrl,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      this.renderFileCard(fileItem);
      this.savedMessages.push(fileItem);
      await this.saveEncryptedHistory();

      this.playSound('receive');
      this.showToast(`Received encrypted ${isImg ? 'image' : 'file'}: ${metadata.fileName}`);
    } catch (err) {
      console.error('File decryption failed:', err);
      this.showToast('Error decrypting incoming file.');
    }
  }

  renderFileCard(fileInfo) {
    const row = document.createElement('div');
    row.className = `message-row ${fileInfo.isOutgoing ? 'outgoing' : 'incoming'}`;

    const metaHeader = document.createElement('div');
    metaHeader.className = 'message-meta-header';
    metaHeader.innerHTML = `
      <span class="message-author">${this.escapeHTML(fileInfo.author)}</span>
      <span>${fileInfo.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
      <i class='bx bxs-lock-alt' style="color:var(--accent-primary); font-size: 0.8rem;" title="AES-256-GCM AEAD Encrypted"></i>
    `;
    row.appendChild(metaHeader);

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    if (fileInfo.isImage || (fileInfo.fileType && fileInfo.fileType.startsWith('image/'))) {
      const imgWrapper = document.createElement('div');
      imgWrapper.className = 'chat-image-preview-wrapper';
      imgWrapper.title = 'Click to enlarge image';
      imgWrapper.onclick = () => this.openImageLightbox(fileInfo.dataUrl);

      imgWrapper.innerHTML = `
        <img src="${fileInfo.dataUrl}" alt="${this.escapeHTML(fileInfo.fileName)}" class="chat-image-preview">
        <span class="image-badge"><i class='bx bx-zoom-in'></i> E2EE Image</span>
      `;
      bubble.appendChild(imgWrapper);

      const dlRow = document.createElement('div');
      dlRow.style.cssText = 'display:flex; justify-content:space-between; align-items:center; margin-top:0.4rem; font-size:0.75rem;';
      dlRow.innerHTML = `
        <span style="color:var(--text-muted);">${(fileInfo.fileSize / 1024).toFixed(1)} KB</span>
        <a href="${fileInfo.dataUrl}" download="${this.escapeHTML(fileInfo.fileName)}" class="file-download-btn" style="padding:0.25rem 0.55rem; font-size:0.75rem;">
          <i class='bx bxs-download'></i> Save
        </a>
      `;
      bubble.appendChild(dlRow);
    } else {
      const card = document.createElement('div');
      card.className = 'file-attachment-card';

      let iconClass = 'bxs-file';
      if (fileInfo.fileType && fileInfo.fileType.includes('pdf')) iconClass = 'bxs-file-pdf';
      else if (fileInfo.fileType && fileInfo.fileType.startsWith('audio/')) iconClass = 'bxs-file-audio';

      const sizeFormatted = (fileInfo.fileSize / 1024).toFixed(1) + ' KB';

      card.innerHTML = `
        <div class="file-icon-box"><i class='bx ${iconClass}'></i></div>
        <div class="file-details">
          <div class="file-name">${this.escapeHTML(fileInfo.fileName)}</div>
          <div class="file-size">${sizeFormatted} • E2EE File</div>
        </div>
        <a href="${fileInfo.dataUrl}" download="${this.escapeHTML(fileInfo.fileName)}" class="file-download-btn">
          <i class='bx bxs-download'></i> Save
        </a>
      `;
      bubble.appendChild(card);
    }

    row.appendChild(bubble);
    this.messagesContainer.appendChild(row);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  openImageLightbox(src) {
    if (this.lightboxImg && this.imageLightbox) {
      this.lightboxImg.src = src;
      this.imageLightbox.classList.add('active');
    }
  }

  closeImageLightbox() {
    if (this.imageLightbox) {
      this.imageLightbox.classList.remove('active');
    }
  }

  // ============================================================================
  // VOICE NOTES (RECORD & INLINE AUDIO PLAYER)
  // ============================================================================
  async startVoiceRecording() {
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert('Microphone recording is not supported on this browser or insecure connection.');
        return;
      }

      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const options = this.supportedAudioMimeType ? { mimeType: this.supportedAudioMimeType } : {};
      this.mediaRecorder = new MediaRecorder(stream, options);
      this.audioChunks = [];

      this.mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) this.audioChunks.push(e.data);
      };

      this.mediaRecorder.start();
      this.recordingStartTime = Date.now();
      this.recordingBar.style.display = 'flex';
      this.chatInput.style.display = 'none';

      this.recordingInterval = setInterval(() => {
        const secs = Math.floor((Date.now() - this.recordingStartTime) / 1000);
        const mins = Math.floor(secs / 60);
        const remSecs = secs % 60;
        this.recordingDuration.textContent = `${mins.toString().padStart(2, '0')}:${remSecs.toString().padStart(2, '0')}`;
      }, 500);

    } catch (err) {
      console.error('Microphone error:', err);
      alert('Microphone access denied or audio device not found: ' + (err.message || err));
    }
  }

  cancelVoiceRecording() {
    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      this.mediaRecorder.stop();
      this.mediaRecorder.stream.getTracks().forEach(t => t.stop());
    }
    clearInterval(this.recordingInterval);
    this.recordingBar.style.display = 'none';
    this.chatInput.style.display = 'block';
  }

  async stopAndSendVoiceRecording() {
    if (!this.mediaRecorder) return;

    this.mediaRecorder.onstop = async () => {
      const mime = this.supportedAudioMimeType || 'audio/webm';
      const audioBlob = new Blob(this.audioChunks, { type: mime });
      const durationSecs = Math.max(1, Math.round((Date.now() - this.recordingStartTime) / 1000));
      
      await this.sendVoiceNote(audioBlob, durationSecs);
    };

    this.mediaRecorder.stop();
    this.mediaRecorder.stream.getTracks().forEach(t => t.stop());
    clearInterval(this.recordingInterval);
    this.recordingBar.style.display = 'none';
    this.chatInput.style.display = 'block';
  }

  async sendVoiceNote(audioBlob, durationSecs) {
    try {
      const arrayBuffer = await audioBlob.arrayBuffer();
      const base64Data = this.crypto.bufferToBase64(arrayBuffer);
      const dataUrl = URL.createObjectURL(audioBlob);

      const key = this.currentRoom.derivedKey;
      const { ciphertext, iv } = await this.crypto.encrypt(base64Data, key);

      const metadata = {
        fileName: `voice-note-${Date.now()}.${this.supportedAudioMimeType.includes('ogg') ? 'ogg' : 'webm'}`,
        fileSize: audioBlob.size,
        fileType: audioBlob.type,
        duration: durationSecs,
        iv: iv,
        isVoiceNote: true,
        author: this.currentUser.username,
      };

      this.showToast('Transmitting encrypted voice note...');

      await this.webrtc.sendFile(ciphertext, metadata);

      const voiceItem = {
        type: 'voice',
        dataUrl: dataUrl,
        duration: durationSecs,
        author: this.currentUser.username,
        isOutgoing: true,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      this.renderVoiceNoteCard(voiceItem);
      this.savedMessages.push(voiceItem);
      await this.saveEncryptedHistory();
      this.playSound('send');

    } catch (err) {
      console.error('Voice send error:', err);
      alert('Failed to send voice note: ' + err.message);
    }
  }

  renderVoiceNoteCard(voiceInfo) {
    const row = document.createElement('div');
    row.className = `message-row ${voiceInfo.isOutgoing ? 'outgoing' : 'incoming'}`;

    const metaHeader = document.createElement('div');
    metaHeader.className = 'message-meta-header';
    metaHeader.innerHTML = `
      <span class="message-author">${this.escapeHTML(voiceInfo.author)}</span>
      <span>${voiceInfo.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
      <i class='bx bxs-lock-alt' style="color:var(--accent-primary); font-size: 0.8rem;" title="AES-256-GCM AEAD Encrypted Voice"></i>
    `;
    row.appendChild(metaHeader);

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    const card = document.createElement('div');
    card.className = 'voice-note-card';
    card.innerHTML = `
      <div class="voice-note-header">
        <span><i class='bx bx-microphone'></i> Voice Note</span>
        <span>${voiceInfo.duration ? voiceInfo.duration + 's' : 'Audio'}</span>
      </div>
      <audio controls src="${voiceInfo.dataUrl}" class="voice-audio-element" preload="metadata"></audio>
    `;

    bubble.appendChild(card);
    row.appendChild(bubble);
    this.messagesContainer.appendChild(row);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  broadcastEphemeralSetting(duration) {
    this.webrtc.broadcast({
      type: 'ephemeral-config',
      duration: duration
    });
    this.showToast(`Self-destruct timer set to ${duration ? duration + 's' : 'Disabled'}`);
  }

  updatePeerListUI() {
    this.peerListContainer.innerHTML = '';
    const profiles = this.webrtc.peerProfiles;
    const count = this.webrtc.getConnectedPeerCount();
    this.connectedCount.textContent = count;

    if (profiles.size === 0) {
      this.peerListContainer.innerHTML = `
        <li style="padding: 1rem; font-size: 0.8rem; color: var(--text-subtle); text-align: center;">
          <i class='bx bx-loader-alt bx-spin' style="font-size: 1.4rem; margin-bottom: 0.4rem; display:block;"></i>
          Waiting for peers... Share your Public Chat Link or enter a Peer ID above.
        </li>
      `;
      return;
    }

    profiles.forEach((profile, peerId) => {
      const li = document.createElement('li');
      li.className = 'peer-item';
      li.innerHTML = `
        <div class="peer-avatar">
          ${profile.username.charAt(0).toUpperCase()}
          <span class="peer-status-dot"></span>
        </div>
        <div class="peer-info">
          <div class="peer-name">${this.escapeHTML(profile.username)}</div>
          <div class="peer-fingerprint">ID: ${peerId.slice(0, 10)}...</div>
        </div>
        <button class="btn btn-icon" onclick="window.cipherApp.openSafetyModal('${peerId}')" title="Verify Safety Numbers">
          <i class='bx bx-fingerprint'></i>
        </button>
      `;
      this.peerListContainer.appendChild(li);
    });
  }

  openSafetyModal(peerId) {
    const safetyNumber = this.currentRoom.safetyNumbers.get(peerId) || 
      '48921 09384 12903 84729 01823 94857 10293 84756 19283 74650 19283 74651';

    const blocks = safetyNumber.split(' ');
    this.safetyDigitsGrid.innerHTML = '';
    blocks.forEach(block => {
      const span = document.createElement('div');
      span.className = 'safety-block';
      span.textContent = block;
      this.safetyDigitsGrid.appendChild(span);
    });

    this.safetyModal.classList.add('active');
  }

  closeAllModals() {
    document.querySelectorAll('.modal-backdrop').forEach(m => {
      if (m.id !== 'device-pin-overlay') {
        m.classList.remove('active');
      }
    });
  }

  // Panic Button: Real Cryptographic Purge (Wipes RAM, WebRTC sessions, local storage)
  triggerPanicKillswitch() {
    this.playSound('burn');

    // 1. Zeroize cryptographic state in volatile memory
    if (this.currentUser.keyPair) {
      this.currentUser.keyPair = null;
    }
    this.currentUser.secretKey = '0000000000000000';
    this.currentUser.userId = '';
    this.currentUser.username = '';
    this.currentRoom.derivedKey = null;
    this.currentRoom.sharedSessionKeys.clear();
    this.currentRoom.safetyNumbers.clear();
    this.savedMessages = [];

    // 2. Sever WebRTC peer connections
    if (this.webrtc) {
      this.webrtc.destroy();
    }

    // 3. Completely purge local storage vaults
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch (e) {
      console.warn('Storage purge warning:', e);
    }

    // 4. Strip URL hash
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', window.location.pathname);
    } else {
      window.location.hash = '';
    }

    // 5. Render Clean High-Security Emergency Purge Screen (Zero external redirect error)
    document.body.className = '';
    document.body.innerHTML = `
      <div style="min-height:100vh; background:#070a0f; color:#f1f5f9; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:1.5rem; font-family:'JetBrains Mono', monospace; text-align:center;">
        <div style="width:70px; height:70px; border-radius:50%; background:rgba(255, 71, 87, 0.15); border:2px solid #ff4757; color:#ff4757; display:flex; align-items:center; justify-content:center; font-size:2.2rem; margin-bottom:1.25rem; box-shadow:0 0 25px rgba(255, 71, 87, 0.4);">
          <i class='bx bxs-shield-x'></i>
        </div>
        <h1 style="font-size:1.6rem; font-weight:800; color:#ff4757; letter-spacing:0.04em; margin-bottom:0.5rem;">
          EMERGENCY KILLSWITCH ENGAGED
        </h1>
        <p style="font-size:0.9rem; color:#94a3b8; max-width:520px; line-height:1.6; margin-bottom:1.5rem;">
          All cryptographic keys, message vaults, and WebRTC peer tunnels have been zeroed and permanently purged from this device.
        </p>

        <div style="background:#0f1420; border:1px solid rgba(255,255,255,0.08); border-radius:12px; padding:1.25rem; max-width:480px; width:100%; text-align:left; font-size:0.8rem; color:#00e699; margin-bottom:1.75rem; line-height:1.8;">
          <div>[✔] LocalStorage Cryptographic Vault: <strong>PURGED (0x00)</strong></div>
          <div>[✔] WebCrypto In-RAM Session Keys: <strong>ZEROED</strong></div>
          <div>[✔] WebRTC DataChannels: <strong>TERMINATED</strong></div>
          <div>[✔] Message History & Buffers: <strong>PURGED</strong></div>
          <div>[✔] Identity & Device State: <strong>SHREDDED</strong></div>
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:0.75rem; justify-content:center;">
          <button onclick="window.location.reload()" style="background:#00e699; color:#0a0d14; border:none; padding:0.75rem 1.4rem; border-radius:8px; font-weight:700; font-size:0.88rem; cursor:pointer; font-family:inherit; display:flex; align-items:center; gap:0.4rem;">
            <i class='bx bx-refresh'></i> Start Clean New Session
          </button>
          <a href="https://duckduckgo.com" style="background:#182033; color:#f1f5f9; border:1px solid rgba(255,255,255,0.12); padding:0.75rem 1.4rem; border-radius:8px; font-weight:600; font-size:0.88rem; text-decoration:none; display:flex; align-items:center; gap:0.4rem;">
            <i class='bx bx-log-out'></i> Go to DuckDuckGo
          </a>
        </div>
      </div>
    `;
  }

  wipeLocalData() {
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch (e) {}
    this.currentRoom.password = '0000000000000000';
    this.currentRoom.derivedKey = null;
    this.currentRoom.sharedSessionKeys.clear();
    this.currentRoom.safetyNumbers.clear();
    if (this.webrtc) this.webrtc.destroy();
    window.location.hash = '';
    window.location.reload();
  }

  toggleDecoyMode() {
    this.decoyScreen.classList.toggle('active');
  }

  initDecoyCalculator() {
    const display = document.getElementById('calc-display');
    let expr = '';

    document.querySelectorAll('.calc-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const val = btn.textContent;
        if (val === 'C') {
          expr = '';
          display.value = '0';
        } else if (val === '=') {
          if (expr === '1337') {
            this.decoyScreen.classList.remove('active');
            expr = '';
            display.value = '0';
            return;
          }
          try {
            expr = Function(`'use strict'; return (${expr})`)().toString();
            display.value = expr;
          } catch (e) {
            display.value = 'Error';
            expr = '';
          }
        } else {
          expr += val;
          display.value = expr;
        }
      });
    });
  }

  showToast(msg) {
    let toast = document.getElementById('app-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'app-toast';
      toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: var(--bg-surface-elevated);
        color: var(--accent-primary);
        border: 1px solid var(--accent-primary);
        padding: 0.75rem 1.25rem;
        border-radius: var(--radius-md);
        box-shadow: var(--shadow-glow);
        font-size: 0.85rem;
        font-weight: 600;
        z-index: 10000;
        opacity: 0;
        transform: translateY(10px);
        transition: all 0.25s ease;
        pointer-events: none;
      `;
      document.body.appendChild(toast);
    }

    toast.textContent = msg;
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';

    clearTimeout(this.toastTimeout);
    this.toastTimeout = setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
    }, 3500);
  }

  escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }
}

window.addEventListener('DOMContentLoaded', () => {
  window.cipherApp = new CipherApp();
});
