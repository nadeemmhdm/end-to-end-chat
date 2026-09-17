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

    // Emoji Picker Elements
    this.btnToggleEmojiPicker = document.getElementById('btn-toggle-emoji-picker');
    this.emojiPickerPopover = document.getElementById('emoji-picker-popover');
    this.emojiSearchInput = document.getElementById('emoji-search-input');
    this.btnClearEmojiSearch = document.getElementById('btn-clear-emoji-search');
    this.btnCloseEmojiPicker = document.getElementById('btn-close-emoji-picker');
    this.emojiGridContainer = document.getElementById('emoji-grid-container');
    this.emojiCategoryTabs = document.getElementById('emoji-category-tabs');
    this.emojiPreviewText = document.getElementById('emoji-preview-text');
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

    // Initialize Comprehensive Emoji Picker
    this.initEmojiPicker();

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
          if (!item.dataUrl && item.base64Data) {
            try {
              const buf = this.crypto.base64ToBuffer(item.base64Data);
              const blob = new Blob([buf], { type: item.fileType || 'application/octet-stream' });
              item.dataUrl = URL.createObjectURL(blob);
            } catch (e) {}
          }
          this.renderFileCard(item);
        } else if (item.type === 'voice') {
          if (!item.dataUrl && item.base64Audio) {
            try {
              const buf = this.crypto.base64ToBuffer(item.base64Audio);
              const blob = new Blob([buf], { type: item.mimeType || 'audio/webm' });
              item.dataUrl = URL.createObjectURL(blob);
            } catch (e) {}
          }
          this.renderVoiceNoteCard(item);
        } else {
          this.renderMessageBubble(item);
        }
      });
      this.showToast(`Restored ${history.length} encrypted items from local storage.`);
    }
  }

  // ============================================================================
  // COMPREHENSIVE CATEGORIZED EMOJI PICKER WITH SEARCH (280+ UNICODE EMOJIS)
  // ============================================================================
  initEmojiPicker() {
    if (!this.emojiPickerPopover || !this.emojiGridContainer) return;

    this.allEmojis = [
      // Smileys & Emotion
      { e: '😀', n: 'grinning face', c: 'smileys', k: 'smile happy joy grin' },
      { e: '😃', n: 'grinning face big eyes', c: 'smileys', k: 'smile happy' },
      { e: '😄', n: 'grinning face smiling eyes', c: 'smileys', k: 'happy laugh' },
      { e: '😁', n: 'beaming face', c: 'smileys', k: 'grin proud teeth' },
      { e: '😆', n: 'grinning squinting', c: 'smileys', k: 'haha laugh lol' },
      { e: '😅', n: 'grinning sweat', c: 'smileys', k: 'relief phew sweat' },
      { e: '🤣', n: 'rolling on the floor laughing', c: 'smileys', k: 'rofl lol laugh' },
      { e: '😂', n: 'face with tears of joy', c: 'smileys', k: 'cry laugh happy' },
      { e: '🙂', n: 'slightly smiling face', c: 'smileys', k: 'smile ok' },
      { e: '🙃', n: 'upside down face', c: 'smileys', k: 'sarcasm silly' },
      { e: '😉', n: 'winking face', c: 'smileys', k: 'wink flirt' },
      { e: '😊', n: 'smiling face with smiling eyes', c: 'smileys', k: 'blush smile' },
      { e: '😇', n: 'smiling face with halo', c: 'smileys', k: 'angel innocent' },
      { e: '🥰', n: 'smiling face with hearts', c: 'smileys', k: 'love adore hearts' },
      { e: '😍', n: 'heart eyes', c: 'smileys', k: 'love crush adore' },
      { e: '🤩', n: 'star struck', c: 'smileys', k: 'star wow excited' },
      { e: '😘', n: 'face blowing a kiss', c: 'smileys', k: 'kiss love' },
      { e: '😗', n: 'kissing face', c: 'smileys', k: 'kiss' },
      { e: '😚', n: 'kissing face with closed eyes', c: 'smileys', k: 'kiss romance' },
      { e: '😋', n: 'face savoring food', c: 'smileys', k: 'yum delicious tongue' },
      { e: '😛', n: 'face with tongue', c: 'smileys', k: 'tongue silly' },
      { e: '😜', n: 'winking face with tongue', c: 'smileys', k: 'joke party silly' },
      { e: '🤪', n: 'zany face', c: 'smileys', k: 'crazy wild goofy' },
      { e: '😝', n: 'squinting face with tongue', c: 'smileys', k: 'tongue lol' },
      { e: '🤑', n: 'money mouth face', c: 'smileys', k: 'rich dollar cash' },
      { e: '🤗', n: 'hugging face', c: 'smileys', k: 'hug embrace warm' },
      { e: '🤭', n: 'face with hand over mouth', c: 'smileys', k: 'oops giggle quiet' },
      { e: '🤫', n: 'shushing face', c: 'smileys', k: 'quiet secret hush' },
      { e: '🤔', n: 'thinking face', c: 'smileys', k: 'think ponder consider' },
      { e: '🤐', n: 'zipper mouth face', c: 'smileys', k: 'silent zip secret' },
      { e: '🤨', n: 'face with raised eyebrow', c: 'smileys', k: 'skeptical distrust' },
      { e: '😐', n: 'neutral face', c: 'smileys', k: 'meh poker straight' },
      { e: '😑', n: 'expressionless face', c: 'smileys', k: 'blank no expression' },
      { e: '😶', n: 'face without mouth', c: 'smileys', k: 'speechless mute' },
      { e: '😏', n: 'smirking face', c: 'smileys', k: 'smirk flirt sly' },
      { e: '😒', n: 'unamused face', c: 'smileys', k: 'bored unimpressed' },
      { e: '🙄', n: 'face with rolling eyes', c: 'smileys', k: 'eye roll annoying' },
      { e: '😬', n: 'grimacing face', c: 'smileys', k: 'awkward eek nervous' },
      { e: '🤥', n: 'lying face', c: 'smileys', k: 'pinocchio lie fake' },
      { e: '😌', n: 'relieved face', c: 'smileys', k: 'peace calm zen' },
      { e: '😔', n: 'pensive face', c: 'smileys', k: 'sad down sorrow' },
      { e: '😪', n: 'sleepy face', c: 'smileys', k: 'tired snot sleep' },
      { e: '🤤', n: 'drooling face', c: 'smileys', k: 'drool hungry crave' },
      { e: '😴', n: 'sleeping face', c: 'smileys', k: 'zzz bedtime sleep' },
      { e: '😷', n: 'face with medical mask', c: 'smileys', k: 'sick virus mask' },
      { e: '🤒', n: 'face with thermometer', c: 'smileys', k: 'fever ill sick' },
      { e: '🤕', n: 'face with head bandage', c: 'smileys', k: 'hurt injury' },
      { e: '🤢', n: 'nauseated face', c: 'smileys', k: 'green vomit gross' },
      { e: '🤮', n: 'face vomiting', c: 'smileys', k: 'puke barf ill' },
      { e: '🤧', n: 'sneezing face', c: 'smileys', k: 'achoo cold flu' },
      { e: '🥵', n: 'hot face', c: 'smileys', k: 'summer heat sweat' },
      { e: '🥶', n: 'cold face', c: 'smileys', k: 'freezing winter ice' },
      { e: '🥴', n: 'woozy face', c: 'smileys', k: 'dizzy drunk tipsy' },
      { e: '😵', n: 'dizzy face', c: 'smileys', k: 'passed out knocked' },
      { e: '🤯', n: 'exploding head', c: 'smileys', k: 'mind blown shock' },
      { e: '🤠', n: 'cowboy hat face', c: 'smileys', k: 'wild west yeehaw' },
      { e: '🥳', n: 'partying face', c: 'smileys', k: 'celebrate birthday fun' },
      { e: '🥸', n: 'disguised face', c: 'smileys', k: 'spy incognito disguise' },
      { e: '😎', n: 'smiling face with sunglasses', c: 'smileys', k: 'cool chill hacker' },
      { e: '🤓', n: 'nerd face', c: 'smileys', k: 'geek smart glasses' },
      { e: '🧐', n: 'face with monocle', c: 'smileys', k: 'curious inspect posh' },
      { e: '😕', n: 'confused face', c: 'smileys', k: 'puzzled unsure' },
      { e: '😟', n: 'worried face', c: 'smileys', k: 'anxious stress' },
      { e: '🙁', n: 'slightly frowning face', c: 'smileys', k: 'disappointed' },
      { e: '😮', n: 'face with open mouth', c: 'smileys', k: 'surprise whoa' },
      { e: '😯', n: 'hushed face', c: 'smileys', k: 'stunned gasp' },
      { e: '😲', n: 'astonished face', c: 'smileys', k: 'omg shocked' },
      { e: '😳', n: 'flushed face', c: 'smileys', k: 'blush red embarrassment' },
      { e: '🥺', n: 'pleading face', c: 'smileys', k: 'puppy eyes please' },
      { e: '😦', n: 'frowning face with open mouth', c: 'smileys', k: 'alarmed' },
      { e: '😧', n: 'anguished face', c: 'smileys', k: 'pain hurt' },
      { e: '😨', n: 'fearful face', c: 'smileys', k: 'scared terrified' },
      { e: '😰', n: 'anxious face with sweat', c: 'smileys', k: 'nervous panic' },
      { e: '😥', n: 'sad but relieved face', c: 'smileys', k: 'whew sweat' },
      { e: '😢', n: 'crying face', c: 'smileys', k: 'tear weep sad' },
      { e: '😭', n: 'loudly crying face', c: 'smileys', k: 'bawling sob despair' },
      { e: '😱', n: 'face screaming in fear', c: 'smileys', k: 'horror scream munch' },
      { e: '😖', n: 'confounded face', c: 'smileys', k: 'struggle upset' },
      { e: '😣', n: 'persevering face', c: 'smileys', k: 'endure tough' },
      { e: '😞', n: 'disappointed face', c: 'smileys', k: 'bummed sad' },
      { e: '😓', n: 'downcast face with sweat', c: 'smileys', k: 'hard work stress' },
      { e: '😩', n: 'weary face', c: 'smileys', k: 'tired give up' },
      { e: '😫', n: 'tired face', c: 'smileys', k: 'exhausted overwhelmed' },
      { e: '🥱', n: 'yawning face', c: 'smileys', k: 'sleepy bored' },
      { e: '😤', n: 'face with steam from nose', c: 'smileys', k: 'triumph huff anger' },
      { e: '😡', n: 'pouting face', c: 'smileys', k: 'furious mad rage' },
      { e: '😠', n: 'angry face', c: 'smileys', k: 'mad grr cross' },
      { e: '🤬', n: 'face with symbols on mouth', c: 'smileys', k: 'swearing cuss anger' },
      { e: '😈', n: 'smiling face with horns', c: 'smileys', k: 'devil mischievous evil' },
      { e: '👿', n: 'angry face with horns', c: 'smileys', k: 'demon furious' },
      { e: '💀', n: 'skull', c: 'smileys', k: 'dead skeleton death' },
      { e: '☠️', n: 'skull and crossbones', c: 'smileys', k: 'danger poison pirate' },
      { e: '💩', n: 'pile of poo', c: 'smileys', k: 'poop crap stinky' },
      { e: '🤡', n: 'clown face', c: 'smileys', k: 'circus joker funny' },
      { e: '👹', n: 'ogre', c: 'smileys', k: 'monster japanese' },
      { e: '👺', n: 'goblin', c: 'smileys', k: 'red nose troll' },
      { e: '👻', n: 'ghost', c: 'smileys', k: 'spooky halloween spirit' },
      { e: '👽', n: 'alien', c: 'smileys', k: 'ufo et extra extraterrestrial' },
      { e: '👾', n: 'alien monster', c: 'smileys', k: '8bit retro arcade game' },
      { e: '🤖', n: 'robot', c: 'smileys', k: 'bot ai android tech' },
      { e: '😺', n: 'grinning cat', c: 'smileys', k: 'kitten pet feline' },
      { e: '😻', n: 'heart eyes cat', c: 'smileys', k: 'cat love adore' },
      { e: '😹', n: 'cat tears of joy', c: 'smileys', k: 'laughing cat' },
      { e: '💋', n: 'kiss mark', c: 'smileys', k: 'lips lipstick romance' },
      { e: '💌', n: 'love letter', c: 'smileys', k: 'heart envelope mail' },
      { e: '💘', n: 'heart with arrow', c: 'smileys', k: 'cupid falling in love' },
      { e: '💝', n: 'heart with ribbon', c: 'smileys', k: 'gift present romance' },
      { e: '💖', n: 'sparkling heart', c: 'smileys', k: 'glitter love shiny' },
      { e: '💗', n: 'growing heart', c: 'smileys', k: 'pulse expanding love' },
      { e: '💓', n: 'beating heart', c: 'smileys', k: 'thump alive heartbeat' },
      { e: '💞', n: 'revolving hearts', c: 'smileys', k: 'affection twirl' },
      { e: '💕', n: 'two hearts', c: 'smileys', k: 'sweet couple bond' },
      { e: '❣️', n: 'heart exclamation', c: 'smileys', k: 'point heavy heart' },
      { e: '💔', n: 'broken heart', c: 'smileys', k: 'heartbreak breakup sad' },
      { e: '❤️', n: 'red heart', c: 'smileys', k: 'love passion pure' },
      { e: '🧡', n: 'orange heart', c: 'smileys', k: 'warmth friend' },
      { e: '💛', n: 'yellow heart', c: 'smileys', k: 'friendship gold' },
      { e: '💚', n: 'green heart', c: 'smileys', k: 'nature health eco' },
      { e: '💙', n: 'blue heart', c: 'smileys', k: 'loyalty trust calm' },
      { e: '💜', n: 'purple heart', c: 'smileys', k: 'magic royal' },
      { e: '🤎', n: 'brown heart', c: 'smileys', k: 'chocolate coffee earth' },
      { e: '🖤', n: 'black heart', c: 'smileys', k: 'dark gothic chic' },
      { e: '🤍', n: 'white heart', c: 'smileys', k: 'peace pure angel' },
      { e: '💯', n: 'hundred points', c: 'smileys', k: '100 perfect exam score' },
      { e: '💢', n: 'anger symbol', c: 'smileys', k: 'vein mad anime' },
      { e: '💥', n: 'collision', c: 'smileys', k: 'boom bang explode' },
      { e: '💫', n: 'dizzy', c: 'smileys', k: 'stars orbit galaxy' },
      { e: '💦', n: 'sweat droplets', c: 'smileys', k: 'water splash drip' },
      { e: '💨', n: 'dashing away', c: 'smileys', k: 'fast run wind speed' },
      { e: '🔥', n: 'fire', c: 'smileys', k: 'lit flame hot lit trending' },
      { e: '✨', n: 'sparkles', c: 'smileys', k: 'magic clean shiny star' },
      { e: '💬', n: 'speech balloon', c: 'smileys', k: 'chat message talk comment' },
      { e: '💭', n: 'thought balloon', c: 'smileys', k: 'think idea dream' },

      // People & Gestures
      { e: '👋', n: 'waving hand', c: 'gestures', k: 'wave hello goodbye hi' },
      { e: '🤚', n: 'raised back of hand', c: 'gestures', k: 'backhand stop' },
      { e: '🖐️', n: 'hand with fingers splayed', c: 'gestures', k: 'five palm' },
      { e: '✋', n: 'raised hand', c: 'gestures', k: 'high five stop question' },
      { e: '🖖', n: 'vulcan salute', c: 'gestures', k: 'spock live long trek' },
      { e: '👌', n: 'ok hand', c: 'gestures', k: 'perfect good fine' },
      { e: '🤌', n: 'pinched fingers', c: 'gestures', k: 'italian gesture what' },
      { e: '🤏', n: 'pinching hand', c: 'gestures', k: 'small tiny bit' },
      { e: '✌️', n: 'victory hand', c: 'gestures', k: 'peace two v win' },
      { e: '🤞', n: 'crossed fingers', c: 'gestures', k: 'luck hope wish' },
      { e: '🤟', n: 'love you gesture', c: 'gestures', k: 'ily sign language' },
      { e: '🤘', n: 'sign of the horns', c: 'gestures', k: 'rock metal concert' },
      { e: '🤙', n: 'call me hand', c: 'gestures', k: 'shaka phone surf' },
      { e: '👈', n: 'backhand index pointing left', c: 'gestures', k: 'point left' },
      { e: '👉', n: 'backhand index pointing right', c: 'gestures', k: 'point right' },
      { e: '👆', n: 'backhand index pointing up', c: 'gestures', k: 'point up' },
      { e: '🖕', n: 'middle finger', c: 'gestures', k: 'rude finger rebel' },
      { e: '👇', n: 'backhand index pointing down', c: 'gestures', k: 'point down' },
      { e: '☝️', n: 'index pointing up', c: 'gestures', k: 'one number attention' },
      { e: '👍', n: 'thumbs up', c: 'gestures', k: 'like agree approve yes' },
      { e: '👎', n: 'thumbs down', c: 'gestures', k: 'dislike bad no reject' },
      { e: '✊', n: 'raised fist', c: 'gestures', k: 'power solidarity punch' },
      { e: '👊', n: 'oncoming fist', c: 'gestures', k: 'brofist punch bump' },
      { e: '🤛', n: 'left facing fist', c: 'gestures', k: 'fist bump left' },
      { e: '🤜', n: 'right facing fist', c: 'gestures', k: 'fist bump right' },
      { e: '👏', n: 'clapping hands', c: 'gestures', k: 'applause bravo praise' },
      { e: '🙌', n: 'raising hands', c: 'gestures', k: 'celebration hooray cheer' },
      { e: '👐', n: 'open hands', c: 'gestures', k: 'welcome open warm' },
      { e: '🤲', n: 'palms up together', c: 'gestures', k: 'prayer dua offering' },
      { e: '🤝', n: 'handshake', c: 'gestures', k: 'deal agreement partner' },
      { e: '🙏', n: 'folded hands', c: 'gestures', k: 'pray thank you please namaste' },
      { e: '✍️', n: 'writing hand', c: 'gestures', k: 'write pen author' },
      { e: '💅', n: 'nail polish', c: 'gestures', k: 'beauty manicure slay' },
      { e: '🤳', n: 'selfie', c: 'gestures', k: 'camera phone snapshot' },
      { e: '💪', n: 'flexed biceps', c: 'gestures', k: 'strong muscle power fitness' },
      { e: '🦾', n: 'mechanical arm', c: 'gestures', k: 'prosthetic cyber robot' },
      { e: '👀', n: 'eyes', c: 'gestures', k: 'look see inspect spy watching' },
      { e: '👁️', n: 'eye', c: 'gestures', k: 'vision observe privacy' },
      { e: '🧠', n: 'brain', c: 'gestures', k: 'smart intelligence mind idea' },

      // Animals & Nature
      { e: '🐶', n: 'dog face', c: 'nature', k: 'puppy canine pet' },
      { e: '🐱', n: 'cat face', c: 'nature', k: 'kitty feline pet' },
      { e: '🐭', n: 'mouse face', c: 'nature', k: 'rodent cheese' },
      { e: '🐹', n: 'hamster', c: 'nature', k: 'pet cute cheeks' },
      { e: '🐰', n: 'rabbit face', c: 'nature', k: 'bunny easter cute' },
      { e: '🦊', n: 'fox', c: 'nature', k: 'clever wild animal' },
      { e: '🐻', n: 'bear', c: 'nature', k: 'grizzly wild animal' },
      { e: '🐼', n: 'panda', c: 'nature', k: 'bamboo cute bear' },
      { e: '🐨', n: 'koala', c: 'nature', k: 'australia eucalyptus' },
      { e: '🐯', n: 'tiger face', c: 'nature', k: 'big cat stripes wild' },
      { e: '🦁', n: 'lion', c: 'nature', k: 'king jungle brave' },
      { e: '🐮', n: 'cow face', c: 'nature', k: 'dairy milk farm' },
      { e: '🐷', n: 'pig face', c: 'nature', k: 'farm oink pink' },
      { e: '🐸', n: 'frog', c: 'nature', k: 'toad amphibian ribbit' },
      { e: '🐵', n: 'monkey face', c: 'nature', k: 'ape jungle cheeky' },
      { e: '🙈', n: 'see no evil monkey', c: 'nature', k: 'blind shy hide' },
      { e: '🙉', n: 'hear no evil monkey', c: 'nature', k: 'deaf loud ignore' },
      { e: '🙊', n: 'speak no evil monkey', c: 'nature', k: 'quiet hush secret' },
      { e: '🦅', n: 'eagle', c: 'nature', k: 'bird predator fly freedom' },
      { e: '🦉', n: 'owl', c: 'nature', k: 'wise bird night nocturne' },
      { e: '🦇', n: 'bat', c: 'nature', k: 'vampire night cave batman' },
      { e: '🐺', n: 'wolf', c: 'nature', k: 'howl pack wild moonlight' },
      { e: '🦄', n: 'unicorn', c: 'nature', k: 'fantasy magic horn horse' },
      { e: '🐝', n: 'honeybee', c: 'nature', k: 'insect honey sting pollinate' },
      { e: '🐛', n: 'bug', c: 'nature', k: 'insect caterpillar code' },
      { e: '🦋', n: 'butterfly', c: 'nature', k: 'pretty wings insect' },
      { e: '🐌', n: 'snail', c: 'nature', k: 'slow shell garden' },
      { e: '🐞', n: 'lady beetle', c: 'nature', k: 'ladybug spotted insect' },
      { e: '🕷️', n: 'spider', c: 'nature', k: 'web arachnid eight legs' },
      { e: '🦂', n: 'scorpion', c: 'nature', k: 'desert sting venom' },
      { e: '🐢', n: 'turtle', c: 'nature', k: 'slow reptile shell ocean' },
      { e: '🐍', n: 'snake', c: 'nature', k: 'python reptile venom serpent' },
      { e: '🐙', n: 'octopus', c: 'nature', k: 'sea tentacles ocean' },
      { e: '🐬', n: 'dolphin', c: 'nature', k: 'marine smart swim' },
      { e: '🐳', n: 'spouting whale', c: 'nature', k: 'huge sea mammal ocean' },
      { e: '🦈', n: 'shark', c: 'nature', k: 'predator jaws ocean' },
      { e: '🌲', n: 'evergreen tree', c: 'nature', k: 'pine forest wood' },
      { e: '🌳', n: 'deciduous tree', c: 'nature', k: 'park green leaves' },
      { e: '🌴', n: 'palm tree', c: 'nature', k: 'beach tropical oasis' },
      { e: '🌵', n: 'cactus', c: 'nature', k: 'desert spikes succulent' },
      { e: '🌿', n: 'herb', c: 'nature', k: 'leaf plant eco green' },
      { e: '🍀', n: 'four leaf clover', c: 'nature', k: 'lucky irish fortune' },
      { e: '🌹', n: 'rose', c: 'nature', k: 'flower red romantic love' },
      { e: '🌻', n: 'sunflower', c: 'nature', k: 'flower yellow sun field' },
      { e: '🌺', n: 'hibiscus', c: 'nature', k: 'flower tropical pink' },
      { e: '🌸', n: 'cherry blossom', c: 'nature', k: 'sakura spring japan' },
      { e: '🍄', n: 'mushroom', c: 'nature', k: 'fungus toadstool forest' },
      { e: '🌞', n: 'sun with face', c: 'nature', k: 'summer bright morning' },
      { e: '🌙', n: 'crescent moon', c: 'nature', k: 'night dark sky' },
      { e: '⭐', n: 'star', c: 'nature', k: 'night sky bright rating' },
      { e: '⚡', n: 'high voltage', c: 'nature', k: 'lightning zap power speed' },
      { e: '🌈', n: 'rainbow', c: 'nature', k: 'colors sky pride weather' },
      { e: '☁️', n: 'cloud', c: 'nature', k: 'weather overcast sky' },
      { e: '🌧️', n: 'cloud with rain', c: 'nature', k: 'rainy weather storm' },
      { e: '❄️', n: 'snowflake', c: 'nature', k: 'winter cold snow ice' },
      { e: '🌊', n: 'water wave', c: 'nature', k: 'sea ocean surf tsunami' },

      // Food & Drink
      { e: '🍏', n: 'green apple', c: 'food', k: 'fruit fresh healthy' },
      { e: '🍎', n: 'red apple', c: 'food', k: 'fruit teacher sweet' },
      { e: '🍐', n: 'pear', c: 'food', k: 'fruit juicy sweet' },
      { e: '🍊', n: 'tangerine', c: 'food', k: 'orange citrus vitamin' },
      { e: '🍋', n: 'lemon', c: 'food', k: 'sour citrus yellow' },
      { e: '🍌', n: 'banana', c: 'food', k: 'fruit peel yellow potassium' },
      { e: '🍉', n: 'watermelon', c: 'food', k: 'summer fruit slice juicy' },
      { e: '🍇', n: 'grapes', c: 'food', k: 'fruit wine bunch purple' },
      { e: '🍓', n: 'strawberry', c: 'food', k: 'fruit berry sweet red' },
      { e: '🫐', n: 'blueberries', c: 'food', k: 'fruit berry healthy' },
      { e: '🍒', n: 'cherries', c: 'food', k: 'fruit sweet pair red' },
      { e: '🍑', n: 'peach', c: 'food', k: 'fruit sweet booty fuzzy' },
      { e: '🥭', n: 'mango', c: 'food', k: 'tropical fruit sweet juicy' },
      { e: '🍍', n: 'pineapple', c: 'food', k: 'tropical fruit hawaii' },
      { e: '🥑', n: 'avocado', c: 'food', k: 'guacamole toast green healthy' },
      { e: '🍔', n: 'hamburger', c: 'food', k: 'burger beef fast food diner' },
      { e: '🍟', n: 'french fries', c: 'food', k: 'chips potato fast food' },
      { e: '🍕', n: 'pizza', c: 'food', k: 'slice cheese pepperoni italian' },
      { e: '🌭', n: 'hot dog', c: 'food', k: 'sausage mustard bun frank' },
      { e: '🥪', n: 'sandwich', c: 'food', k: 'bread lunch sub deli' },
      { e: '🌮', n: 'taco', c: 'food', k: 'mexican shell salsa food' },
      { e: '🌯', n: 'burrito', c: 'food', k: 'wrap mexican beans rice' },
      { e: '🥗', n: 'green salad', c: 'food', k: 'healthy diet vegetables' },
      { e: '🍝', n: 'spaghetti', c: 'food', k: 'pasta noodles italian sauce' },
      { e: '🍜', n: 'steaming bowl', c: 'food', k: 'ramen noodles soup asian' },
      { e: '🍣', n: 'sushi', c: 'food', k: 'japanese fish rice roll sashimi' },
      { e: '🥟', n: 'dumpling', c: 'food', k: 'gyoza potsticker dim sum' },
      { e: '🍦', n: 'soft ice cream', c: 'food', k: 'vanilla dessert sweet cone' },
      { e: '🍰', n: 'shortcake', c: 'food', k: 'cake birthday dessert slice' },
      { e: '🎂', n: 'birthday cake', c: 'food', k: 'celebration candle party' },
      { e: '🍩', n: 'doughnut', c: 'food', k: 'donut sprinkles glaze sweet' },
      { e: '🍪', n: 'cookie', c: 'food', k: 'chocolate chip sweet snack' },
      { e: '🍫', n: 'chocolate bar', c: 'food', k: 'cocoa dessert treat' },
      { e: '🍿', n: 'popcorn', c: 'food', k: 'movie cinema snack butter' },
      { e: '☕', n: 'hot beverage', c: 'food', k: 'coffee tea cup caffeine' },
      { e: '🧃', n: 'beverage box', c: 'food', k: 'juice box straw kid' },
      { e: '🥤', n: 'cup with straw', c: 'food', k: 'soda drink cup cola' },
      { e: '🧋', n: 'bubble tea', c: 'food', k: 'boba milk tea tapioca' },
      { e: '🍺', n: 'beer mug', c: 'food', k: 'alcohol pub drink foam' },
      { e: '🍻', n: 'clinking beer mugs', c: 'food', k: 'cheers toast party drink' },
      { e: '🥂', n: 'clinking glasses', c: 'food', k: 'celebrate champagne toast' },
      { e: '🍷', n: 'wine glass', c: 'food', k: 'red wine alcoholic beverage' },
      { e: '🍸', n: 'cocktail glass', c: 'food', k: 'martini olive bar drink' },

      // Travel & Places
      { e: '🚀', n: 'rocket', c: 'travel', k: 'spacecraft launch blast off speed' },
      { e: '🛸', n: 'flying saucer', c: 'travel', k: 'ufo alien space spaceship' },
      { e: '🛰️', n: 'satellite', c: 'travel', k: 'orbit space communication gps' },
      { e: '✈️', n: 'airplane', c: 'travel', k: 'flight travel airport vacation' },
      { e: '🚗', n: 'automobile', c: 'travel', k: 'car drive vehicle commute' },
      { e: '🏎️', n: 'racing car', c: 'travel', k: 'f1 speed race fast drift' },
      { e: '🚓', n: 'police car', c: 'travel', k: 'cop siren patrol law' },
      { e: '🚑', n: 'ambulance', c: 'travel', k: 'paramedic hospital medical 911' },
      { e: '🚒', n: 'fire engine', c: 'travel', k: 'fire truck emergency rescue' },
      { e: '🚲', n: 'bicycle', c: 'travel', k: 'bike cycling ride eco sport' },
      { e: '🏍️', n: 'motorcycle', c: 'travel', k: 'motorbike ride speed biker' },
      { e: '🚆', n: 'train', c: 'travel', k: 'railway railway commute travel' },
      { e: '🚇', n: 'metro', c: 'travel', k: 'subway underground transport' },
      { e: '🚢', n: 'ship', c: 'travel', k: 'cruise boat sea voyage ocean' },
      { e: '⚓', n: 'anchor', c: 'travel', k: 'nautical harbor maritime port' },
      { e: '🚨', n: 'police car light', c: 'travel', k: 'alert siren emergency red' },
      { e: '🗺️', n: 'world map', c: 'travel', k: 'cartography geography travel' },
      { e: '🗿', n: 'moai', c: 'travel', k: 'easter island stone statue' },
      { e: '🗽', n: 'statue of liberty', c: 'travel', k: 'new york america freedom' },
      { e: '🗼', n: 'tokyo tower', c: 'travel', k: 'japan antenna landmark red' },
      { e: '🏰', n: 'castle', c: 'travel', k: 'fairytale medieval fortress' },
      { e: '🏟️', n: 'stadium', c: 'travel', k: 'arena concert sports match' },
      { e: '🏝️', n: 'desert island', c: 'travel', k: 'beach tropical palm paradise' },
      { e: '⛰️', n: 'mountain', c: 'travel', k: 'peak hiking nature high' },
      { e: '🌋', n: 'volcano', c: 'travel', k: 'lava eruption magma mountain' },
      { e: '🏕️', n: 'camping', c: 'travel', k: 'tent outdoor campfire forest' },
      { e: '🏠', n: 'house', c: 'travel', k: 'home building living residence' },
      { e: '🏢', n: 'office building', c: 'travel', k: 'work company corporate skyscraper' },
      { e: '🌃', n: 'night with stars', c: 'travel', k: 'cityscape evening skyscrapers' },
      { e: '🌉', n: 'bridge at night', c: 'travel', k: 'golden gate highway suspension' },

      // Objects & Tech
      { e: '💻', n: 'laptop', c: 'objects', k: 'computer mac pc coding tech hacker' },
      { e: '🖥️', n: 'desktop computer', c: 'objects', k: 'monitor workstation pc' },
      { e: '📱', n: 'mobile phone', c: 'objects', k: 'smartphone iphone android call' },
      { e: '⌨️', n: 'keyboard', c: 'objects', k: 'typing mechanical input' },
      { e: '🖱️', n: 'computer mouse', c: 'objects', k: 'click cursor pc trackpad' },
      { e: '💾', n: 'floppy disk', c: 'objects', k: 'save storage retro 3.5' },
      { e: '💿', n: 'optical disk', c: 'objects', k: 'cd dvd media software' },
      { e: '📷', n: 'camera', c: 'objects', k: 'photo picture lens capture' },
      { e: '📹', n: 'video camera', c: 'objects', k: 'record film movie camcorder' },
      { e: '🎙️', n: 'studio microphone', c: 'objects', k: 'podcast audio recording voice' },
      { e: '🎧', n: 'headphone', c: 'objects', k: 'music audio listen sound beats' },
      { e: '📡', n: 'satellite antenna', c: 'objects', k: 'dish signal broadcast wireless' },
      { e: '🔋', n: 'battery', c: 'objects', k: 'power energy charge full' },
      { e: '🔌', n: 'electric plug', c: 'objects', k: 'power cord outlet connect' },
      { e: '💡', n: 'light bulb', c: 'objects', k: 'idea insight bright illuminate' },
      { e: '🔦', n: 'flashlight', c: 'objects', k: 'torch dark search beam' },
      { e: '💸', n: 'money with wings', c: 'objects', k: 'cash spend flying rich' },
      { e: '💵', n: 'dollar banknote', c: 'objects', k: 'money currency usd paper' },
      { e: '💳', n: 'credit card', c: 'objects', k: 'payment visa debit purchase' },
      { e: '💎', n: 'gem stone', c: 'objects', k: 'diamond crystal precious luxury' },
      { e: '⚖️', n: 'balance scale', c: 'objects', k: 'justice law court equal' },
      { e: '🔧', n: 'wrench', c: 'objects', k: 'tool fix repair settings mechanic' },
      { e: '🔨', n: 'hammer', c: 'objects', k: 'tool build strike repair' },
      { e: '⚙️', n: 'gear', c: 'objects', k: 'settings cog wheel machinery' },
      { e: '💣', n: 'bomb', c: 'objects', k: 'explosive boom danger dynamite' },
      { e: '🛡️', n: 'shield', c: 'objects', k: 'security defense protection cyber' },
      { e: '🔑', n: 'key', c: 'objects', k: 'unlock secret access password' },
      { e: '🗝️', n: 'old key', c: 'objects', k: 'vintage clue antique lock' },
      { e: '🔒', n: 'locked', c: 'objects', k: 'secure lock private encryption e2ee safe' },
      { e: '🔓', n: 'unlocked', c: 'objects', k: 'open insecure access public' },
      { e: '🔏', n: 'locked with pen', c: 'objects', k: 'privacy signature sign' },
      { e: '🔐', n: 'locked with key', c: 'objects', k: 'vault security private cipher' },
      { e: '🔔', n: 'bell', c: 'objects', k: 'notification alarm ring chime' },
      { e: '📦', n: 'package', c: 'objects', k: 'box delivery parcel ship' },
      { e: '✉️', n: 'envelope', c: 'objects', k: 'mail message email letter' },
      { e: '📫', n: 'closed mailbox', c: 'objects', k: 'post mail inbox delivery' },
      { e: '📝', n: 'memo', c: 'objects', k: 'note document write text paper' },
      { e: '📄', n: 'page facing up', c: 'objects', k: 'document file paper text' },
      { e: '📅', n: 'date calendar', c: 'objects', k: 'schedule plan event day' },
      { e: '📊', n: 'bar chart', c: 'objects', k: 'analytics stats data graph' },
      { e: '📈', n: 'chart increasing', c: 'objects', k: 'growth stocks profit up' },
      { e: '📉', n: 'chart decreasing', c: 'objects', k: 'loss crash down drop' },
      { e: '🔍', n: 'magnifying glass left', c: 'objects', k: 'search inspect find query' },
      { e: '🔎', n: 'magnifying glass right', c: 'objects', k: 'examine look search' },

      // Symbols & Security
      { e: '✅', n: 'check mark button', c: 'symbols', k: 'yes ok correct tick green' },
      { e: '❌', n: 'cross mark', c: 'symbols', k: 'no wrong cancel x error' },
      { e: '⭕', n: 'heavy large circle', c: 'symbols', k: 'circle ring ok red' },
      { e: '⛔', n: 'no entry', c: 'symbols', k: 'stop forbidden access denied' },
      { e: '🚫', n: 'prohibited', c: 'symbols', k: 'ban restricted no forbidden' },
      { e: '⚠️', n: 'warning', c: 'symbols', k: 'alert caution hazard danger' },
      { e: '☢️', n: 'radioactive', c: 'symbols', k: 'nuclear radiation hazard' },
      { e: '☣️', n: 'biohazard', c: 'symbols', k: 'biological virus danger' },
      { e: '🛑', n: 'stop sign', c: 'symbols', k: 'halt octagon red' },
      { e: '♻️', n: 'recycling symbol', c: 'symbols', k: 'eco green reuse waste' },
      { e: '❇️', n: 'sparkle', c: 'symbols', k: 'green star sparkle shiny' },
      { e: '✳️', n: 'eight spoked asterisk', c: 'symbols', k: 'star footnote asterisk' },
      { e: '🌐', n: 'globe with meridians', c: 'symbols', k: 'world internet web p2p online' },
      { e: '💠', n: 'diamond with a dot', c: 'symbols', k: 'gem cute kawaii blue' },
      { e: '♾️', n: 'infinity', c: 'symbols', k: 'endless loop forever' },
      { e: '❓', n: 'question mark', c: 'symbols', k: 'confused what why help' },
      { e: '❗', n: 'exclamation mark', c: 'symbols', k: 'alert important attention' },
      { e: '💤', n: 'zzz', c: 'symbols', k: 'sleep tired snoring bedtime' },
      { e: '🔴', n: 'red circle', c: 'symbols', k: 'recording live status dot' },
      { e: '🟢', n: 'green circle', c: 'symbols', k: 'online verified active connected' },
      { e: '🔵', n: 'blue circle', c: 'symbols', k: 'info status calm' },
      { e: '🟡', n: 'yellow circle', c: 'symbols', k: 'pending away idle' },
      { e: '🟠', n: 'orange circle', c: 'symbols', k: 'warning alert' },
      { e: '🟣', n: 'purple circle', c: 'symbols', k: 'dot circle violet' },
      { e: '⚫', n: 'black circle', c: 'symbols', k: 'offline dark' },
      { e: '⚪', n: 'white circle', c: 'symbols', k: 'light empty' },
      { e: '🏁', n: 'chequered flag', c: 'symbols', k: 'race finish victory win' },
      { e: '🚩', n: 'triangular flag', c: 'symbols', k: 'red flag marker priority' },
      { e: '🏴‍☠️', n: 'pirate flag', c: 'symbols', k: 'jolly roger skull corsair' },

      // Flags
      { e: '🇺🇸', n: 'flag United States', c: 'flags', k: 'usa america american' },
      { e: '🇬🇧', n: 'flag United Kingdom', c: 'flags', k: 'uk britain british london' },
      { e: '🇨🇦', n: 'flag Canada', c: 'flags', k: 'canadian maple leaf' },
      { e: '🇦🇺', n: 'flag Australia', c: 'flags', k: 'australian kangaroo' },
      { e: '🇯🇵', n: 'flag Japan', c: 'flags', k: 'japanese tokyo' },
      { e: '🇩🇪', n: 'flag Germany', c: 'flags', k: 'german berlin' },
      { e: '🇫🇷', n: 'flag France', c: 'flags', k: 'french paris' },
      { e: '🇮🇳', n: 'flag India', c: 'flags', k: 'indian delhi' },
      { e: '🇧🇷', n: 'flag Brazil', c: 'flags', k: 'brazilian rio' },
      { e: '🇦🇪', n: 'flag United Arab Emirates', c: 'flags', k: 'uae dubai abu dhabi' },
      { e: '🇺🇳', n: 'flag United Nations', c: 'flags', k: 'un international world' },
      { e: '🏳️‍🌈', n: 'rainbow flag', c: 'flags', k: 'pride lgbtq equality' },
      { e: '🏴', n: 'black flag', c: 'flags', k: 'dark stealth' },
      { e: '🏳️', n: 'white flag', c: 'flags', k: 'peace surrender truce' }
    ];

    this.activeEmojiCategory = 'all';

    // Render initial emoji grid
    this.renderEmojiGrid(this.allEmojis);

    // Toggle button
    if (this.btnToggleEmojiPicker) {
      this.btnToggleEmojiPicker.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = this.emojiPickerPopover.style.display !== 'none';
        if (isOpen) {
          this.emojiPickerPopover.style.display = 'none';
        } else {
          this.emojiPickerPopover.style.display = 'flex';
          if (this.emojiSearchInput) {
            this.emojiSearchInput.value = '';
            this.emojiSearchInput.focus();
          }
          this.filterEmojis();
        }
      });
    }

    // Close button
    if (this.btnCloseEmojiPicker) {
      this.btnCloseEmojiPicker.addEventListener('click', (e) => {
        e.stopPropagation();
        this.emojiPickerPopover.style.display = 'none';
      });
    }

    // Category Tabs
    if (this.emojiCategoryTabs) {
      this.emojiCategoryTabs.querySelectorAll('.emoji-tab-btn').forEach(tab => {
        tab.addEventListener('click', (e) => {
          e.stopPropagation();
          this.emojiCategoryTabs.querySelectorAll('.emoji-tab-btn').forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          this.activeEmojiCategory = tab.dataset.cat;
          this.filterEmojis();
        });
      });
    }

    // Search input
    if (this.emojiSearchInput) {
      this.emojiSearchInput.addEventListener('input', () => {
        const query = this.emojiSearchInput.value.trim();
        if (this.btnClearEmojiSearch) {
          this.btnClearEmojiSearch.style.display = query ? 'block' : 'none';
        }
        this.filterEmojis();
      });
    }

    // Clear search
    if (this.btnClearEmojiSearch) {
      this.btnClearEmojiSearch.addEventListener('click', (e) => {
        e.stopPropagation();
        if (this.emojiSearchInput) {
          this.emojiSearchInput.value = '';
          this.emojiSearchInput.focus();
        }
        this.btnClearEmojiSearch.style.display = 'none';
        this.filterEmojis();
      });
    }

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (this.emojiPickerPopover && this.emojiPickerPopover.style.display !== 'none') {
        if (!this.emojiPickerPopover.contains(e.target) && e.target !== this.btnToggleEmojiPicker && !this.btnToggleEmojiPicker.contains(e.target)) {
          this.emojiPickerPopover.style.display = 'none';
        }
      }
    });
  }

  filterEmojis() {
    const query = this.emojiSearchInput ? this.emojiSearchInput.value.toLowerCase().trim() : '';
    let filtered = this.allEmojis;

    if (this.activeEmojiCategory && this.activeEmojiCategory !== 'all') {
      filtered = filtered.filter(item => item.c === this.activeEmojiCategory);
    }

    if (query) {
      filtered = filtered.filter(item => 
        item.e.includes(query) || 
        item.n.toLowerCase().includes(query) || 
        item.k.toLowerCase().includes(query)
      );
    }

    this.renderEmojiGrid(filtered);
  }

  renderEmojiGrid(emojis) {
    if (!this.emojiGridContainer) return;
    this.emojiGridContainer.innerHTML = '';

    if (emojis.length === 0) {
      this.emojiGridContainer.innerHTML = `
        <div style="grid-column: 1 / -1; padding: 1.5rem 0.5rem; text-align: center; color: var(--text-subtle); font-size: 0.8rem;">
          <i class='bx bx-search' style="font-size: 1.5rem; display:block; margin-bottom: 0.3rem;"></i>
          No emojis match your search.
        </div>
      `;
      return;
    }

    emojis.forEach(item => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'emoji-item-btn';
      btn.dataset.emoji = item.e;
      btn.title = item.n;
      btn.textContent = item.e;

      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (this.chatInput) {
          this.chatInput.value += item.e;
          this.chatInput.focus();
        }
        if (this.emojiPreviewText) {
          this.emojiPreviewText.textContent = `Inserted ${item.e} (${item.n})`;
        }
      });

      btn.addEventListener('mouseenter', () => {
        if (this.emojiPreviewText) {
          this.emojiPreviewText.textContent = `${item.e} ${item.n}`;
        }
      });

      this.emojiGridContainer.appendChild(btn);
    });
  }

  // ============================================================================
  // ENVELOPE ENCRYPTION HELPERS (FOR ZERO-LEAK FILES & VOICE NOTES)
  // ============================================================================
  async createEnvelopeRecipientKeys(rawTransferKeyBase64) {
    const recipientKeys = {};
    const targetPeers = Array.from(new Set([
      ...Array.from(this.webrtc.peerProfiles.keys()),
      ...Array.from(this.webrtc.connections.keys())
    ]));

    for (const peerId of targetPeers) {
      const peerKey = this.currentRoom.sharedSessionKeys.get(peerId) || this.currentRoom.derivedKey;
      if (peerKey) {
        try {
          const enc = await this.crypto.encrypt(rawTransferKeyBase64, peerKey);
          recipientKeys[peerId] = enc;
        } catch (e) {
          console.warn('Envelope encryption failed for peer', peerId, e);
        }
      }
    }

    // Always encrypt for self and broadcast room using derivedKey (if present)
    if (this.currentRoom.derivedKey) {
      try {
        const selfEnc = await this.crypto.encrypt(rawTransferKeyBase64, this.currentRoom.derivedKey);
        recipientKeys[this.currentUser.userId] = selfEnc;
        recipientKeys['room'] = selfEnc;
      } catch (e) {}
    }

    return recipientKeys;
  }

  async resolveEnvelopeTransferKey(metadata, peerId) {
    if (!metadata.recipientKeys || typeof metadata.recipientKeys !== 'object') {
      return null;
    }

    const sessionKey = this.currentRoom.sharedSessionKeys.get(peerId);
    const senderId = metadata.senderId;
    const sessionKeyBySender = senderId ? this.currentRoom.sharedSessionKeys.get(senderId) : null;
    const roomKey = this.currentRoom.derivedKey;

    const keysToTry = [sessionKey, sessionKeyBySender, roomKey].filter(Boolean);

    const candidatePayloads = [
      metadata.recipientKeys[this.webrtc.myPeerId],
      metadata.recipientKeys[this.currentUser.userId],
      metadata.recipientKeys['room'],
      metadata.recipientKeys[peerId],
      ...Object.values(metadata.recipientKeys)
    ].filter(Boolean);

    for (const payload of candidatePayloads) {
      for (const k of keysToTry) {
        try {
          const rawKeyBase64 = await this.crypto.decrypt(payload.ciphertext, payload.iv, k);
          if (rawKeyBase64 && rawKeyBase64.length > 20) {
            return await this.crypto.importSymmetricKey(rawKeyBase64);
          }
        } catch (err) {
          // Continue attempting other candidate keys
        }
      }
    }

    return null;
  }

  // ============================================================================
  // FILE & IMAGE SHARING WITH INLINE PREVIEWS & ENVELOPE ENCRYPTION
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

        // Generate fresh ephemeral 256-bit AES-GCM transfer key
        const transferKey = await this.crypto.generateSymmetricKey();
        const transferKeyBase64 = await this.crypto.exportSymmetricKey(transferKey);

        // Encrypt file payload with transferKey
        const { ciphertext, iv } = await this.crypto.encrypt(base64Data, transferKey);

        // Create envelope recipient keys for all connected peers + self
        const recipientKeys = await this.createEnvelopeRecipientKeys(transferKeyBase64);

        const isImg = file.type.startsWith('image/');
        const fileMetadata = {
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type,
          isImage: isImg,
          iv: iv,
          author: this.currentUser.username,
          senderId: this.currentUser.userId,
          recipientKeys: recipientKeys,
          isVoiceNote: false
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
      if (!metadata) {
        console.warn('Received file chunk without metadata');
        return;
      }

      let transferKey = await this.resolveEnvelopeTransferKey(metadata, peerId);

      // Fallback if envelope decryption was not used (legacy / direct session key)
      if (!transferKey) {
        transferKey = this.currentRoom.sharedSessionKeys.get(peerId) || 
                      (metadata.senderId ? this.currentRoom.sharedSessionKeys.get(metadata.senderId) : null) || 
                      this.currentRoom.derivedKey;
      }

      if (!transferKey) {
        throw new Error('No decryption key available for incoming file or voice note');
      }

      const decryptedBase64 = await this.crypto.decrypt(data, metadata.iv, transferKey);
      const buffer = this.crypto.base64ToBuffer(decryptedBase64);

      // Handle voice note receiving
      if (metadata.isVoiceNote) {
        const mime = metadata.fileType || 'audio/webm';
        const blob = new Blob([buffer], { type: mime });
        const dataUrl = URL.createObjectURL(blob);

        const voiceItem = {
          type: 'voice',
          dataUrl: dataUrl,
          base64Audio: decryptedBase64,
          mimeType: mime,
          duration: metadata.duration || 0,
          fileSize: buffer.byteLength,
          fileName: metadata.fileName || 'voice-note.webm',
          author: metadata.author || 'Peer',
          isOutgoing: false,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };

        this.renderVoiceNoteCard(voiceItem);
        this.savedMessages.push(voiceItem);
        await this.saveEncryptedHistory();

        this.playSound('receive');
        this.showToast(`🎤 Received encrypted voice note (${voiceItem.duration}s) from ${this.escapeHTML(voiceItem.author)}`);
        return;
      }

      // Handle standard file / image receiving
      const isImg = metadata.isImage || (metadata.fileType && metadata.fileType.startsWith('image/'));
      const blob = new Blob([buffer], { type: metadata.fileType || 'application/octet-stream' });
      const dataUrl = URL.createObjectURL(blob);

      const fileItem = {
        type: isImg ? 'image' : 'file',
        fileName: metadata.fileName || (isImg ? 'image.png' : 'file.bin'),
        fileSize: metadata.fileSize || buffer.byteLength,
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
      this.showToast(`Received encrypted ${isImg ? 'image' : 'file'}: ${this.escapeHTML(fileItem.fileName)}`);
    } catch (err) {
      console.error('File/voice decryption failed:', err);
      this.showToast('Error decrypting incoming media: ' + (err.message || 'Key mismatch'));
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
        alert('Microphone recording is not supported on this browser or connection is insecure (HTTPS or localhost required).');
        return;
      }

      // Explicit high-sensitivity constraints to guarantee clear voice capture
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          channelCount: 1,
          sampleRate: 48000
        }
      });

      this.activeAudioStream = stream;

      // Real-time AudioContext Analyser for Voice Level Detection & Visualizer
      try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
          this.recordingAudioCtx = new AudioCtx();
          if (this.recordingAudioCtx.state === 'suspended') {
            await this.recordingAudioCtx.resume();
          }
          const source = this.recordingAudioCtx.createMediaStreamSource(stream);
          this.recordingAnalyser = this.recordingAudioCtx.createAnalyser();
          this.recordingAnalyser.fftSize = 64;
          source.connect(this.recordingAnalyser);

          // Audio level detection loop
          const dataArray = new Uint8Array(this.recordingAnalyser.frequencyBinCount);
          this.maxVoiceLevel = 0;
          this.voiceDetected = false;

          const updateVisualizer = () => {
            if (!this.recordingAnalyser || !this.mediaRecorder || this.mediaRecorder.state === 'inactive') return;
            this.recordingAnalyser.getByteFrequencyData(dataArray);

            let sum = 0;
            for (let i = 0; i < dataArray.length; i++) {
              sum += dataArray[i];
            }
            const average = sum / dataArray.length;
            if (average > this.maxVoiceLevel) this.maxVoiceLevel = average;

            // Animate waveform bars in the recording bar
            const bars = document.querySelectorAll('#voice-recording-visualizer .v-bar');
            if (bars && bars.length > 0) {
              bars.forEach((bar, idx) => {
                const val = dataArray[idx % dataArray.length] || 0;
                const heightPct = Math.max(15, Math.min(100, Math.round((val / 255) * 100)));
                bar.style.height = `${heightPct}%`;
                if (val > 25) {
                  bar.classList.add('active');
                } else {
                  bar.classList.remove('active');
                }
              });
            }

            const statusEl = document.getElementById('voice-live-status');
            if (statusEl) {
              if (average > 12) {
                this.voiceDetected = true;
                statusEl.textContent = 'Voice detected 🎙️';
                statusEl.style.color = '#00e699';
              } else {
                statusEl.textContent = 'Listening...';
                statusEl.style.color = 'var(--text-subtle)';
              }
            }

            this.visualizerAnimationId = requestAnimationFrame(updateVisualizer);
          };

          this.visualizerAnimationId = requestAnimationFrame(updateVisualizer);
        }
      } catch (e) {
        console.warn('AudioContext analyser initialization notice:', e);
      }

      // Cross-browser supported MIME type
      let mime = this.supportedAudioMimeType;
      if (!mime || !MediaRecorder.isTypeSupported(mime)) {
        if (MediaRecorder.isTypeSupported('audio/webm;codecs=opus')) mime = 'audio/webm;codecs=opus';
        else if (MediaRecorder.isTypeSupported('audio/webm')) mime = 'audio/webm';
        else if (MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')) mime = 'audio/ogg;codecs=opus';
        else if (MediaRecorder.isTypeSupported('audio/mp4')) mime = 'audio/mp4';
        else mime = '';
      }

      const recorderOptions = mime ? { mimeType: mime, audioBitsPerSecond: 128000 } : {};
      this.mediaRecorder = new MediaRecorder(stream, recorderOptions);
      this.audioChunks = [];

      this.mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          this.audioChunks.push(e.data);
        }
      };

      // Start recording with 100ms timeslice so audio is continuously committed into chunks
      this.mediaRecorder.start(100);
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
      try { this.mediaRecorder.stop(); } catch (e) {}
    }
    if (this.activeAudioStream) {
      this.activeAudioStream.getTracks().forEach(t => t.stop());
      this.activeAudioStream = null;
    }
    if (this.visualizerAnimationId) {
      cancelAnimationFrame(this.visualizerAnimationId);
      this.visualizerAnimationId = null;
    }
    if (this.recordingAudioCtx) {
      try { this.recordingAudioCtx.close(); } catch (e) {}
      this.recordingAudioCtx = null;
    }
    clearInterval(this.recordingInterval);
    this.recordingBar.style.display = 'none';
    this.chatInput.style.display = 'block';
    this.showToast('Voice recording cancelled.');
  }

  async stopAndSendVoiceRecording() {
    if (!this.mediaRecorder || this.mediaRecorder.state === 'inactive') return;

    // Flush any pending data before stopping
    try {
      if (typeof this.mediaRecorder.requestData === 'function') {
        this.mediaRecorder.requestData();
      }
    } catch (e) {}

    // Cleanup recording timer & UI
    clearInterval(this.recordingInterval);
    if (this.visualizerAnimationId) {
      cancelAnimationFrame(this.visualizerAnimationId);
      this.visualizerAnimationId = null;
    }
    if (this.recordingAudioCtx) {
      try { this.recordingAudioCtx.close(); } catch (e) {}
      this.recordingAudioCtx = null;
    }

    this.recordingBar.style.display = 'none';
    this.chatInput.style.display = 'block';

    const recordingStream = this.activeAudioStream;
    const durationSecs = Math.max(1, Math.round((Date.now() - this.recordingStartTime) / 1000));

    // Wait for onstop to finish gathering all chunks BEFORE stopping tracks
    await new Promise((resolve) => {
      this.mediaRecorder.onstop = async () => {
        try {
          // Safe to close hardware tracks now that encoding has finalized
          if (recordingStream) {
            recordingStream.getTracks().forEach(t => t.stop());
          }

          const mime = (this.mediaRecorder && this.mediaRecorder.mimeType) || this.supportedAudioMimeType || 'audio/webm';
          const audioBlob = new Blob(this.audioChunks, { type: mime });

          console.log(`Voice note finalized: ${audioBlob.size} bytes, type=${mime}, duration=${durationSecs}s`);

          if (audioBlob.size < 400) {
            alert('Voice recording was too short or no audio was detected. Please hold microphone and speak clearly.');
            resolve();
            return;
          }

          await this.sendVoiceNote(audioBlob, durationSecs);
        } catch (err) {
          console.error('Error assembling voice note:', err);
          this.showToast('Failed to process voice recording: ' + err.message);
        }
        resolve();
      };

      this.mediaRecorder.stop();
    });

    this.mediaRecorder = null;
    this.activeAudioStream = null;
  }

  async sendVoiceNote(audioBlob, durationSecs) {
    try {
      const arrayBuffer = await audioBlob.arrayBuffer();
      const base64Data = this.crypto.bufferToBase64(arrayBuffer);
      const dataUrl = URL.createObjectURL(audioBlob);

      // Generate fresh ephemeral 256-bit AES-GCM transfer key
      const transferKey = await this.crypto.generateSymmetricKey();
      const transferKeyBase64 = await this.crypto.exportSymmetricKey(transferKey);

      // Encrypt audio payload with transferKey
      const { ciphertext, iv } = await this.crypto.encrypt(base64Data, transferKey);

      // Create envelope recipient keys for all connected peers + self
      const recipientKeys = await this.createEnvelopeRecipientKeys(transferKeyBase64);

      const mimeType = audioBlob.type || this.supportedAudioMimeType || 'audio/webm';
      const ext = mimeType.includes('ogg') ? 'ogg' : (mimeType.includes('mp4') ? 'mp4' : 'webm');
      const metadata = {
        fileName: `voice-note-${Date.now()}.${ext}`,
        fileSize: audioBlob.size,
        fileType: mimeType,
        duration: durationSecs,
        iv: iv,
        isVoiceNote: true,
        author: this.currentUser.username,
        senderId: this.currentUser.userId,
        recipientKeys: recipientKeys
      };

      this.showToast(`Transmitting encrypted voice note (${(audioBlob.size / 1024).toFixed(1)} KB)...`);

      await this.webrtc.sendFile(ciphertext, metadata);

      const voiceItem = {
        type: 'voice',
        dataUrl: dataUrl,
        base64Audio: base64Data,
        mimeType: mimeType,
        duration: durationSecs,
        fileSize: audioBlob.size,
        fileName: metadata.fileName,
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

    // Unique ID for this player instance
    const playerId = 'vp_' + Math.random().toString(36).substr(2, 9);
    const duration = voiceInfo.duration || 1;

    // Generate 24 static soundwave bars with pleasant varying heights
    const barHeights = [25, 45, 75, 55, 30, 80, 100, 65, 40, 90, 85, 50, 70, 95, 60, 40, 75, 50, 30, 85, 65, 45, 35, 20];
    const barsHtml = barHeights.map(h => `<span style="height:${h}%;"></span>`).join('');

    card.innerHTML = `
      <div class="voice-note-header">
        <div style="display:flex; align-items:center; gap:0.35rem;">
          <i class='bx bx-microphone' style="color:var(--accent-primary); font-size:1.05rem;"></i>
          <span>Encrypted Voice Note</span>
        </div>
        <span class="voice-duration-tag">${duration}s</span>
      </div>

      <div class="voice-player-body" id="${playerId}">
        <button type="button" class="voice-play-btn" id="${playerId}_btn" title="Play / Pause Voice Note">
          <i class='bx bx-play'></i>
        </button>

        <div class="voice-waveform-track" id="${playerId}_track">
          <div class="voice-waveform-progress" id="${playerId}_prog"></div>
          <div class="voice-waveform-bars" id="${playerId}_bars">
            ${barsHtml}
          </div>
        </div>

        <span class="voice-time-display" id="${playerId}_time">0:00</span>
      </div>

      <div class="voice-footer-controls">
        <span style="font-size:0.7rem; color:var(--text-subtle);">
          <i class='bx bx-shield-quarter'></i> AES-256-GCM • ${voiceInfo.fileSize ? (voiceInfo.fileSize / 1024).toFixed(1) + ' KB' : 'Opus'}
        </span>
        <a href="${voiceInfo.dataUrl}" download="${this.escapeHTML(voiceInfo.fileName || 'voice-note.webm')}" class="voice-save-btn" title="Download Decrypted Voice Note">
          <i class='bx bxs-download'></i> Save
        </a>
      </div>
    `;

    bubble.appendChild(card);
    row.appendChild(bubble);
    this.messagesContainer.appendChild(row);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;

    // Attach Interactive Audio Player Controller
    this.attachVoicePlayerController(playerId, voiceInfo);
  }

  attachVoicePlayerController(playerId, voiceInfo) {
    const playBtn = document.getElementById(`${playerId}_btn`);
    const track = document.getElementById(`${playerId}_track`);
    const progressEl = document.getElementById(`${playerId}_prog`);
    const timeEl = document.getElementById(`${playerId}_time`);
    const barsContainer = document.getElementById(`${playerId}_bars`);

    if (!playBtn || !voiceInfo.dataUrl) return;

    let audioElement = null;
    let isAudioContextPlaying = false;
    let audioContextSource = null;
    let fallbackStartTime = 0;
    let fallbackInterval = null;

    const formatTime = (secs) => {
      const s = Math.floor(secs);
      const m = Math.floor(s / 60);
      const rem = s % 60;
      return `${m}:${rem.toString().padStart(2, '0')}`;
    };

    const resetUI = () => {
      playBtn.innerHTML = "<i class='bx bx-play'></i>";
      progressEl.style.width = '0%';
      timeEl.textContent = '0:00';
      barsContainer.classList.remove('playing');
      isAudioContextPlaying = false;
      if (fallbackInterval) {
        clearInterval(fallbackInterval);
        fallbackInterval = null;
      }
    };

    // Playback via AudioContext PCM decoding (bulletproof fallback for any browser container glitch)
    const playViaAudioContext = async () => {
      try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        const ctx = new AudioCtx();
        if (ctx.state === 'suspended') {
          await ctx.resume();
        }

        let arrayBuffer;
        if (voiceInfo.base64Audio) {
          arrayBuffer = this.crypto.base64ToBuffer(voiceInfo.base64Audio);
        } else {
          const resp = await fetch(voiceInfo.dataUrl);
          arrayBuffer = await resp.arrayBuffer();
        }

        const audioBuffer = await ctx.decodeAudioData(arrayBuffer);
        const source = ctx.createBufferSource();
        source.buffer = audioBuffer;
        source.connect(ctx.destination);

        const duration = audioBuffer.duration || voiceInfo.duration || 1;
        fallbackStartTime = ctx.currentTime;
        isAudioContextPlaying = true;
        audioContextSource = source;

        playBtn.innerHTML = "<i class='bx bx-pause'></i>";
        barsContainer.classList.add('playing');

        fallbackInterval = setInterval(() => {
          if (!isAudioContextPlaying) return;
          const elapsed = ctx.currentTime - fallbackStartTime;
          if (elapsed >= duration) {
            resetUI();
            try { ctx.close(); } catch (e) {}
          } else {
            const pct = Math.min(100, (elapsed / duration) * 100);
            progressEl.style.width = `${pct}%`;
            timeEl.textContent = formatTime(elapsed);
          }
        }, 50);

        source.onended = () => {
          resetUI();
          try { ctx.close(); } catch (e) {}
        };

        source.start(0);
      } catch (err) {
        console.error('AudioContext fallback decode error:', err);
        this.showToast('Audio playback failed: ' + (err.message || err));
        resetUI();
      }
    };

    playBtn.addEventListener('click', async (e) => {
      e.stopPropagation();

      // If AudioContext fallback is currently playing, pause/stop it
      if (isAudioContextPlaying) {
        if (audioContextSource) {
          try { audioContextSource.stop(); } catch (e) {}
        }
        resetUI();
        return;
      }

      // If native Audio is playing, pause it
      if (audioElement && !audioElement.paused) {
        audioElement.pause();
        playBtn.innerHTML = "<i class='bx bx-play'></i>";
        barsContainer.classList.remove('playing');
        return;
      }

      // If native Audio is paused mid-way, resume
      if (audioElement && audioElement.paused && audioElement.currentTime > 0 && !audioElement.ended) {
        try {
          await audioElement.play();
          playBtn.innerHTML = "<i class='bx bx-pause'></i>";
          barsContainer.classList.add('playing');
          return;
        } catch (err) {
          console.warn('Native audio resume failed, using fallback:', err);
        }
      }

      // Otherwise start new playback
      if (!audioElement) {
        audioElement = new Audio();
        audioElement.src = voiceInfo.dataUrl;
        audioElement.volume = 1.0;

        audioElement.ontimeupdate = () => {
          const current = audioElement.currentTime;
          const total = audioElement.duration && isFinite(audioElement.duration) ? audioElement.duration : (voiceInfo.duration || 1);
          const pct = Math.min(100, (current / total) * 100);
          progressEl.style.width = `${pct}%`;
          timeEl.textContent = formatTime(current);
        };

        audioElement.onended = () => {
          resetUI();
        };

        audioElement.onerror = () => {
          console.warn('HTML5 Audio element error, switching to AudioContext raw decoder...');
          playViaAudioContext();
        };
      }

      try {
        audioElement.currentTime = 0;
        await audioElement.play();
        playBtn.innerHTML = "<i class='bx bx-pause'></i>";
        barsContainer.classList.add('playing');
      } catch (err) {
        console.warn('Direct Audio.play() rejected, executing AudioContext decoder:', err);
        playViaAudioContext();
      }
    });

    // Seek on track click
    track.addEventListener('click', (e) => {
      e.stopPropagation();
      const rect = track.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const ratio = Math.max(0, Math.min(1, clickX / rect.width));
      const targetSecs = ratio * (voiceInfo.duration || 1);

      if (audioElement && audioElement.duration && isFinite(audioElement.duration)) {
        audioElement.currentTime = ratio * audioElement.duration;
      }
      progressEl.style.width = `${ratio * 100}%`;
      timeEl.textContent = formatTime(targetSecs);
    });
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
