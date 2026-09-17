/**
 * ==============================================================================
 * CIPHERCORE APPLICATION CONTROLLER (v2.5)
 * Username-Based Chat, Voice Player, Image Previews, Clickable Links,
 * Encrypted Local Storage Persistence & Zero-Server P2P E2EE
 * ==============================================================================
 */

class CipherApp {
  constructor() {
    this.crypto = window.cipherCore;
    this.webrtc = new WebRTCManager();

    // Storage Keys
    this.STORAGE_PROFILE_KEY = 'ciphercore_profile_vault';
    this.STORAGE_HISTORY_KEY = 'ciphercore_messages_vault';

    // Current User State
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
      activeRecipientId: null, // In direct 1-to-1 mode
    };

    // Stored Message History in memory
    this.savedMessages = [];

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

    // Initialize user identity lifecycle
    this.initIdentityFlow();
  }

  // Detect supported audio MIME type for cross-browser voice notes
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

    // Setup elements
    this.inputUsername = document.getElementById('setup-username');
    this.inputPassword = document.getElementById('setup-password');
    this.inputRoomId = document.getElementById('setup-room-id');
    this.btnRegenPassword = document.getElementById('btn-regen-password');
    this.btnCopyPassword = document.getElementById('btn-copy-password');
    this.passwordEntropyLabel = document.getElementById('password-entropy');
    this.entropyDots = document.querySelectorAll('.entropy-dot');
    this.btnSubmitAction = document.getElementById('btn-submit-action');
    this.tabButtons = document.querySelectorAll('.card-tabs .tab-btn');

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

    // Lightbox Modal
    this.imageLightbox = document.getElementById('image-lightbox');
    this.lightboxImg = document.getElementById('lightbox-img');
    this.btnCloseLightbox = document.getElementById('btn-close-lightbox');
  }

  // Identity Lifecycle: URL Hash (#account / #chat) -> Local Storage -> Auto-generation
  async initIdentityFlow() {
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);

    const accountId = params.get('account');
    const accountKey = params.get('key');
    const accountUser = params.get('user');
    const chatTargetId = params.get('chat');

    // Scenario 1: User opened their Unique Access URL (#account=...&key=...)
    if (accountId && accountKey) {
      const username = accountUser ? decodeURIComponent(accountUser) : 'Agent_' + accountId.slice(4, 9);
      await this.loginWithCredentials(accountId, accountKey, username, true);
      this.showToast('✅ Logged in via your Unique Access URL!');
      return;
    }

    // Scenario 2: Check Local Encrypted Storage for returning user
    const localProfileRaw = localStorage.getItem('ciphercore_identity_hint');
    if (localProfileRaw) {
      try {
        const hint = JSON.parse(localProfileRaw);
        if (hint.userId && hint.storedKey) {
          await this.loginWithCredentials(hint.userId, hint.storedKey, hint.username || 'Agent', false);
          
          if (chatTargetId) {
            this.handleDirectChatWithPeer(chatTargetId);
          }
          return;
        }
      } catch (e) {
        console.warn('Failed parsing local identity hint:', e);
      }
    }

    // Scenario 3: First-time visitor -> Generate Unique Identity & 16-character CSPRNG Key
    const newUserId = 'usr_' + this.crypto.bufferToHex(this.crypto.generateSalt(4));
    const newPassword = this.crypto.generateSecurePassword(16);
    const defaultUsername = 'Agent_' + newUserId.slice(4, 9);

    if (this.inputUsername) this.inputUsername.value = defaultUsername;
    if (this.inputPassword) this.inputPassword.value = newPassword;
    this.updateEntropyMeter(newPassword);

    await this.loginWithCredentials(newUserId, newPassword, defaultUsername, true);

    if (chatTargetId) {
      this.handleDirectChatWithPeer(chatTargetId);
    }
  }

  // Log in and activate user credentials
  async loginWithCredentials(userId, secretKey, username, saveToLocal = true) {
    this.currentUser.userId = userId;
    this.currentUser.secretKey = secretKey;
    this.currentUser.username = username;

    // Generate Ephemeral ECDH Key Pair for PFS
    this.currentUser.keyPair = await this.crypto.generateECDHKeyPair();
    this.currentUser.publicKeyBase64 = await this.crypto.exportPublicKey(this.currentUser.keyPair.publicKey);

    // Derive Master AES-256-GCM Key from Secret Key
    const salt = await this.crypto.computeFingerprint(userId);
    this.currentRoom.derivedKey = await this.crypto.deriveKeyFromPassword(
      secretKey,
      new TextEncoder().encode(salt)
    );

    // Store local profile hint
    if (saveToLocal) {
      this.persistProfileToLocalStorage();
    }

    // Update URLs
    this.updateUniqueUrls();

    // Initialize WebRTC with userId as custom peer ID
    await this.initializeWebRTCIdentity(userId);

    // Load saved encrypted messages
    await this.loadEncryptedHistory();

    // Update UI Badges
    this.updateUserBadgeUI();

    // Transition to Chat view
    if (this.viewSetup) this.viewSetup.classList.remove('active');
    if (this.viewChat) this.viewChat.classList.add('active');
    if (this.displayRoomId) this.displayRoomId.textContent = userId;
  }

  updateUserBadgeUI() {
    if (this.userBadgeId) this.userBadgeId.textContent = this.currentUser.userId;
    if (this.userBadgeName) this.userBadgeName.textContent = this.currentUser.username;
    if (this.userAvatarBadge) this.userAvatarBadge.textContent = this.currentUser.username.charAt(0).toUpperCase();
  }

  persistProfileToLocalStorage() {
    localStorage.setItem('ciphercore_identity_hint', JSON.stringify({
      userId: this.currentUser.userId,
      storedKey: this.currentUser.secretKey,
      username: this.currentUser.username,
      updatedAt: Date.now()
    }));

    this.crypto.saveSecureLocal(this.STORAGE_PROFILE_KEY, {
      userId: this.currentUser.userId,
      username: this.currentUser.username,
      secretKey: this.currentUser.secretKey,
      created: Date.now()
    }, this.currentUser.secretKey);
  }

  // Update Unique Access URL and Public Chat Link inputs
  updateUniqueUrls() {
    const baseUrl = window.location.origin + window.location.pathname;
    
    // Private Access URL (keeps keys strictly in hash # - RFC 3986)
    const privateAccessUrl = `${baseUrl}#account=${this.currentUser.userId}&key=${encodeURIComponent(this.currentUser.secretKey)}&user=${encodeURIComponent(this.currentUser.username)}`;
    if (this.uniqueAccessUrlInput) {
      this.uniqueAccessUrlInput.value = privateAccessUrl;
    }

    // Public Chat Link (share with friends so they can message you directly)
    const publicChatUrl = `${baseUrl}#chat=${this.currentUser.userId}`;
    if (this.publicChatUrlInput) {
      this.publicChatUrlInput.value = publicChatUrl;
    }
  }

  // Initialize WebRTC peer with user's permanent ID
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

  // Direct 1-to-1 Connect to target peer
  handleDirectChatWithPeer(targetPeerId) {
    if (!targetPeerId || targetPeerId === this.currentUser.userId) return;

    this.showToast(`Connecting to peer ${targetPeerId}...`);
    this.currentRoom.activeRecipientId = targetPeerId;
    
    try {
      this.webrtc.connectToPeer(targetPeerId, {
        username: this.currentUser.username,
        publicKey: this.currentUser.publicKeyBase64
      });
    } catch (e) {
      console.error('Direct connect error:', e);
    }
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
    // Edit Username on clicking badge
    if (this.userPillBadge) {
      this.userPillBadge.style.cursor = 'pointer';
      this.userPillBadge.title = 'Click to edit your username';
      this.userPillBadge.addEventListener('click', () => {
        const newName = prompt('Enter your new username / codename:', this.currentUser.username);
        if (newName && newName.trim()) {
          this.currentUser.username = newName.trim();
          this.updateUserBadgeUI();
          this.updateUniqueUrls();
          this.persistProfileToLocalStorage();
          this.showToast(`Username updated to: ${this.currentUser.username}`);
          
          // Broadcast username update to peers
          this.webrtc.broadcast({
            type: 'username-update',
            username: this.currentUser.username
          });
        }
      });
    }

    // Connect to Peer by ID in sidebar
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

    // Copy Private Access URL
    if (this.btnCopyAccessUrl) {
      this.btnCopyAccessUrl.addEventListener('click', () => {
        navigator.clipboard.writeText(this.uniqueAccessUrlInput.value).then(() => {
          this.showToast('🔑 Unique Private Access URL copied! Bookmark to restore your account.');
        });
      });
    }

    // Copy Public Chat URL
    if (this.btnCopyPublicUrl) {
      this.btnCopyPublicUrl.addEventListener('click', () => {
        navigator.clipboard.writeText(this.publicChatUrlInput.value).then(() => {
          this.showToast('💬 Public Chat Link copied! Share with friends to let them message you.');
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

    // Tab Switching in Setup
    this.tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        this.tabButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const mode = btn.getAttribute('data-tab');
        if (mode === 'create') {
          this.btnSubmitAction.textContent = 'Generate New Identity & Key';
          this.btnSubmitAction.setAttribute('data-action', 'create');
          document.getElementById('room-id-field').style.display = 'none';
        } else {
          this.btnSubmitAction.textContent = 'Connect via Peer ID';
          this.btnSubmitAction.setAttribute('data-action', 'join');
          document.getElementById('room-id-field').style.display = 'block';
        }
      });
    });

    // Password generation controls
    if (this.btnRegenPassword) {
      this.btnRegenPassword.addEventListener('click', () => this.regeneratePassword());
    }

    if (this.btnCopyPassword) {
      this.btnCopyPassword.addEventListener('click', () => {
        navigator.clipboard.writeText(this.inputPassword.value).then(() => {
          this.showToast('16-character password copied to clipboard!');
        });
      });
    }

    if (this.inputPassword) {
      this.inputPassword.addEventListener('input', () => {
        this.updateEntropyMeter(this.inputPassword.value);
      });
    }

    // Submit button in setup
    if (this.btnSubmitAction) {
      this.btnSubmitAction.addEventListener('click', (e) => {
        const action = e.target.getAttribute('data-action') || 'create';
        if (action === 'create') {
          const uName = this.inputUsername.value.trim() || 'Agent_' + Math.random().toString(36).substring(2, 6);
          const uKey = this.inputPassword.value.trim() || this.crypto.generateSecurePassword(16);
          const uId = 'usr_' + this.crypto.bufferToHex(this.crypto.generateSalt(4));
          this.loginWithCredentials(uId, uKey, uName, true);
        } else {
          const targetRoom = this.inputRoomId.value.trim();
          if (targetRoom) {
            this.handleDirectChatWithPeer(targetRoom);
          }
        }
      });
    }

    // Reset / Wipe Account Button
    if (this.btnResetAccount) {
      this.btnResetAccount.addEventListener('click', () => {
        if (confirm('Are you sure you want to reset your local identity and wipe stored messages? Make sure you backed up your Unique Access URL!')) {
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

    // File Sharing
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
        this.showToast('💬 Public Chat Link copied! Share with friends to message you.');
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

  regeneratePassword() {
    const pwd = this.crypto.generateSecurePassword(16);
    this.inputPassword.value = pwd;
    this.updateEntropyMeter(pwd);
  }

  updateEntropyMeter(password) {
    if (!this.passwordEntropyLabel) return;
    const entropy = this.crypto.calculateEntropy(password);
    this.passwordEntropyLabel.textContent = `${entropy} bits`;

    this.entropyDots.forEach(dot => {
      dot.className = 'entropy-dot';
    });

    if (entropy >= 80) {
      this.entropyDots[0].classList.add('active-high');
      this.entropyDots[1].classList.add('active-high');
      this.entropyDots[2].classList.add('active-high');
      this.entropyDots[3].classList.add('active-high');
    } else if (entropy >= 55) {
      this.entropyDots[0].classList.add('active-med');
      this.entropyDots[1].classList.add('active-med');
      this.entropyDots[2].classList.add('active-med');
    } else {
      this.entropyDots[0].classList.add('active-low');
      this.entropyDots[1].classList.add('active-low');
    }
  }

  // WebRTC Events binding
  bindWebRTCEvents() {
    this.webrtc.on('peerConnect', async ({ peerId }) => {
      this.showToast(`Peer ${peerId.slice(0, 8)} connected! Exchanging keys...`);
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

  // Handshake Protocol: Exchange Ephemeral ECDH Public Keys
  async sendHandshake(targetPeerId) {
    const handshakePayload = {
      type: 'handshake',
      username: this.currentUser.username,
      publicKey: this.currentUser.publicKeyBase64,
      timestamp: Date.now(),
    };
    this.webrtc.sendTo(targetPeerId, handshakePayload);
  }

  // Handle incoming data packets
  async handleIncomingMessage(peerId, packet) {
    if (!packet || !packet.type) return;

    if (packet.type === 'handshake') {
      const remotePublicKey = await this.crypto.importPublicKey(packet.publicKey);
      
      // Derive Shared Secret (PFS)
      const sharedKey = await this.crypto.deriveSharedSecret(
        this.currentUser.keyPair.privateKey,
        remotePublicKey
      );
      this.currentRoom.sharedSessionKeys.set(peerId, sharedKey);

      // Compute 60-digit Signal-style Safety Numbers
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

      this.updatePeerListUI();
      this.showToast(`🔒 E2EE Established with ${packet.username}!`);
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

        // Save persistent non-ephemeral messages encrypted in localStorage
        if (!msgObj.ephemeralSeconds) {
          this.savedMessages.push(msgObj);
          await this.saveEncryptedHistory();
        }

        this.playSound('receive');
      } catch (err) {
        console.error('Decryption failed for incoming message:', err);
      }
    }
  }

  // Send Encrypted Message
  async handleSendMessage() {
    const text = this.chatInput.value.trim();
    if (!text) return;

    const payload = {
      username: this.currentUser.username,
      text: text,
      timestamp: Date.now(),
      ephemeralDuration: this.settings.ephemeralDuration
    };

    const peers = Array.from(this.webrtc.connections.keys());

    for (const peerId of peers) {
      const key = this.currentRoom.sharedSessionKeys.get(peerId) || this.currentRoom.derivedKey;
      const { ciphertext, iv } = await this.crypto.encrypt(JSON.stringify(payload), key);

      this.webrtc.sendTo(peerId, {
        type: 'encrypted-message',
        ciphertext: ciphertext,
        iv: iv
      });
    }

    const msgObj = {
      author: this.currentUser.username,
      text: text,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      isOutgoing: true,
      ephemeralSeconds: this.settings.ephemeralDuration
    };

    this.renderMessageBubble(msgObj);

    // Save persistent non-ephemeral messages encrypted in localStorage
    if (!msgObj.ephemeralSeconds) {
      this.savedMessages.push(msgObj);
      await this.saveEncryptedHistory();
    }

    this.chatInput.value = '';
    this.playSound('send');
  }

  // Format message text: escape HTML, make URLs clickable, extract links for preview
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

  // Render message bubble with clickable links and link preview card
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

    // Parse and render formatted text with clickable links
    const { formattedHtml, urls } = this.formatMessageContent(msgData.text);
    const textSpan = document.createElement('div');
    textSpan.innerHTML = formattedHtml;
    bubble.appendChild(textSpan);

    // Render Link Preview Card if URLs are present
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

    // Ephemeral Countdown Bar
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

  // Render File or Image Preview Card
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

    // If Image -> Render image preview thumbnail with click-to-enlarge lightbox
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

      // Download link below image
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
      // General File Attachment Card
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

  // Encrypt and transmit voice note
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

      // Broadcast file chunks
      await this.webrtc.sendFile(ciphertext, metadata);

      // Render audio player locally
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

  // Render Inline Audio Player Card
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
          Waiting for peers... Share your Public Chat Link or enter a Peer ID below.
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
    document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
  }

  // Panic Button: Wipes RAM, WebRTC sessions, local storage, and redirects
  triggerPanicKillswitch() {
    this.playSound('burn');
    this.wipeLocalData();
    document.body.innerHTML = '<div style="background:#000;color:#333;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;">Session Cleared.</div>';
    window.location.replace('https://duckduckgo.com');
  }

  // Wipe Local Storage & Identity
  wipeLocalData() {
    localStorage.removeItem('ciphercore_identity_hint');
    localStorage.removeItem(this.STORAGE_PROFILE_KEY);
    localStorage.removeItem(this.STORAGE_HISTORY_KEY + '_' + this.currentUser.userId);
    this.currentRoom.password = '0000000000000000';
    this.currentRoom.derivedKey = null;
    this.currentRoom.sharedSessionKeys.clear();
    this.currentRoom.safetyNumbers.clear();
    this.webrtc.destroy();
    window.location.hash = '';
    window.location.reload();
  }

  // Decoy Calculator Mode
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
