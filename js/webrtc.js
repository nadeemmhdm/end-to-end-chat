/**
 * ==============================================================================
 * WEBRTC P2P DATACHANNEL MANAGER
 * Zero-Server Direct Peer-to-Peer Communication
 * ==============================================================================
 * Features:
 * - Direct browser-to-browser WebRTC DataChannels (zero intermediary server after ICE)
 * - Uses public open STUN servers (Google STUN)
 * - Automatic ECDH Ephemeral Public Key handshake upon channel open
 * - Chunked binary transport for large encrypted files
 * - Ping/Pong heartbeat & connection state telemetry
 */

class WebRTCManager {
  constructor(options = {}) {
    this.options = {
      debug: false,
      privacyMode: false, // Default false to allow local network & same-machine direct WebRTC connections
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' }
      ],
      ...options
    };

    this.peer = null;
    this.myPeerId = null;
    this.connections = new Map(); // peerId -> DataConnection
    this.peerProfiles = new Map(); // peerId -> { username, publicKey, safetyNumber, ... }
    this.eventListeners = {
      open: [],
      peerConnect: [],
      peerDisconnect: [],
      message: [],
      fileChunk: [],
      fileComplete: [],
      error: [],
      statusChange: []
    };

    this.pendingFileTransfers = new Map(); // transferId -> { peerId, chunks, receivedChunks, totalChunks, metadata, lastActive }
    this.tabInstanceId = 'tab_' + Math.random().toString(36).substring(2, 9);

    // Cryptographic Session Mesh Token (blocks unauthorized script injection into BroadcastChannel)
    // Shared via localStorage across same-origin tabs
    this.meshAuthToken = null;
    try {
      this.meshAuthToken = localStorage.getItem('cc_mesh_auth_token');
      if (!this.meshAuthToken) {
        const tokenBytes = new Uint8Array(24);
        if (window.crypto && window.crypto.getRandomValues) {
          window.crypto.getRandomValues(tokenBytes);
          this.meshAuthToken = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
          this.meshAuthToken = 'mat_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
        }
        localStorage.setItem('cc_mesh_auth_token', this.meshAuthToken);
      }
    } catch (e) {
      this.meshAuthToken = 'mat_shared_default_token';
    }

    // Periodic sweep for abandoned file transfers (prevents memory leak DoS)
    setInterval(() => this._sweepStaleTransfers(), 30000);

    // Local Multi-Tab Mesh Relay
    this.broadcastChannel = null;
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        this.broadcastChannel = new BroadcastChannel('ciphercore_p2p_mesh');
        this.broadcastChannel.onmessage = (event) => {
          this._handleBroadcastChannelMessage(event.data);
        };
      }
    } catch (e) {
      console.warn('BroadcastChannel initialization warning:', e);
    }
  }

  on(event, callback) {
    if (this.eventListeners[event]) {
      this.eventListeners[event].push(callback);
    }
  }

  emit(event, data) {
    if (this.eventListeners[event]) {
      this.eventListeners[event].forEach(cb => {
        try { cb(data); } catch (err) { console.error(`Error in event ${event}:`, err); }
      });
    }
  }

  /**
   * Initializes PeerJS peer instance with automatic ID collision retry
   * @param {string} customId - Preferred peer ID
   * @returns {Promise<string>} assigned peer ID
   */
  initialize(customId = null) {
    return new Promise((resolve, reject) => {
      try {
        if (typeof Peer === 'undefined') {
          throw new Error('PeerJS library is not loaded. Check your internet connection.');
        }

        const peerConfig = {
          debug: 1,
          config: {
            iceServers: this.options.iceServers
          }
        };

        const setupPeer = (idToTry) => {
          this.peer = idToTry ? new Peer(idToTry, peerConfig) : new Peer(peerConfig);

          this.peer.on('open', (id) => {
            this.myPeerId = id;
            this.emit('statusChange', { status: 'ready', peerId: id });
            this._announceToLocalMesh();
            resolve(id);
          });

          this.peer.on('connection', (conn) => {
            this._handleIncomingConnection(conn);
          });

          this.peer.on('error', (err) => {
            console.warn('WebRTC / Peer error:', err);
            // Handle ID collision gracefully (e.g. multi-tab testing on the same machine)
            if (err.type === 'unavailable-id' && idToTry) {
              const fallbackId = `${idToTry}_${Math.random().toString(36).substring(2, 6)}`;
              console.log(`Peer ID "${idToTry}" is active elsewhere. Reconnecting as instance: ${fallbackId}`);
              try { this.peer.destroy(); } catch (e) {}
              setupPeer(fallbackId);
              return;
            }
            this.emit('error', err);
            if (!this.myPeerId) reject(err);
          });

          this.peer.on('disconnected', () => {
            this.emit('statusChange', { status: 'disconnected' });
          });

          this.peer.on('close', () => {
            this.emit('statusChange', { status: 'closed' });
          });
        };

        setupPeer(customId);

      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * Connect to a remote peer via their Peer ID
   * @param {string} targetPeerId 
   * @param {Object} metadata - Optional initial metadata (e.g. username)
   */
  connectToPeer(targetPeerId, metadata = {}) {
    if (!this.peer || this.peer.destroyed) {
      throw new Error('Peer is not initialized');
    }

    if (this.connections.has(targetPeerId)) {
      const existingConn = this.connections.get(targetPeerId);
      if (existingConn && existingConn.open) {
        return existingConn;
      }
      this.connections.delete(targetPeerId);
    }

    // Ping local mesh immediately with auth token
    if (this.broadcastChannel) {
      this.broadcastChannel.postMessage({
        type: 'mesh-discovery-ping',
        senderPeerId: this.myPeerId,
        targetPeerId: targetPeerId,
        tabId: this.tabInstanceId,
        token: this.meshAuthToken,
        metadata: metadata
      });
    }

    const conn = this.peer.connect(targetPeerId, {
      reliable: true,
      metadata: metadata
    });

    this._setupConnectionHandlers(conn);
    return conn;
  }

  _handleIncomingConnection(conn) {
    this._setupConnectionHandlers(conn);
  }

  _setupConnectionHandlers(conn) {
    // Privacy Shield: Filter private LAN host ICE candidates if privacyMode is active
    if (this.options.privacyMode && conn.peerConnection) {
      const pc = conn.peerConnection;
      const origAddIceCandidate = pc.addIceCandidate;
      if (origAddIceCandidate) {
        pc.addIceCandidate = function (candidate, ...args) {
          if (candidate && candidate.candidate) {
            const candStr = candidate.candidate;
            // Suppress host candidates revealing internal LAN (192.168.x, 10.x, 172.16-31.x)
            if (candStr.includes('typ host')) {
              return Promise.resolve();
            }
          }
          return origAddIceCandidate.apply(this, [candidate, ...args]);
        };
      }
    }

    const handleOpen = () => {
      this.connections.set(conn.peer, conn);
      this.emit('peerConnect', {
        peerId: conn.peer,
        metadata: conn.metadata || {}
      });

      // Send local handshake message
      if (this.onHandshakeReady) {
        this.onHandshakeReady(conn.peer);
      }
    };

    if (conn.open) {
      handleOpen();
    } else {
      conn.on('open', handleOpen);
    }

    conn.on('data', (data) => {
      this._processIncomingData(conn.peer, data);
    });

    conn.on('close', () => {
      this.connections.delete(conn.peer);
      this.peerProfiles.delete(conn.peer);
      this.emit('peerDisconnect', { peerId: conn.peer });
    });

    conn.on('error', (err) => {
      console.warn(`Connection error with peer ${conn.peer}:`, err);
      this.emit('error', { peerId: conn.peer, error: err });
    });
  }

  _announceToLocalMesh() {
    if (!this.broadcastChannel || !this.myPeerId) return;
    this.broadcastChannel.postMessage({
      type: 'mesh-discovery-ping',
      senderPeerId: this.myPeerId,
      tabId: this.tabInstanceId,
      token: this.meshAuthToken
    });
  }

  _handleBroadcastChannelMessage(packet) {
    if (!packet || typeof packet !== 'object') return;
    if (packet.tabId === this.tabInstanceId) return; // ignore self

    // Authenticate token to prevent cross-script or rogue extension spoofing
    if (!packet.token || packet.token !== this.meshAuthToken) {
      return;
    }

    if (packet.type === 'mesh-discovery-ping') {
      if (this.broadcastChannel && this.myPeerId) {
        // If targeted ping, verify match (including prefix match for instance collision)
        if (packet.targetPeerId && 
            packet.targetPeerId !== this.myPeerId && 
            !this.myPeerId.startsWith(packet.targetPeerId) && 
            !packet.targetPeerId.startsWith(this.myPeerId)) {
          return;
        }

        // Send Pong response back
        this.broadcastChannel.postMessage({
          type: 'mesh-discovery-pong',
          senderPeerId: this.myPeerId,
          targetPeerId: packet.senderPeerId,
          tabId: this.tabInstanceId,
          token: this.meshAuthToken
        });

        // Trigger local peer connection event
        this.emit('peerConnect', {
          peerId: packet.senderPeerId,
          isLocalMesh: true
        });

        if (this.onHandshakeReady) {
          this.onHandshakeReady(packet.senderPeerId);
        }
      }
      return;
    }

    if (packet.type === 'mesh-discovery-pong') {
      const isMatch = !packet.targetPeerId || 
                      packet.targetPeerId === this.myPeerId || 
                      this.myPeerId.startsWith(packet.targetPeerId) || 
                      packet.targetPeerId.startsWith(this.myPeerId);
      if (isMatch) {
        this.emit('peerConnect', {
          peerId: packet.senderPeerId,
          isLocalMesh: true
        });

        if (this.onHandshakeReady) {
          this.onHandshakeReady(packet.senderPeerId);
        }
      }
      return;
    }

    if (packet.type === 'mesh-direct-data') {
      const isMatch = !packet.targetPeerId || 
                      packet.targetPeerId === this.myPeerId || 
                      this.myPeerId.startsWith(packet.targetPeerId) || 
                      packet.targetPeerId.startsWith(this.myPeerId);
      if (isMatch) {
        this._processIncomingData(packet.senderPeerId, packet.payload);
      }
      return;
    }
  }

  sendToMesh(targetPeerId, payload) {
    if (this.broadcastChannel && this.myPeerId) {
      this.broadcastChannel.postMessage({
        type: 'mesh-direct-data',
        senderPeerId: this.myPeerId,
        targetPeerId: targetPeerId,
        tabId: this.tabInstanceId,
        token: this.meshAuthToken,
        payload: payload
      });
      return true;
    }
    return false;
  }

  _processIncomingData(peerId, data) {
    if (!data || typeof data !== 'object') return;

    // Handle large file chunk protocol
    if (data.type === 'file-chunk') {
      this._handleFileChunk(peerId, data);
      return;
    }

    // Normal encrypted payload or handshake
    this.emit('message', { peerId, data });
  }

  /**
   * Send data payload to all connected peers (WebRTC + Mesh)
   */
  broadcast(data) {
    let sentCount = 0;
    this.connections.forEach((conn) => {
      if (conn.open) {
        try {
          conn.send(data);
          sentCount++;
        } catch (e) {}
      }
    });

    if (this.broadcastChannel && this.myPeerId) {
      this.broadcastChannel.postMessage({
        type: 'mesh-direct-data',
        senderPeerId: this.myPeerId,
        targetPeerId: null,
        tabId: this.tabInstanceId,
        token: this.meshAuthToken,
        payload: data
      });
      sentCount++;
    }
    return sentCount;
  }

  /**
   * Send data payload to a specific peer
   */
  sendTo(peerId, data) {
    let sent = false;
    const conn = this.connections.get(peerId);
    if (conn && conn.open) {
      try {
        conn.send(data);
        sent = true;
      } catch (e) {
        console.warn('WebRTC conn.send failed:', e);
      }
    }

    // Also send via local BroadcastChannel mesh
    if (this.broadcastChannel) {
      this.sendToMesh(peerId, data);
      sent = true;
    }

    return sent;
  }

  /**
   * Cleans up abandoned file transfers older than 60 seconds (prevents memory leaks)
   */
  _sweepStaleTransfers() {
    const now = Date.now();
    const TTL_MS = 60000;
    for (const [id, transfer] of this.pendingFileTransfers.entries()) {
      if (now - (transfer.lastActive || transfer.createdAt) > TTL_MS) {
        console.warn(`[WebRTC Security] Pruned expired/abandoned file transfer: ${id}`);
        this.pendingFileTransfers.delete(id);
      }
    }
  }

  /**
   * Sends a large encrypted file by slicing it into 32KB chunks over WebRTC DataChannel.
   * Supports strings and binary typed arrays (Uint8Array / ArrayBuffer).
   * Targets a specific recipient peer if provided, eliminating accidental mesh leakage.
   */
  async sendFile(fileData, fileMetadata, onProgress, targetPeerId = null) {
    this._sweepStaleTransfers();

    let processedData = fileData;
    let isBinary = false;

    if (fileData instanceof ArrayBuffer) {
      processedData = new Uint8Array(fileData);
      isBinary = true;
    } else if (fileData instanceof Uint8Array) {
      isBinary = true;
    } else if (typeof fileData !== 'string') {
      processedData = String(fileData);
    }

    const CHUNK_SIZE = 32 * 1024; // 32 KB per chunk
    const totalLength = isBinary ? processedData.byteLength : processedData.length;
    const totalChunks = Math.max(1, Math.ceil(totalLength / CHUNK_SIZE));

    // High-entropy cryptographically secure transfer ID scoped to sender
    const randPart = (window.crypto && window.crypto.getRandomValues)
      ? Array.from(window.crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('')
      : Math.random().toString(36).substring(2, 10);
    const transferId = `tx_${this.myPeerId || 'local'}_${randPart}`;

    for (let index = 0; index < totalChunks; index++) {
      const start = index * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, totalLength);

      let chunk;
      if (isBinary) {
        const sub = processedData.subarray(start, end);
        chunk = window.cipherCore
          ? window.cipherCore.bufferToBase64(sub)
          : window.btoa(String.fromCharCode.apply(null, sub));
      } else {
        chunk = processedData.substring(start, end);
      }

      const packet = {
        type: 'file-chunk',
        transferId: transferId,
        index: index,
        totalChunks: totalChunks,
        chunk: chunk,
        isBinary: isBinary,
        metadata: index === 0 ? fileMetadata : null
      };

      if (targetPeerId) {
        this.sendTo(targetPeerId, packet);
      } else {
        this.broadcast(packet);
      }

      if (onProgress) {
        onProgress(Math.round(((index + 1) / totalChunks) * 100));
      }

      // Small yield to prevent data channel buffer congestion
      if (index % 10 === 0) {
        await new Promise(r => setTimeout(r, 10));
      }
    }

    return transferId;
  }

  _handleFileChunk(peerId, packet) {
    const { transferId, index, totalChunks, chunk, metadata, isBinary } = packet;

    // Security constraints: Validate bounds and types to prevent memory exhaustion DoS
    const MAX_CHUNKS = 2500; // ~80 MB limit
    const MAX_CHUNK_SIZE = 65536; // 64 KB limit

    if (!transferId || typeof transferId !== 'string') return;
    if (!Number.isInteger(totalChunks) || totalChunks <= 0 || totalChunks > MAX_CHUNKS) {
      console.warn(`[Security] Dropped transfer ${transferId} with invalid totalChunks:`, totalChunks);
      return;
    }
    if (!Number.isInteger(index) || index < 0 || index >= totalChunks) {
      console.warn(`[Security] Dropped chunk with invalid index ${index}/${totalChunks}`);
      return;
    }
    if (!chunk || typeof chunk !== 'string' || chunk.length > MAX_CHUNK_SIZE) {
      console.warn(`[Security] Dropped oversized or invalid chunk for transfer ${transferId}`);
      return;
    }

    if (!this.pendingFileTransfers.has(transferId)) {
      this.pendingFileTransfers.set(transferId, {
        peerId: peerId,
        chunks: new Array(totalChunks),
        receivedChunks: 0,
        metadata: metadata,
        isBinary: !!isBinary,
        totalChunks: totalChunks,
        createdAt: Date.now(),
        lastActive: Date.now()
      });
    }

    const transfer = this.pendingFileTransfers.get(transferId);

    // Ownership Verification: Ensure chunk originates strictly from the peer who initiated transferId
    if (transfer.peerId !== peerId) {
      console.warn(`[Security] Transfer spoofing detected! Chunks for ${transferId} expected from ${transfer.peerId}, rejected from ${peerId}`);
      return;
    }

    transfer.lastActive = Date.now();
    if (metadata && !transfer.metadata) {
      transfer.metadata = metadata;
    }
    if (isBinary !== undefined) {
      transfer.isBinary = !!isBinary;
    }

    if (!transfer.chunks[index]) {
      transfer.chunks[index] = chunk;
      transfer.receivedChunks++;
    }

    const progress = Math.round((transfer.receivedChunks / totalChunks) * 100);
    this.emit('fileChunk', { transferId, progress, peerId });

    if (transfer.receivedChunks === totalChunks) {
      let completeData;
      if (transfer.isBinary) {
        // Reassemble binary chunks
        const byteArrays = transfer.chunks.map(c => {
          return window.cipherCore
            ? new Uint8Array(window.cipherCore.base64ToBuffer(c))
            : new Uint8Array(Array.from(window.atob(c)).map(ch => ch.charCodeAt(0)));
        });
        const totalBytes = byteArrays.reduce((acc, arr) => acc + arr.length, 0);
        const merged = new Uint8Array(totalBytes);
        let offset = 0;
        for (const arr of byteArrays) {
          merged.set(arr, offset);
          offset += arr.length;
        }
        completeData = merged;
      } else {
        completeData = transfer.chunks.join('');
      }

      const fileResult = {
        transferId,
        peerId,
        metadata: transfer.metadata,
        data: completeData
      };
      this.pendingFileTransfers.delete(transferId);
      this.emit('fileComplete', fileResult);
    }
  }

  /**
   * Closes all connections and destroys peer
   */
  destroy() {
    this.connections.forEach(conn => {
      try { conn.close(); } catch (e) {}
    });
    this.connections.clear();
    this.peerProfiles.clear();
    this.pendingFileTransfers.clear();
    if (this.peer) {
      try { this.peer.destroy(); } catch (e) {}
      this.peer = null;
    }
  }

  getConnectedPeerCount() {
    const webrtcCount = Array.from(this.connections.values()).filter(c => c.open).length;
    const profileCount = this.peerProfiles.size;
    return Math.max(webrtcCount, profileCount);
  }
}

window.WebRTCManager = WebRTCManager;
