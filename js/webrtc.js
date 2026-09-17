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

    this.pendingFileTransfers = new Map(); // transferId -> { name, size, type, chunks, receivedBytes, totalChunks }
    this.tabInstanceId = 'tab_' + Math.random().toString(36).substring(2, 9);

    // Local Multi-Tab Mesh Relay (instant zero-server communication between tabs on same browser/origin)
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
      return this.connections.get(targetPeerId);
    }

    // Ping local mesh immediately
    if (this.broadcastChannel) {
      this.broadcastChannel.postMessage({
        type: 'mesh-discovery-ping',
        senderPeerId: this.myPeerId,
        targetPeerId: targetPeerId,
        tabId: this.tabInstanceId,
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
      tabId: this.tabInstanceId
    });
  }

  _handleBroadcastChannelMessage(packet) {
    if (!packet || typeof packet !== 'object') return;
    if (packet.tabId === this.tabInstanceId) return; // ignore self

    if (packet.type === 'mesh-discovery-ping') {
      if (this.broadcastChannel && this.myPeerId) {
        // Send Pong response back
        this.broadcastChannel.postMessage({
          type: 'mesh-discovery-pong',
          senderPeerId: this.myPeerId,
          targetPeerId: packet.senderPeerId,
          tabId: this.tabInstanceId
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
      if (packet.targetPeerId === this.myPeerId || !packet.targetPeerId) {
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
      if (packet.targetPeerId === this.myPeerId || !packet.targetPeerId) {
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
   * Sends a large encrypted file by slicing it into 32KB chunks over WebRTC DataChannel
   */
  async sendFile(fileData, fileMetadata, onProgress) {
    const CHUNK_SIZE = 32 * 1024; // 32 KB per chunk
    const transferId = 'tx_' + Math.random().toString(36).substring(2, 9);
    const totalChunks = Math.ceil(fileData.length / CHUNK_SIZE);

    for (let index = 0; index < totalChunks; index++) {
      const start = index * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileData.length);
      const chunk = fileData.substring(start, end);

      const packet = {
        type: 'file-chunk',
        transferId: transferId,
        index: index,
        totalChunks: totalChunks,
        chunk: chunk,
        metadata: index === 0 ? fileMetadata : null
      };

      this.broadcast(packet);

      if (onProgress) {
        onProgress(Math.round(((index + 1) / totalChunks) * 100));
      }

      // Small throttling yield to prevent channel buffer overflow
      if (index % 10 === 0) {
        await new Promise(r => setTimeout(r, 10));
      }
    }

    return transferId;
  }

  _handleFileChunk(peerId, packet) {
    const { transferId, index, totalChunks, chunk, metadata } = packet;

    if (!this.pendingFileTransfers.has(transferId)) {
      this.pendingFileTransfers.set(transferId, {
        peerId: peerId,
        chunks: new Array(totalChunks),
        receivedChunks: 0,
        metadata: metadata,
        totalChunks: totalChunks
      });
    }

    const transfer = this.pendingFileTransfers.get(transferId);
    if (metadata && !transfer.metadata) {
      transfer.metadata = metadata;
    }

    if (!transfer.chunks[index]) {
      transfer.chunks[index] = chunk;
      transfer.receivedChunks++;
    }

    const progress = Math.round((transfer.receivedChunks / totalChunks) * 100);
    this.emit('fileChunk', { transferId, progress, peerId });

    if (transfer.receivedChunks === totalChunks) {
      // Reassemble complete payload
      const completeData = transfer.chunks.join('');
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
