#!/usr/bin/env node

/**
 * Single-file JavaScript port of the Python Messenger client.
 * Supports HTTP polling and WebSocket transports, plus remote port forwarding.
 * Uses binary framing identical to the Python implementation, with AES-256-CBC encryption for payloads.
 *
 * Dependencies: npm install ws axios
 */

const WebSocket = require('ws');
const axios = require('axios');
const https = require('https');
const { randomBytes, createHash, createCipheriv, createDecipheriv } = require('crypto');
const net = require('net');
const { argv, exit } = require('process');

// --- AES helpers (AES-256-CBC with random IV prefix) ---
function encrypt(key, buf) {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, enc]);
}

function decrypt(key, buf) {
  const iv = buf.slice(0, 16);
  const data = buf.slice(16);
  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// --- Message type constants to match Python ---
const TYPE = {
  INITIATE_FORWARDER_CLIENT_REQ: 0x01,
  INITIATE_FORWARDER_CLIENT_REP: 0x02,
  SEND_DATA: 0x03,
  CHECK_IN: 0x04
};

// --- Helpers for length-prefixed strings ---
function buildString(s) {
  const buf = Buffer.from(s, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

function readString(buf, offset) {
  const len = buf.readUInt32BE(offset);
  const start = offset + 4;
  return [buf.slice(start, start + len).toString('utf8'), start + len];
}

// --- MessageBuilder: framing + encryption ---
class MessageBuilder {
  static serialize(msg, key) {
    let type, body;
    switch (msg.constructor.name) {
      case 'InitiateForwarderClientReq':
        type = TYPE.INITIATE_FORWARDER_CLIENT_REQ;
        body = Buffer.concat([
          buildString(msg.forwarder_client_id),
          buildString(msg.ip_address),
          (() => { const b = Buffer.alloc(4); b.writeUInt32BE(msg.port); return b; })()
        ]);
        body = encrypt(key, body);
        break;
      case 'InitiateForwarderClientRep':
        type = TYPE.INITIATE_FORWARDER_CLIENT_REP;
        body = Buffer.concat([
          buildString(msg.forwarder_client_id),
          buildString(msg.bind_address),
          (() => { const b = Buffer.alloc(4); b.writeUInt32BE(msg.bind_port); return b; })(),
          (() => { const b = Buffer.alloc(4); b.writeUInt32BE(msg.address_type); return b; })(),
          (() => { const b = Buffer.alloc(4); b.writeUInt32BE(msg.reason); return b; })()
        ]);
        body = encrypt(key, body);
        break;
      case 'SendDataMessage':
        type = TYPE.SEND_DATA;
        const encoded = Buffer.from(msg.data).toString('base64');
        body = Buffer.concat([ buildString(msg.forwarder_client_id), buildString(encoded) ]);
        body = encrypt(key, body);
        break;
      case 'CheckInMessage':
        type = TYPE.CHECK_IN;
        body = buildString(msg.messenger_id);
        break;
      default:
        throw new Error(`Unknown message ${msg.constructor.name}`);
    }
    const header = Buffer.alloc(8);
    header.writeUInt32BE(type, 0);
    header.writeUInt32BE(8 + body.length, 4);
    return Buffer.concat([header, body]);
  }
}

// --- MessageParser: header, decryption, unpack ---
class MessageParser {
  static deserialize(key, buffer) {
    const out = [];
    let buf = buffer;
    while (buf.length >= 8) {
      const type = buf.readUInt32BE(0);
      const length = buf.readUInt32BE(4);
      if (buf.length < length) break;
      let payload = buf.slice(8, length);
      buf = buf.slice(length);
      let plain = payload;
      if (type !== TYPE.CHECK_IN) plain = decrypt(key, payload);
      let msg;
      let offset = 0;
      switch (type) {
        case TYPE.CHECK_IN: {
          const [id] = readString(plain, 0);
          msg = new CheckInMessage(id);
          break;
        }
        case TYPE.INITIATE_FORWARDER_CLIENT_REQ: {
          const [id, o1] = readString(plain, 0);
          const [ip, o2] = readString(plain, o1);
          const port = plain.readUInt32BE(o2);
          msg = new InitiateForwarderClientReq(id, ip, port);
          break;
        }
        case TYPE.INITIATE_FORWARDER_CLIENT_REP: {
          let o = 0;
          const [id, o1] = readString(plain, o);
          const [baddr, o2] = readString(plain, o1);
          const bport = plain.readUInt32BE(o2); o2 += 4;
          const atype = plain.readUInt32BE(o2); o2 += 4;
          const reason = plain.readUInt32BE(o2);
          msg = new InitiateForwarderClientRep({ forwarder_client_id: id, bind_address: baddr, bind_port: bport, address_type: atype, reason });
          break;
        }
        case TYPE.SEND_DATA: {
          const [id, o1] = readString(plain, 0);
          const [enc, o2] = readString(plain, o1);
          const data = Buffer.from(enc, 'base64');
          msg = new SendDataMessage(id, data);
          break;
        }
        default:
          console.log(`Unknown type: 0x${type.toString(16)}`);
          continue;
      }
      out.push(msg);
    }
    return out;
  }
}

// --- Message Classes ---
class CheckInMessage    { constructor(messenger_id) { this.messenger_id = messenger_id; } }
class InitiateForwarderClientReq { constructor(id, ip, port) { this.forwarder_client_id = id; this.ip_address = ip; this.port = port; } }
class InitiateForwarderClientRep { constructor({ forwarder_client_id, bind_address, bind_port, address_type, reason }) { Object.assign(this, { forwarder_client_id, bind_address, bind_port, address_type, reason }); } }
class SendDataMessage    { constructor(id, data)     { this.forwarder_client_id = id; this.data = data; } }

// --- Base MessengerClient ---
class MessengerClient {
  constructor(key) { this.key = key; this.forwarderClients = new Map(); this.identifier = null; }
  serialize(msgs) { return Buffer.concat(msgs.map(m => MessageBuilder.serialize(m, this.key))); }
  deserialize(buf) { return MessageParser.deserialize(this.key, buf); }
  async handleMessage(msg) {
    if (msg instanceof InitiateForwarderClientReq) {
      await this.handleInitiateForwarderClientReq(msg);
    } else if (msg instanceof InitiateForwarderClientRep) {
      this.stream(msg.forwarder_client_id);
    } else if (msg instanceof SendDataMessage) {
      const c = this.forwarderClients.get(msg.forwarder_client_id);
      if (c) c.socket.write(msg.data);
    }
  }
  async handleInitiateForwarderClientReq(msg) {
    let reason = 0, bAddr = '0.0.0.0', bPort = 0, aType = 1;
    try {
      const sock = net.createConnection({ host: msg.ip_address, port: msg.port, timeout: 5000 });
      await new Promise((res, rej) => sock.once('connect', res).once('error', rej));
      bAddr = sock.localAddress; bPort = sock.localPort;
      aType = sock.remoteFamily === 'IPv6' ? 4 : 1;
      this.forwarderClients.set(msg.forwarder_client_id, { socket: sock });
      this.stream(msg.forwarder_client_id);
    } catch {
      reason = 1;
    }
    const rep = new InitiateForwarderClientRep({ forwarder_client_id: msg.forwarder_client_id, bind_address: bAddr, bind_port: bPort, address_type: aType, reason });
    await this.sendDownstreamMessages([rep]);
  }
  async sendDownstreamMessages(msgs) {}
  async stream(id) {}
}

// --- WebSocketClient ---
class WebSocketClient extends MessengerClient {
  constructor(url, key, remotes, proxy) { super(key); this.serverUrl = url; this.remoteForwards = remotes; this.proxy = proxy; this.ws = null; }
  async connect() {
    await Promise.all(this.remoteForwards.map(cfg => new RemotePortForwarder(this, cfg).start()));
    this.ws = new WebSocket(this.serverUrl, { agent: this.proxy ? new https.Agent({ proxy: this.proxy }) : undefined });
    await new Promise((res, rej) => this.ws.once('open', res).once('error', rej));
    const init = new CheckInMessage('');
    this.ws.send(this.serialize([init]));
    const msg = await new Promise(r => this.ws.once('message', r));
    this.identifier = this.deserialize(Buffer.from(msg))[0].messenger_id;
  }
  async start() {
    this.ws.on('message', data => this.deserialize(Buffer.from(data)).forEach(m => this.handleMessage(m)));
    this.ws.on('close', () => setTimeout(() => this.connect().then(() => this.start()), 15000));
    await new Promise(() => {});
  }
  async sendDownstreamMessages(msgs) { this.ws.send(this.serialize([new CheckInMessage(this.identifier), ...msgs])); }
  async stream(clientId) {
    const c = this.forwarderClients.get(clientId);
    c.socket.on('data', d => this.sendDownstreamMessages([new SendDataMessage(clientId, d)]));
    c.socket.on('end', () => {
      this.sendDownstreamMessages([new SendDataMessage(clientId, Buffer.alloc(0))]);
      this.forwarderClients.delete(clientId);
    });
  }
}

// --- HTTPClient ---
class HTTPClient extends MessengerClient {
  constructor(url, key, remotes, proxy) { super(key); this.serverUrl = url; this.remoteForwards = remotes; this.proxy = proxy; this.queue = []; }
  async connect() {
    await Promise.all(this.remoteForwards.map(cfg => new RemotePortForwarder(this, cfg).start()));
    const init = new CheckInMessage('');
    const resp = await axios.post(this.serverUrl, this.serialize([init]), { responseType: 'arraybuffer', proxy: this.proxy });
    this.identifier = this.deserialize(Buffer.from(resp.data))[0].messenger_id;
  }
  async start() {
    setInterval(async () => {
      const toSend = [new CheckInMessage(this.identifier), ...this.queue];
      this.queue = [];
      try {
        const resp = await axios.post(this.serverUrl, this.serialize(toSend), { responseType: 'arraybuffer', proxy: this.proxy });
        this.deserialize(Buffer.from(resp.data)).forEach(m => this.handleMessage(m));
      } catch {
        console.log('[!] HTTP polling error');
      }
    }, 1000);
  }
  async sendDownstreamMessages(msgs) { this.queue.push(...msgs); }
  async stream(clientId) {
    const c = this.forwarderClients.get(clientId);
    c.socket.on('data', d => this.sendDownstreamMessages([new SendDataMessage(clientId, d)]));
    c.socket.on('end', () => {
      this.sendDownstreamMessages([new SendDataMessage(clientId, Buffer.alloc(0))]);
      this.forwarderClients.delete(clientId);
    });
  }
}

// --- RemotePortForwarder ---
class RemotePortForwarder {
  constructor(messenger, config) { [this.host, this.port, this.dstHost, this.dstPort] = config.split(':'); this.messenger = messenger; this.id = randomBytes(4).toString('hex'); }
  start() {
    return new Promise(res => net.createServer(socket => {
      const cid = randomBytes(4).toString('hex');
      this.messenger.handleMessage(new InitiateForwarderClientReq(cid, this.dstHost, parseInt(this.dstPort)));
      this.messenger.forwarderClients.set(cid, { socket });
    }).listen(parseInt(this.port), this.host, () => { console.log(`Forwarder ${this.id} listening on ${this.host}:${this.port}`); res(); }));
  }
}

// --- Main Messenger ---
class Messenger {
  constructor(url, key, remotes, proxy, contAfter) { this.serverUrl = url; this.key = key; this.remotes = remotes; this.proxy = proxy; this.contAfter = contAfter; this.connected = false; }
  async start() {
    const schemes = this.serverUrl.includes('://') ? this.serverUrl.split('://')[0].split('+') : ['ws','http','wss','https'];
    const target = this.serverUrl.replace(/.*?:\/\//, '');
    for (const s of schemes) {
      if (this.connected && !this.contAfter) break;
      const base = `${s.startsWith('wss')? 'https': s}://${target}/`;
      if (s.includes('http')) console.log(`[*] Trying HTTP ${base}socketio/?EIO=4&transport=polling`), await this.tryHTTP(`${base}socketio/?EIO=4&transport=polling`);
      if (s.includes('ws')) console.log(`[*] Trying WS ${base}socketio/?EIO=4&transport=websocket`), await this.tryWS(`${base}socketio/?EIO=4&transport=websocket`);
    }
    console.log('Messenger stopped');
  }
  async tryWS(uri) { try { const c = new WebSocketClient(uri,this.key,this.remotes,this.proxy); await c.connect(); console.log(`[+] WS connected: ${uri}`); this.connected=true; await c.start(); } catch { console.log('[!] WS failed'); } }
  async tryHTTP(uri) { try { const c = new HTTPClient(uri,this.key,this.remotes,this.proxy); await c.connect(); console.log(`[+] HTTP connected: ${uri}`); this.connected=true; await c.start(); } catch { console.log('[!] HTTP failed'); } }
}

// --- CLI Entry Point ---
(async()=>{
  const [, , serverUrl, keyHex, ...rest] = argv;
  if (!serverUrl || !keyHex) { console.error('Usage: node messengerClient.js <server_url> <hex_key> [forwards...]'); exit(1); }
  let key;
  if (/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    key = Buffer.from(keyHex, 'hex');
  } else {
    // Derive a 32-byte AES key by hashing the passphrase
    key = createHash('sha256').update(keyHex).digest();
  }
  const messenger = new Messenger(serverUrl, key, rest, null, false);
  await messenger.start();
})();
