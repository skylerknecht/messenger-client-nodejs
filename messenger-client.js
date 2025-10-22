#!/usr/bin/env node
/**
 * Messenger Client (Node.js)
 *
 * Features:
 * - AES-256-CBC (random IV prepended)
 * - Framing: [u32 type][u32 len=8+payload][payload]
 * - Strings: [u32 len][utf8 bytes]
 * - Messages:
 *    0x01 InitiateForwarderClientReq(forwarder_client_id, ip, port)  -- encrypted
 *    0x02 InitiateForwarderClientRep(forwarder_client_id, bind_addr, bind_port, address_type, reason) -- encrypted
 *    0x03 SendDataMessage(forwarder_client_id, base64(data)) -- encrypted
 *    0x04 CheckInMessage(messenger_id) -- plaintext
 * - RemotePortForwarder "host:port:dst_host:dst_port"
 *
 * Requires: npm i ws https-proxy-agent
 * (https-proxy-agent is only needed if you pass --proxy)
 */

const crypto = require('crypto');
const net = require('net');
const { URL } = require('url');
const WebSocket = require('ws');
let HttpsProxyAgent; // loaded on demand

// ---------- Utils ----------
function sha256Bytes(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest();
}
function beU32(n) {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}
function readU32(buf, off) {
  return buf.readUInt32BE(off);
}
function packString(str) {
  const b = Buffer.from(str, 'utf8');
  return Buffer.concat([beU32(b.length), b]);
}
function readString(buf, off) {
  const len = readU32(buf, off);
  const start = off + 4;
  const end = start + len;
  return { value: buf.toString('utf8', start, end), next: end };
}
function xorBuffers(a, b) {
  const out = Buffer.allocUnsafe(Math.min(a.length, b.length));
  for (let i = 0; i < out.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ---------- Crypto (AES-256-CBC w/ random IV prefix) ----------
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

// ---------- Message Builders ----------
const TYPE = {
  InitiateForwarderClientReq: 0x01,
  InitiateForwarderClientRep: 0x02,
  SendDataMessage: 0x03,
  CheckInMessage: 0x04,
};

// Plaintext (CheckIn)
function buildCheckInMessage(messenger_id) {
  return packString(messenger_id);
}

// Encrypted payloads (we encrypt the inner struct)
function buildInitiateForwarderClientReq(forwarder_client_id, ip, port) {
  return Buffer.concat([packString(forwarder_client_id), packString(ip), beU32(port)]);
}
function buildInitiateForwarderClientRep(forwarder_client_id, bind_addr, bind_port, address_type, reason) {
  return Buffer.concat([packString(forwarder_client_id), packString(bind_addr), beU32(bind_port), beU32(address_type), beU32(reason)]);
}
function buildSendData(forwarder_client_id, dataBuf) {
  const b64 = Buffer.from(dataBuf).toString('base64');
  return Buffer.concat([packString(forwarder_client_id), packString(b64)]);
}

// Frame: [type][len=8+payload][payload]
function frameMessage(type, payload) {
  const len = 8 + payload.length;
  return Buffer.concat([beU32(type), beU32(len), payload]);
}

// ---------- Message Parser ----------
function parseMessages(encryptionKey, buf) {
  const messages = [];
  let off = 0;

  while (off + 8 <= buf.length) {
    const type = readU32(buf, off);
    const msgLen = readU32(buf, off + 4);
    if (off + msgLen > buf.length) break;

    const payload = buf.subarray(off + 8, off + msgLen);
    let parsed;

    if (type === TYPE.CheckInMessage) {
      let p = 0;
      const { value: messenger_id } = readString(payload, p);
      parsed = { type, messenger_id };
    } else if (type === TYPE.InitiateForwarderClientReq) {
      const dec = decrypt(encryptionKey, payload);
      let p = 0;
      const { value: forwarder_client_id, next: n1 } = readString(dec, p);
      const { value: ip, next: n2 } = readString(dec, n1);
      const port = dec.readUInt32BE(n2);
      parsed = { type, forwarder_client_id, ip, port };
    } else if (type === TYPE.InitiateForwarderClientRep) {
      const dec = decrypt(encryptionKey, payload);
      let p = 0;
      const a = readString(dec, p);
      const b = readString(dec, a.next);
      const bind_port = dec.readUInt32BE(b.next);
      const address_type = dec.readUInt32BE(b.next + 4);
      const reason = dec.readUInt32BE(b.next + 8);
      parsed = {
        type,
        forwarder_client_id: a.value,
        bind_addr: b.value,
        bind_port,
        address_type,
        reason,
      };
    } else if (type === TYPE.SendDataMessage) {
      const dec = decrypt(encryptionKey, payload);
      let p = 0;
      const { value: forwarder_client_id, next: n1 } = readString(dec, p);
      const { value: b64 } = readString(dec, n1);
      parsed = { type, forwarder_client_id, data: Buffer.from(b64, 'base64') };
    } else {
      throw new Error(`Unknown message type: 0x${type.toString(16)}`);
    }

    messages.push(parsed);
    off += msgLen;
  }

  return { messages, leftover: buf.subarray(off) };
}

// ---------- Serialize helpers ----------
function serializeMessage(encryptionKey, msg) {
  if (msg.type === TYPE.CheckInMessage) {
    return frameMessage(TYPE.CheckInMessage, buildCheckInMessage(msg.messenger_id));
  }
  if (msg.type === TYPE.InitiateForwarderClientReq) {
    const inner = buildInitiateForwarderClientReq(msg.forwarder_client_id, msg.ip, msg.port);
    return frameMessage(TYPE.InitiateForwarderClientReq, encrypt(encryptionKey, inner));
  }
  if (msg.type === TYPE.InitiateForwarderClientRep) {
    const inner = buildInitiateForwarderClientRep(msg.forwarder_client_id, msg.bind_addr, msg.bind_port, msg.address_type, msg.reason);
    return frameMessage(TYPE.InitiateForwarderClientRep, encrypt(encryptionKey, inner));
  }
  if (msg.type === TYPE.SendDataMessage) {
    const inner = buildSendData(msg.forwarder_client_id, msg.data);
    return frameMessage(TYPE.SendDataMessage, encrypt(encryptionKey, inner));
  }
  throw new Error(`Unknown message object type: ${msg.type}`);
}

function serializeMessages(encryptionKey, arr) {
  return Buffer.concat(arr.map(m => serializeMessage(encryptionKey, m)));
}

// ---------- Client ----------
class Client {
  constructor(serverEndpoint, encryptionKey, userAgent, proxy, remotePortForwards) {
    this.serverEndpoint = serverEndpoint;
    this.encryptionKey = encryptionKey;
    this.headers = { 'User-Agent': userAgent };
    this.proxy = proxy || '';
    this.identifier = '';
    this.forwarderClients = new Map(); // id -> net.Socket
    this.remotePortForwards = remotePortForwards || [];
    this.leftover = Buffer.alloc(0);
    this.ws = null;
  }

  async connect() {
    // Proxy agent if provided
    let agent = undefined;
    if (this.proxy) {
      if (!HttpsProxyAgent) {
        try { HttpsProxyAgent = require('https-proxy-agent'); }
        catch {
          console.error('Install https-proxy-agent to use --proxy');
          process.exit(2);
        }
      }
      agent = new HttpsProxyAgent.HttpsProxyAgent(this.proxy);
    }

    // ws options: rejectUnauthorized=false to mimic Python’s insecure SSL
    const wsOpts = {
      headers: this.headers,
      agent,
      rejectUnauthorized: false,
      perMessageDeflate: false,
    };

    this.ws = new WebSocket(this.serverEndpoint, wsOpts);
    await new Promise((res, rej) => {
      this.ws.once('open', res);
      this.ws.once('error', rej);
    });

    // Check-in (empty id)
    const checkIn = serializeMessages(this.encryptionKey, [{ type: TYPE.CheckInMessage, messenger_id: '' }]);
    this.ws.send(checkIn);

    // First message should include a CheckIn back with assigned messenger_id
    const first = await this._readOnce();
    const { messages } = parseMessages(this.encryptionKey, first);
    if (!messages.length || messages[0].type !== TYPE.CheckInMessage) {
      throw new Error(`Expected CheckInMessage, got ${messages[0] ? messages[0].type : 'nothing'}`);
    }
    this.identifier = messages[0].messenger_id;
    console.log(`Connected to ${this.serverEndpoint} as ${this.identifier}`);

    // Start remote listeners
    await Promise.all(this.remotePortForwards.map(cfg => new RemotePortForwarder(this, cfg).start()));
  }

  async start() {
    this.ws.on('message', (data, isBinary) => {
      const buf = isBinary ? data : Buffer.from(data);
      this.leftover = Buffer.concat([this.leftover, buf]);
      try {
        let parsed;
        do {
          parsed = parseMessages(this.encryptionKey, this.leftover);
          this.leftover = parsed.leftover;
          for (const m of parsed.messages) this.handleMessage(m).catch(() => {});
        } while (parsed.messages.length > 0);
      } catch (e) {
        console.error('Parse error:', e.message);
        // If framing breaks, drop buffer to avoid infinite loop
        this.leftover = Buffer.alloc(0);
      }
    });

    await new Promise((resolve, reject) => {
      this.ws.on('close', resolve);
      this.ws.on('error', reject);
    });
  }

  async _readOnce() {
    return await new Promise((resolve, reject) => {
      const onMsg = (data, isBinary) => {
        this.ws.off('error', onErr);
        resolve(isBinary ? data : Buffer.from(data));
      };
      const onErr = (e) => {
        this.ws.off('message', onMsg);
        reject(e);
      };
      this.ws.once('message', onMsg);
      this.ws.once('error', onErr);
    });
  }

  async handleMessage(message) {
    switch (message.type) {
      case TYPE.InitiateForwarderClientReq:
        await this._handleInitiateForwarderClientReq(message);
        break;
      case TYPE.InitiateForwarderClientRep:
        // Server replied with bind info — begin reading local socket stream (if not already)
        this._startStream(message.forwarder_client_id);
        break;
      case TYPE.SendDataMessage: {
        const sock = this.forwarderClients.get(message.forwarder_client_id);
        if (!sock) return;
        if (message.data.length === 0) {
          try { sock.end(); } catch {}
          this.forwarderClients.delete(message.forwarder_client_id);
        } else {
          sock.write(message.data);
        }
        break;
      }
      default:
        console.log(`Received unknown message type: ${message.type}`);
    }
  }

  async _handleInitiateForwarderClientReq({ forwarder_client_id, ip, port }) {
    let reason = 0;
    let sock = null;
    try {
      sock = await connectTcp(ip, port, 5000);
      this.forwarderClients.set(forwarder_client_id, sock);

      const bind = sock.address();
      const bind_addr = (typeof bind.address === 'string') ? bind.address : '0.0.0.0';
      const bind_port = bind.port || 0;
      const address_type = (sock.remoteFamily === 'IPv6' || bind.family === 'IPv6') ? 4 : 1; // 1=IPv4, 4=IPv6 per your code

      await this._sendDownstream({
        type: TYPE.InitiateForwarderClientRep,
        forwarder_client_id,
        bind_addr,
        bind_port,
        address_type,
        reason: 0,
      });

      // begin stream up to server
      this._startStream(forwarder_client_id);
    } catch (e) {
      reason = mapSocketErrorToReason(e);
      await this._sendDownstream({
        type: TYPE.InitiateForwarderClientRep,
        forwarder_client_id,
        bind_addr: '0.0.0.0',
        bind_port: 0,
        address_type: 1,
        reason,
      });
      if (sock) { try { sock.destroy(); } catch {} }
    }
  }

  _startStream(forwarder_client_id) {
    const sock = this.forwarderClients.get(forwarder_client_id);
    if (!sock) return;

    sock.on('data', async (chunk) => {
      await this._sendDownstream({
        type: TYPE.SendDataMessage,
        forwarder_client_id,
        data: chunk,
      });
    });

    const ender = async () => {
      try {
        await this._sendDownstream({
          type: TYPE.SendDataMessage,
          forwarder_client_id,
          data: Buffer.alloc(0),
        });
      } finally {
        this.forwarderClients.delete(forwarder_client_id);
      }
    };

    sock.once('end', ender);
    sock.once('close', ender);
    sock.once('error', ender);
  }

  async _sendDownstream(downstreamMessage) {
    const pkt = serializeMessages(this.encryptionKey, [
      { type: TYPE.CheckInMessage, messenger_id: this.identifier },
      downstreamMessage,
    ]);
    this.ws.send(pkt);
  }
}

// ---------- Remote Port Forwarder ----------
class RemotePortForwarder {
  constructor(messenger, config) {
    this.messenger = messenger;
    const [listenHost, listenPort, dstHost, dstPort] = this.parseConfig(config);
    this.listening_host = listenHost;
    this.listening_port = Number(listenPort);
    this.destination_host = dstHost;
    this.destination_port = Number(dstPort);
    this.identifier = randomAlphaNum(10);
  }

  parseConfig(config) {
    // "<host>:<port>:<dst_host>:<dst_port>"
    const parts = String(config).split(':');
    if (parts.length < 4) throw new Error(`Bad remote port forward config: ${config}`);
    return parts;
  }

  async start() {
    await new Promise((resolve) => {
      const server = net.createServer(async (socket) => {
        const forwarder_client_id = randomAlphaNum(10);
        // Register socket
        this.messenger.forwarderClients.set(forwarder_client_id, socket);

        // Tell server to initiate a connection to destination
        await this.messenger._sendDownstream({
          type: TYPE.InitiateForwarderClientReq,
          forwarder_client_id,
          ip: this.destination_host,
          port: this.destination_port,
        });

        // When client socket receives data, we stream *after* we get Rep, but buffering early is okay
        // We rely on Client._startStream being called upon Rep or immediately if already present

        socket.on('error', () => {});
      });

      server.on('listening', () => {
        const addr = server.address();
        console.log(`Remote Port Forwarder ${this.identifier} listening on ${addr.address}:${addr.port}`);
        resolve();
      });
      server.on('error', (e) => {
        console.error(`${this.listening_host}:${this.listening_port} is already in use or failed:`, e.message);
        resolve();
      });

      server.listen(this.listening_port, this.listening_host);
    });
  }
}

// ---------- TCP connector helper ----------
function connectTcp(host, port, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port }, () => resolve(sock));
    const to = setTimeout(() => {
      try { sock.destroy(); } catch {}
      const err = new Error('ETIMEDOUT');
      err.code = 'ETIMEDOUT';
      reject(err);
    }, timeoutMs);

    sock.once('error', (e) => {
      clearTimeout(to);
      reject(e);
    });
    sock.once('connect', () => clearTimeout(to));
  });
}
function mapSocketErrorToReason(e) {
  // Mirror Python mapping as closely as possible
  const code = e.code || '';
  switch (code) {
    case 'ENETUNREACH': return 3;
    case 'EHOSTUNREACH': return 4;
    case 'ECONNREFUSED': return 5;
    case 'ETIMEDOUT': return 6;
    case 'ENOPROTOOPT': return 7;
    case 'EAFNOSUPPORT': return 8;
    default: return 1;
  }
}

// ---------- ID helpers ----------
const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const alnum = alpha + '0123456789';
function randomAlphaNum(n = 10) {
  let out = '';
  for (let i = 0; i < n; i++) out += alnum[(Math.random() * alnum.length) | 0];
  return out;
}

// ---------- CLI ----------
const DEFAULTS = {
  SERVER: 'ws://147.182.186.124:8080',
  ENC_KEY: 'skyler',
  UA: 'help',
  PROXY: '',
  RPF: [], // array of "host:port:dst_host:dst_port"
};

function parseArgs(argv) {
  const args = {
    server: null,
    encryptionKey: null,
    userAgent: null,
    proxy: null,
    remotePortForwards: [],
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--server') args.server = argv[++i];
    else if (a === '--encryption-key') args.encryptionKey = argv[++i];
    else if (a === '--user-agent') args.userAgent = argv[++i];
    else if (a === '--proxy') args.proxy = argv[++i];
    else if (a === '--remote-port-forwards') {
      // consume until next flag or end
      while (argv[i + 1] && !argv[i + 1].startsWith('--')) {
        args.remotePortForwards.push(argv[++i]);
      }
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);

  let server = (args.server || DEFAULTS.SERVER).replace(/\/+$/, '') + '/socketio/?EIO=4&transport=websocket';
  // If it's http(s), convert to ws(s)
  try {
    const u = new URL(server);
    if (u.protocol === 'http:') u.protocol = 'ws:';
    if (u.protocol === 'https:') u.protocol = 'wss:';
    server = u.toString();
  } catch {}

  const encryptionKey = sha256Bytes(args.encryptionKey || DEFAULTS.ENC_KEY);
  const userAgent = args.userAgent || DEFAULTS.UA;
  const proxy = args.proxy || DEFAULTS.PROXY;
  const remotePortForwards = (args.remotePortForwards && args.remotePortForwards.length)
    ? args.remotePortForwards
    : DEFAULTS.RPF;

  const client = new Client(server, encryptionKey, userAgent, proxy, remotePortForwards);

  process.on('SIGINT', () => {
    process.stdout.write('\rShutdown\n');
    try { client.ws && client.ws.close(); } catch {}
    process.exit(0);
  });

  await client.connect();
  await client.start();
}

if (require.main === module) {
  main().catch(err => {
    console.error(err?.stack || err?.message || String(err));
    process.exit(1);
  });
}
