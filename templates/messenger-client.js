const crypto = require('crypto');
const assert = require('assert');
const net = require('net');
const http = require('http');
const https = require('https');

let wsImported = false;
try {
  WebSocket = require('ws');
  wsImported = true;
} catch {
  console.warn('[!] Failed to import "ws" module — WebSocket support disabled.');
}
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

/* Message Structures */

const MSG = {
  INIT_FWD_REQ: 0x01,
  INIT_FWD_REP: 0x02,
  SEND_DATA:    0x03,
  CHECK_IN:     0x04,
};

const CheckInMessage = (messenger_id) => ({ kind: 'CheckInMessage', messenger_id });
const InitiateForwarderClientReq = (forwarder_client_id, ip_address, port) => ({ kind: 'InitiateForwarderClientReq', forwarder_client_id, ip_address, port });
const InitiateForwarderClientRep = (forwarder_client_id, bind_address, bind_port, address_type, reason) => ({ kind: 'InitiateForwarderClientRep', forwarder_client_id, bind_address, bind_port, address_type, reason });
const SendDataMessage = (forwarder_client_id, data) => ({ kind: 'SendDataMessage', forwarder_client_id, data });

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

  static parseInitiateForwarderClientReq(value) {
    let v = value;
    let forwarder_client_id, ip_address, port;
    [forwarder_client_id, v] = MessageParser.readString(v);
    [ip_address, v] = MessageParser.readString(v);
    [port, v] = MessageParser.readUint32(v);
    return InitiateForwarderClientReq(forwarder_client_id, ip_address, port);
  }

  static parseInitiateForwarderClientRep(value) {
    let v = value;
    let forwarder_client_id, bind_address, bind_port, address_type, reason;
    [forwarder_client_id, v] = MessageParser.readString(v);
    [bind_address, v] = MessageParser.readString(v);
    [bind_port, v] = MessageParser.readUint32(v);
    [address_type, v] = MessageParser.readUint32(v);
    [reason, v] = MessageParser.readUint32(v);
    return InitiateForwarderClientRep(forwarder_client_id, bind_address, bind_port, address_type, reason);
  }

  static parseSendData(value) {
    let v = value;
    let forwarder_client_id, encoded_data;
    [forwarder_client_id, v] = MessageParser.readString(v);
    [encoded_data, v] = MessageParser.readString(v);
    const raw = Buffer.from(encoded_data, 'base64');
    return SendDataMessage(forwarder_client_id, raw);
  }

  static deserializeMessage(encryptionKey, raw) {
    let data = raw;
    const [message_type, afterType] = MessageParser.readUint32(data);
    const [message_length, afterLen] = MessageParser.readUint32(afterType);
    const payload_len = message_length - 8;
    if (afterLen.length < payload_len) throw new Error('Not enough bytes in data for the payload');
    const payload = afterLen.subarray(0, payload_len);
    const leftover = afterLen.subarray(payload_len);
    let parsed;
    switch (message_type) {
      case MSG.INIT_FWD_REQ: {
        const decrypted = decrypt(encryptionKey, payload);
        parsed = MessageParser.parseInitiateForwarderClientReq(decrypted);
        break;
      }
      case MSG.INIT_FWD_REP: {
        const decrypted = decrypt(encryptionKey, payload);
        parsed = MessageParser.parseInitiateForwarderClientRep(decrypted);
        break;
      }
      case MSG.SEND_DATA: {
        const decrypted = decrypt(encryptionKey, payload);
        parsed = MessageParser.parseSendData(decrypted);
        break;
      }
      case MSG.CHECK_IN: {
        parsed = MessageParser.parseCheckIn(payload);
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

  static buildInitiateForwarderClientReq(forwarder_client_id, ip_address, port) {
    const p1 = MessageBuilder.buildString(forwarder_client_id);
    const p2 = MessageBuilder.buildString(ip_address);
    const p3 = Buffer.allocUnsafe(4);
    p3.writeUInt32BE(port >>> 0, 0);
    return Buffer.concat([p1, p2, p3]);
  }

  static buildInitiateForwarderClientRep(forwarder_client_id, bind_address, bind_port, address_type, reason) {
    const p1 = MessageBuilder.buildString(forwarder_client_id);
    const p2 = MessageBuilder.buildString(bind_address);
    const p3 = Buffer.allocUnsafe(12);
    p3.writeUInt32BE(bind_port >>> 0, 0);
    p3.writeUInt32BE(address_type >>> 0, 4);
    p3.writeUInt32BE(reason >>> 0, 8);
    return Buffer.concat([p1, p2, p3]);
  }

  static buildSendData(forwarder_client_id, data) {
    const p1 = MessageBuilder.buildString(forwarder_client_id);
    const encoded = Buffer.from(data).toString('base64');
    const p2 = MessageBuilder.buildString(encoded);
    return Buffer.concat([p1, p2]);
  }

  static serializeMessage(encryptionKey, msg) {
    let message_type;
    let value;
    switch (msg.kind) {
      case 'InitiateForwarderClientReq': {
        message_type = MSG.INIT_FWD_REQ;
        const plain = MessageBuilder.buildInitiateForwarderClientReq(msg.forwarder_client_id, msg.ip_address, msg.port);
        value = encrypt(encryptionKey, plain);
        break;
      }
      case 'InitiateForwarderClientRep': {
        message_type = MSG.INIT_FWD_REP;
        const plain = MessageBuilder.buildInitiateForwarderClientRep(msg.forwarder_client_id, msg.bind_address, msg.bind_port, msg.address_type, msg.reason);
        value = encrypt(encryptionKey, plain);
        break;
      }
      case 'SendDataMessage': {
        message_type = MSG.SEND_DATA;
        const plain = MessageBuilder.buildSendData(msg.forwarder_client_id, msg.data);
        value = encrypt(encryptionKey, plain);
        break;
      }
      case 'CheckInMessage': {
        message_type = MSG.CHECK_IN;
        value = MessageBuilder.buildCheckInMessage(msg.messenger_id);
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
    this.forwarderClients = new Map();
    this.downstream_messages = [];
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

  async handleMessage(message) {
    if (message.kind === 'InitiateForwarderClientReq') {
      await this.handleInitiateForwarderClientReq(message.forwarder_client_id, message.ip_address, message.port);
    } else if (message.kind === 'InitiateForwarderClientRep') {
      const socket = this.forwarderClients.get(message.forwarder_client_id);
      if (!socket) return;
      if (message.reason !== 0) {
        try { socket.end(); } catch {}
        this.forwarderClients.delete(message.forwarder_client_id);
      } else {
        socket.resume();
      }
    } else if (message.kind === 'SendDataMessage') {
      const socket = this.forwarderClients.get(message.forwarder_client_id);
      if (!socket) return;

      if (!message.data || message.data.length === 0) {
        try { socket.end(); } catch {}
        this.forwarderClients.delete(message.forwarder_client_id);
        return;
      }

      socket.write(message.data);
    } else {
      console.log(`Received unknown message type: ${message.type}`);
    }
  }

  async handleInitiateForwarderClientReq(forwarder_client_id, ip, port) {
    const socket = new net.Socket();

    socket.once('connect', async () => {
      this.forwarderClients.set(forwarder_client_id, socket);
      const bind_address = socket.localAddress;
      const bind_port = socket.localPort;
      const address_type = net.isIPv4(bind_address) ? 1 : 4;

      await this.sendDownstreamMessage(
        InitiateForwarderClientRep(forwarder_client_id, bind_address, bind_port, address_type, 0)
      );
    });

    socket.once('error', async () => {
      await this.sendDownstreamMessage(
        InitiateForwarderClientRep(forwarder_client_id, '0.0.0.0', 0, 1, 1)
      );
    });

    socket.on('data', async (chunk) => {
      await this.sendDownstreamMessage(SendDataMessage(forwarder_client_id, chunk));
    });

    socket.once('close', async () => {
      await this.sendDownstreamMessage(SendDataMessage(forwarder_client_id, Buffer.alloc(0)));
      this.forwarderClients.delete(forwarder_client_id);
    });

    socket.connect(port, ip);
  }

  async connect() {
    throw new Error('connect() not implemented by subclass');
  }

  async start() {
    throw new Error('start() not implemented by subclass');
  }

  sendDownstreamMessage(_message) {
    throw new Error('sendDownstreamMessage(message) not implemented by subclass');
  }

}

class WSClient extends Client {

  constructor(serverUrl, encryptionKey, userAgent) {
    super(encryptionKey, userAgent);
    this.serverUrl = serverUrl.replace(/^\/+|\/+$/g, '') + '/socketio/?EIO=4&transport=websocket';
    this.ws = null;
    this.wsOptions = {
      headers: this.headers,
      rejectUnauthorized: false
    };
  }

  async connect(){
    this.ws = new WebSocket(this.serverUrl, this.wsOptions);

    await new Promise((resolve, reject) => {
      this.ws.once('open', resolve);
      this.ws.once('error', reject);
    });

    const checkIn = this.serializeMessages([CheckInMessage(this.identifier)]);
    this.ws.send(checkIn);

    if (this.identifier) {
      return;
    }

    const msg = await new Promise((res, rej) => {
      this.ws.once('message', data => res(Buffer.from(data)));
      this.ws.once('error', rej);
    });
    const messages = this.deserializeMessages(msg);
    assert (messages.length > 0, `[!] Invalid response from server ${messages}`);
    const checkInMessage = messages[0];
    assert.strictEqual(checkInMessage.kind, 'CheckInMessage', `[!] Invalid response from server: ${messages}`);
    this.identifier = checkInMessage.messenger_id;
  }

  async start() {
    // flush queued downstream
    while (this.downstream_messages.length > 0) {
      const msg = this.downstream_messages.shift();
      this.sendDownstreamMessage(msg);
    }

    this.ws.on('message', async (data) => {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      const messages = this.deserializeMessages(buf);
      for (const msg of messages) {
        await this.handleMessage(msg);
      }
    });

    return new Promise((resolve, reject) => {
      this.ws.once('close', (code, reason) => {
        console.log(`[*] Websocket Closed: code=${code}, reason=${reason ? reason.toString('utf8') : ''}`);
        resolve({ code, reason });
      });

      this.ws.once('error', (err) => {
        reject(err);
      });
    });
  }

  sendDownstreamMessage(downstream_message) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.downstream_messages.push(downstream_message);
      return;
    }
    const downstream_messages = [CheckInMessage(this.identifier), downstream_message];
    const payload = this.serializeMessages(downstream_messages);
    this.ws.send(payload);
  }
}

class HTTPClient extends Client {
  constructor(serverUrl, encryptionKey, userAgent) {
    super(encryptionKey, userAgent);
    this.serverUrl = String(serverUrl).replace(/\/+$/g, '') + '/socketio/?EIO=4&transport=polling';
    this.identifier = '';
    this.downstream_messages = [];
    this._timeoutMs = 10000; // default per request
  }

  async _postBinary(url, bodyBytes, timeoutMs = this._timeoutMs) {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';

    const agent = isHttps
      ? new https.Agent({ rejectUnauthorized: false }) // accept self-signed certs (scoped to this client)
      : new http.Agent();

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
      agent,
    };

    return new Promise((resolve, reject) => {
      const req = (isHttps ? https : http).request(options, (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          // drain and error
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
  }

  async connect() {
    // Send initial CheckIn (identifier may be empty on first connect)
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

    // Parse server response and extract assigned messenger_id
    try {
      const messages = this.deserializeMessages(resp);
      if (!messages.length) throw new Error('Empty response');
      const msg0 = messages[0];
      if (msg0.kind !== 'CheckInMessage') {
        throw new Error(`Expected CheckInMessage, got ${msg0.kind}`);
      }
      this.identifier = msg0.messenger_id;
    } catch (e) {
      // Bad key / decrypt error typically lands here
      throw new Error(`Failed to parse connect response: ${e.message}`);
    }
  }

  async start() {
    // Long-poll loop: post CheckIn + up to 5 queued messages; handle any replies
    while (true) {
      const toSend = [CheckInMessage(this.identifier)];
      for (let i = 0; i < 5 && this.downstream_messages.length > 0; i++) {
        toSend.push(this.downstream_messages.shift());
      }

      const payload = this.serializeMessages(toSend);

      let resp;
      try {
        resp = await this._postBinary(this.serverUrl, payload, 15000);
      } catch (e) {
        throw new Error(`HTTP poll failed: ${e.message}`);
      }

      if (!resp || resp.length === 0) {
        await new Promise(r => setTimeout(r, 100));
        continue;
      }

      // Deserialize and dispatch messages
      try {
        const messages = this.deserializeMessages(resp);
        for (const m of messages) {
          try {
            await this.handleMessage(m);
          } catch (handlerErr) {
            // Non-fatal: keep polling
            console.error('[!] handler error:', handlerErr.message);
          }
        }
      } catch (e) {
        // Decrypt/parse issues bubble out so caller can retry
        throw new Error(`Failed to deserialize server response: ${e.message}`);
      }
    }
  }

  async sendDownstreamMessage(downstream_message) {
    this.downstream_messages.push(downstream_message);
  }
}

/* REMOTE PORT FORWARDER */

class RemotePortForwarder {
  constructor(messenger, config) {
    this.messenger = messenger;
    const [listenHost, listenPort, dstHost, dstPort] = this.parseConfig(config);
    this.listening_host = listenHost;
    this.listening_port = Number(listenPort);
    this.destination_host = dstHost;
    this.destination_port = Number(dstPort);
    this.identifier = this.randomAlphaNum(10);
  }

  parseConfig(config) {
    const parts = String(config).split(':');
    if (parts.length < 4) throw new Error(`Bad remote port forward config: ${config}`);
    return parts;
  }

  async start() {
    await new Promise((resolve) => {
      const server = net.createServer((socket) => {
        const forwarder_client_id = this.randomAlphaNum(10);

        this.messenger.forwarderClients.set(forwarder_client_id, socket);

        socket.pause();

        this.messenger.sendDownstreamMessage(
          InitiateForwarderClientReq(
            forwarder_client_id,
            this.destination_host,
            this.destination_port
          )
        );

        socket.on('data', async (chunk) => {
          await this.messenger.sendDownstreamMessage(
            SendDataMessage(forwarder_client_id, chunk)
          );
        });

        socket.once('close', async () => {
          await this.messenger.sendDownstreamMessage(
            SendDataMessage(forwarder_client_id, Buffer.alloc(0))
          );
          this.messenger.forwarderClients.delete(forwarder_client_id);
        });

        socket.on('error', () => {});
      });

      server.once('listening', () => {
        const addr = server.address();
        console.log(
          `[+] Remote Port Forwarder ${this.identifier} listening on ${addr.address}:${addr.port}`
        );
        resolve();
      });

      server.once('error', (e) => {
        console.error(
          `${this.listening_host}:${this.listening_port} is already in use or failed:`,
          e.message
        );
        resolve();
      });

      server.listen(this.listening_port, this.listening_host);
    });
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
    remotePortForwards: [],
    retryAttempts: null,
    retryDuration: null,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--server-url') args.serverUrl = argv[++i];
    else if (a === '--encryption-key') args.encryptionKey = argv[++i];
    else if (a === '--user-agent') args.userAgent = argv[++i];
    else if (a === '--retry-attempts') args.retryAttempts = parseInt(argv[++i], 10);
    else if (a === '--retry-duration') args.retryDuration = parseFloat(argv[++i]);
    else if (a === '--remote-port-forwards') {
      while (argv[i + 1] && !argv[i + 1].startsWith('--')) {
        args.remotePortForwards.push(argv[++i]);
      }
    } else {
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
    process.exit(0);
  }
  encryptionKey = sha256Bytes(encryptionKey);
  const userAgent = args.userAgent || DEFAULTS.USER_AGENT;
  const remotePortForwards = Array.isArray(args.remotePortForwards) && args.remotePortForwards.length > 0
    ? args.remotePortForwards
    : DEFAULTS.REMOTE_PORT_FORWARDS;

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
  let connected = false;
  for (const attempt of attempts) {
    const candidateUrl = `${attempt}://${remainder}/`;
    try {
      if (attempt.includes('ws') && wsImported) {
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
      connected = true;
      break; // success
    } catch (e) {
      console.error(`[!] Failed to connect to ${candidateUrl}: ${e?.message || e}`);
      client = null;
    }
  }

  if (!connected){
    console.log('[*] No suitable clients identified, shutting down.');
    process.exit(0);
  }

  const remoteForwards = [];
  for (const cfg of (remotePortForwards || [])) {
    const rf = new RemotePortForwarder(client, cfg);
    await rf.start();
    remoteForwards.push(rf);
  }

  try {
    await client.start();
  } catch (e) {
    console.error(`[!] ${e.name}: ${e.message} at ${e.stack.split('\n')[1].trim()}`);
  }

  if (!(retryAttempts > 0)) {
    console.log('[*] Retry attempts set to zero, exiting.');
    process.exit(0);
  }

  let attemptsCount = 1;
  const sleepTime = retryDuration / retryAttempts;

  while (attemptsCount <= retryAttempts) {
    try {
      console.log(`[*] Attempting to reconnect (attempt #${attemptsCount}/${retryAttempts})`);
      await client.connect();
      console.log(`[+] Reconnected`);
      attemptsCount = 1;
      await client.start();
    } catch (e) {
      console.error(`[!] ${e.name}: ${e.message} at ${e.stack.split('\n')[1].trim()}`);
      attemptsCount += 1;
    }
    await sleep(sleepTime * 1000);
  }
  process.exit(0);
}

const DEFAULTS = {
  SERVER: '{{ server_url }}',
  ENCRYPTION_KEY: '{{ encryption_key }}',
  USER_AGENT: '{{ user_agent }}',
  REMOTE_PORT_FORWARDS: {{ remote_port_forwards }},
  RETRY_ATTEMPTS: {{ retry_attempts }},
  RETRY_DURATION: {{ retry_duration }},
};

if (require.main === module) {
  main().catch(console.error);
}
