#!/usr/bin/env node
/**
 * Tiny server shim: accepts one client check-in over WS, replies, sends checkout.
 */
const { WebSocketServer } = require('ws');

const PORT = process.argv[2] ? Number(process.argv[2]) : 9999;

function buildString(s) {
  const buf = Buffer.from(s, 'utf-8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  return Buffer.concat([len, buf]);
}

function buildMessage(type, payload) {
  const header = Buffer.alloc(8);
  header.writeUInt32BE(type, 0);
  header.writeUInt32BE(8 + payload.length, 4);
  return Buffer.concat([header, payload]);
}

function parseCheckin(data) {
  if (data.length < 8) return null;
  const msgType = data.readUInt32BE(0);
  if (msgType !== 0x04) return null;
  const strLen = data.readUInt32BE(8);
  return data.slice(12, 12 + strLen).toString('utf-8');
}

const wss = new WebSocketServer({ host: '127.0.0.1', port: PORT }, () => {
  console.log(`READY ${PORT}`);
});

wss.on('connection', (ws) => {
  ws.once('message', (data) => {
    const clientId = parseCheckin(data);
    if (clientId === null) { ws.close(); return; }

    const assignedId = clientId || 'shim-test-id';
    ws.send(buildMessage(0x04, buildString(assignedId)));

    setTimeout(() => {
      ws.send(buildMessage(0x07, Buffer.alloc(0)));
      ws.close();
    }, 300);
  });
});
