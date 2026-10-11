'use strict';
// Yougori launcher file receiver. Runs in a terminal session in raw mode and applies the PC's
// saved changes to /workspace as they arrive, without starting a process per change.
// One operation per line, paths and data base64-encoded:
//   W path data   write a file        D path   delete a file or folder
//   T token       record which PC copy this workspace matches
//   K             restart the dev server (after package changes, or after it exited)
//   B seq         acknowledge everything received so far
// Usage: node sync.cjs NONCE
const fs = require('fs');
const path = require('path');

const nonce = process.argv[2] || '';
const root = '/workspace';
const state = '/yougori/launch';
const twoWay = require('./two-way.cjs')(fs.realpathSync(root));
const mark = (event) => process.stdout.write(`\n[yougori-${nonce}:${event}]\n`);

function target(encoded) {
  const relative = Buffer.from(encoded || '', 'base64').toString('utf8');
  const parts = relative.split('/');
  if (!relative || relative.includes('\0') || relative.startsWith('/') || parts.some((p) => p === '' || p === '.' || p === '..')) {
    throw new Error(`invalid path ${JSON.stringify(relative)}`);
  }
  // Guest tools may have replaced a synced directory with a symlink. Never follow
  // it when applying a PC edit (including the final filename).
  let current = root;
  for (const part of parts) {
    current = path.posix.join(current, part);
    try { if (fs.lstatSync(current).isSymbolicLink()) throw new Error('symlink in sync destination'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return path.posix.join(root, relative);
}

function write(file, data) {
  fs.mkdirSync(path.posix.dirname(file), { recursive: true });
  // Small files land in one write; larger ones appear whole through a rename, so watchers
  // never compile half a file.
  if (data.length < 65536) return fs.writeFileSync(file, data);
  // Sync never transfers .yougori-sync-* names, so a leftover is never copied to the PC.
  const temporary = path.posix.join(path.posix.dirname(file), `.yougori-sync-${process.pid}-${Date.now()}`);
  try {
    fs.writeFileSync(temporary, data, { flag: 'wx' });
    fs.renameSync(temporary, file);
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function remove(file) {
  fs.rmSync(file, { recursive: true, force: true });
}

function restart() {
  fs.writeFileSync(`${state}/restart`, '');
  let pid = 0;
  try { pid = Number(fs.readFileSync(`${state}/dev.pid`, 'utf8')); } catch { return; }
  if (!(pid > 1)) return;
  try { process.kill(-pid, 'SIGTERM'); } catch { return; }
  setTimeout(() => { try { process.kill(-pid, 'SIGKILL'); } catch { /* already stopped */ } }, 4000).unref();
}

function handle(line) {
  const [op, a, b] = line.split(' ');
  try {
    switch (op) {
      case 'X': {
        let reply;
        try { reply = { result: twoWay.request(JSON.parse(Buffer.from(b, 'base64').toString('utf8')), progress => mark(`progress:${a}:${Buffer.from(JSON.stringify(progress)).toString('base64')}`)) }; }
        catch (error) { reply = { error: String(error.message || error) }; }
        const data = Buffer.from(JSON.stringify(reply)).toString('base64');
        for (let i = 0; i < data.length; i += 8192) mark(`rpc:${a}:${data.slice(i, i + 8192)}`);
        mark(`end:${a}`);
        break;
      }
      case 'W': write(target(a), Buffer.from(b || '', 'base64')); break;
      case 'D': remove(target(a)); break;
      case 'T': fs.writeFileSync(`${state}/sync-token`, a || ''); break;
      case 'K': restart(); break;
      case 'B': mark(`ack:${a}`); break;
      case '': break;
      default: throw new Error(`unknown operation ${op}`);
    }
  } catch (error) {
    mark(`error:${Buffer.from(String(error && error.message || error)).toString('base64')}`);
  }
}

let buffer = '';
let scanned = 0;
if (process.stdin.isTTY) process.stdin.setRawMode(true);
process.stdin.setEncoding('latin1');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  if (buffer.length > 360 * 1024 * 1024) {
    mark(`error:${Buffer.from('sync frame too large').toString('base64')}`);
    process.exit(1);
  }
  for (let end = buffer.indexOf('\n', scanned); end >= 0; end = buffer.indexOf('\n')) {
    const line = buffer.slice(0, end).replace(/\r$/, '');
    buffer = buffer.slice(end + 1);
    handle(line);
  }
  scanned = buffer.length;
});
process.stdin.on('end', () => process.exit(0));
process.on('exit', () => twoWay.abort());
mark('ready');
