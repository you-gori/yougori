'use strict';
// Bounded, conditional file operations for opt-in two-way project sync.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// Offsets must remain exactly representable in the file protocol.
const MAX = Number.MAX_SAFE_INTEGER;
// Folds a name as case-insensitive filesystems compare it, like sync::folded in the CLI.
function fold(name) {
  return name.replace(/[\u200c-\u200f\u202a-\u202e\u206a-\u206f\ufeff]/g, '').replace(/[. ]+$/, '').toUpperCase();
}
module.exports = function create(root) {
  let upload;
  let inventory;
  const sqlite = require('./sqlite.cjs')(relative => target(relative));
  const hashes = new Map();
  // The PC decides which names it can store; the guest refuses only unsafe paths.
  // Linux stores ':' in names, but on Windows it would address an NTFS stream.
  function target(relative, directory = false, inspectLinks = false) {
    if (relative === '' && directory) return root;
    if (typeof relative !== 'string' || !relative || relative.length > 4096 || /[\\\x00-\x1f]/.test(relative) || (process.platform === 'win32' && relative.includes(':')) || relative.split('/').some(p => !p || p === '.' || p === '..' || p.startsWith('.yougori-sync-'))) throw Error('Invalid sync path');
    let current = root;
    if (fs.lstatSync(root).isSymbolicLink()) throw Error('Workspace is a symlink');
    for (const part of relative.split('/')) {
      current = path.join(current, part);
      try {
        if (fs.lstatSync(current).isSymbolicLink()) {
          if (inspectLinks) return null;
          throw Error(`Symlink blocks sync: ${relative}`);
        }
      }
      catch (e) { if (e.code !== 'ENOENT') throw e; }
    }
    return current;
  }
  function hash(file) {
    let stat;
    try { stat = fs.lstatSync(file); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    if (!stat.isFile() || stat.isSymbolicLink()) throw Error('Sync path is not a regular file');
    if (stat.size > MAX) throw Error('File exceeds the supported filesystem offset');
    const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const digest = crypto.createHash('sha256'), buffer = Buffer.alloc(64 * 1024);
      let n; while ((n = fs.readSync(fd, buffer, 0, buffer.length, null))) digest.update(buffer.subarray(0, n));
      const after = fs.fstatSync(fd);
      if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs || after.ino !== stat.ino) throw Error('File changed during sync; retrying');
      return digest.digest('hex');
    } finally { fs.closeSync(fd); }
  }
  // Parents before children. Links are reported, never followed. Pruned folders
  // (host-only, or nested too deeply) are reported without their contents.
  function walk(prune, report) {
    if (fs.lstatSync(root).isSymbolicLink()) throw Error('Workspace is a symlink');
    const pruned = new Set(prune.map(fold));
    const entries = [];
    const folders = [''];
    while (folders.length) {
      const folder = folders.pop();
      const dir = folder ? path.join(root, folder) : root;
      let names;
      try { names = fs.readdirSync(dir); } catch (e) { if (e.code === 'ENOENT' || e.code === 'ENOTDIR') continue; throw e; }
      const children = [];
      for (const name of names.sort()) {
        if (name.startsWith('.yougori-sync-')) continue;
        const relative = folder ? `${folder}/${name}` : name;
        let stat;
        try { stat = fs.lstatSync(path.join(dir, name), { bigint: true }); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
        if (stat.isSymbolicLink()) entries.push({ path: relative, kind: 'link' });
        else if (stat.isDirectory()) {
          const deep = relative.split('/').length >= 128;
          entries.push(pruned.has(fold(name)) || deep ? { path: relative, kind: 'dir', pruned: true } : { path: relative, kind: 'dir' });
          if (!pruned.has(fold(name)) && !deep) children.push(relative);
        } else if (stat.isFile()) {
          let database = false;
          // Names the helper cannot address are reported as files; the PC holds them.
          try { database = sqlite.request({ op: 'sqlite-detect', path: relative }).database; } catch {}
          entries.push({ path: relative, kind: database ? 'sqlite' : 'file', stamp: `${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}` });
        } else entries.push({ path: relative, kind: 'other' });
        if (entries.length > 2000000) throw Error('The workspace has too many files for two-way sync; use one-way sync');
        // Keep the PC's request alive while a large workspace is inventoried.
        if (entries.length % 2000 === 0) report({ phase: 'inventory', done: entries.length });
      }
      folders.push(...children.reverse());
    }
    return entries;
  }
  function cachedHash(file) {
    let stat;
    try { stat = fs.lstatSync(file, { bigint: true }); }
    catch (e) { if (e.code === 'ENOENT') { hashes.delete(file); return null; } throw e; }
    const stamp = `${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
    const cached = hashes.get(file);
    if (cached && cached.stamp === stamp) return cached.value;
    const value = hash(file);
    if (hashes.size > 100000) hashes.clear();
    hashes.set(file, { stamp, value });
    return value;
  }
  function expected(file, value) {
    if (hash(file) !== value) throw Error('File changed during sync; both versions were kept');
  }
  function validateUpload() {
    target(upload.relative);
    const parent = fs.lstatSync(path.dirname(upload.temp), { bigint: true });
    const staged = fs.lstatSync(upload.temp, { bigint: true });
    if (!parent.isDirectory() || parent.dev !== upload.parent.dev || parent.ino !== upload.parent.ino ||
        !staged.isFile() || staged.dev !== upload.identity.dev || staged.ino !== upload.identity.ino) {
      throw Error('Sync staging location changed; both versions were kept');
    }
  }
  function abort() {
    if (upload) {
      try { fs.closeSync(upload.fd); } catch {}
      // A guest process may replace the parent directory during a transfer.
      // Never let cleanup follow that replacement into unrelated files.
      try { validateUpload(); fs.unlinkSync(upload.temp); } catch {}
      upload = undefined;
    }
  }
  function request(r, report) {
    if (r.op.startsWith('sqlite-')) return sqlite.request(r, report);
    switch (r.op) {
      case 'directories': {
        if (!Array.isArray(r.paths) || r.paths.length > 64) throw Error('Invalid directory batch');
        const errors = [];
        for (const p of r.paths) {
          try { if (r.create) fs.mkdirSync(target(p), { recursive:true }); else fs.rmdirSync(target(p)); }
          catch(e) { if (r.create || e.code !== 'ENOENT') errors.push([p, e.message]); }
        }
        return { errors: Object.fromEntries(errors) };
      }
      case 'mkdir': fs.mkdirSync(target(r.path), { recursive: true }); return {};
      case 'rmdir': {
        try { fs.rmdirSync(target(r.path)); } catch(e) { if (e.code !== 'ENOENT') throw e; }
        return {};
      }
      case 'hashes': {
        if (!Array.isArray(r.paths) || r.paths.length > 64) throw Error('Invalid hash batch');
        if (r.skipLinks === true) {
          const values = [], skipped = [];
          for (const p of r.paths) {
            const file = target(p, false, true);
            if (file === null) skipped.push(p);
            else values.push([p, cachedHash(file)]);
          }
          return { hashes: Object.fromEntries(values), skipped };
        }
        return Object.fromEntries(r.paths.map(p => [p, cachedHash(target(p))]));
      }
      case 'links': {
        if (!Array.isArray(r.paths) || r.paths.length > 64) throw Error('Invalid link batch');
        return { skipped: r.paths.filter(p => target(p, false, true) === null) };
      }
      case 'tree': {
        // The whole workspace in a few replies instead of one request per folder.
        // The first page walks it once; later pages read that snapshot.
        if (!Array.isArray(r.prune) || r.prune.length > 64 || r.prune.some(n => typeof n !== 'string')) throw Error('Invalid sync inventory request');
        const offset = Number.isSafeInteger(r.offset) && r.offset >= 0 ? r.offset : 0;
        if (offset === 0) inventory = { id: crypto.randomBytes(12).toString('hex'), entries: walk(r.prune, report) };
        else if (!inventory || inventory.id !== r.cursor || offset > inventory.entries.length) throw Error('Sync inventory expired; retrying');
        const entries = [];
        let size = 0, next = offset;
        while (next < inventory.entries.length && entries.length < 4096) {
          const bytes = Buffer.byteLength(JSON.stringify(inventory.entries[next])) + 1;
          if (entries.length && size + bytes > 160 * 1024) break;
          entries.push(inventory.entries[next]);
          size += bytes;
          next += 1;
        }
        const cursor = inventory.id;
        if (next >= inventory.entries.length) inventory = undefined;
        return { entries, cursor, next: inventory ? next : null };
      }
      case 'hash': {
        const file = target(r.path);
        return { hash: hash(file) };
      }
      case 'read': {
        const file = target(r.path);
        if (!Number.isSafeInteger(r.offset) || r.offset < 0 || r.offset > MAX) throw Error('Invalid read offset');
        const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        try {
          const s = fs.fstatSync(fd);
          if (!s.isFile() || s.size > MAX) throw Error('Not a supported sync file');
          const data = Buffer.alloc(24 * 1024);
          const n = fs.readSync(fd, data, 0, data.length, r.offset);
          return { data: data.subarray(0, n).toString('base64'), total: s.size, done: r.offset + n >= s.size, mode: s.mode & 0o777 };
        } finally { fs.closeSync(fd); }
      }
      case 'begin': {
        abort();
        const file = target(r.path);
        expected(file, r.expected);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        const temp = path.join(path.dirname(file), `.yougori-sync-${crypto.randomBytes(12).toString('hex')}`);
        let mode = 0o644;
        try { mode = fs.statSync(file).mode & 0o777; } catch {}
        const parent = fs.lstatSync(path.dirname(file), { bigint: true });
        const fd = fs.openSync(temp, 'wx', mode);
        upload = { file, temp, fd, parent, identity: fs.fstatSync(fd, { bigint: true }), relative: r.path, expected: r.expected, bytes: 0 };
        try { validateUpload(); } catch (error) { abort(); throw error; }
        return {};
      }
      case 'chunk': {
        if (!upload) throw Error('No sync upload');
        validateUpload();
        const data = Buffer.from(r.data, 'base64');
        if (data.length > 24 * 1024 || upload.bytes + data.length > MAX) throw Error('Sync upload exceeds limit');
        // Keep the original staging descriptor instead of reopening its name.
        // Directory replacement cannot redirect an in-flight write.
        for (let offset = 0; offset < data.length;) {
          const written = fs.writeSync(upload.fd, data, offset, data.length - offset);
          if (!written) throw Error('Sync upload made no progress');
          offset += written;
        }
        upload.bytes += data.length;
        return {};
      }
      case 'commit': {
        if (!upload) throw Error('No sync upload');
        validateUpload();
        expected(upload.file, upload.expected);
        if (hash(upload.temp) !== r.hash) throw Error('Sync upload checksum mismatch');
        fs.fsyncSync(upload.fd);
        fs.closeSync(upload.fd);
        upload.fd = undefined;
        fs.renameSync(upload.temp, upload.file);
        upload = undefined;
        return {};
      }
      case 'delete': {
        const file = target(r.path);
        expected(file, r.expected);
        if (r.expected !== null) fs.unlinkSync(file);
        return {};
      }
      case 'abort': abort(); return {};
      default: throw Error('Unknown two-way sync operation');
    }
  }
  return { request, abort: () => { abort(); sqlite.close(); } };
};
