#!/usr/bin/env node
/*
 * encrypt.js — Magatzem estàtic d'arxius xifrats.
 *
 * Ús:
 *   node encrypt.js init                 Crea data/salt.bin (16 bytes aleatoris).
 *   node encrypt.js add <fitxer>         Xifra source/<fitxer> -> data/<id>.enc.
 *   node encrypt.js rebuild-index        Re-genera data/index.json.enc.
 *   node encrypt.js all                  init (si cal) + add (tots source/*) + rebuild-index.
 *   node encrypt.js password <nova>     Re-xifra TOT amb un salt nou (canvi de contrasenya).
 *
 * La contrasenya es llegeix de la variable d'entorn VAULT_PW.
 * Si VAULT_PW no existeix i l'stdin és un TTY, es demana amb l'entrada oculta.
 * (No usem PWD: és una variable estàndard del shell = directori actual.)
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const ITER      = 600_000;
const SALT_BYTES = 16;
const IV_BYTES   = 12;
const KEY_BYTES  = 32;

const ROOT   = __dirname;
const DATA   = path.join(ROOT, 'data');
const SOURCE = path.join(ROOT, 'source');

function ensureDirs() {
  if (!fs.existsSync(DATA))   fs.mkdirSync(DATA,   { recursive: true });
  if (!fs.existsSync(SOURCE)) fs.mkdirSync(SOURCE, { recursive: true });
}

function saltPath()  { return path.join(DATA, 'salt.bin'); }
function loadSalt()  { return fs.readFileSync(saltPath()); }
function writeSalt(s) { fs.writeFileSync(saltPath(), s); }

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, ITER, KEY_BYTES, 'sha256');
}

function encryptBuffer(plain, key) {
  const iv     = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct     = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]);
}

function decryptBuffer(encrypted, key) {
  const iv  = encrypted.subarray(0, IV_BYTES);
  const ct  = encrypted.subarray(IV_BYTES, encrypted.length - 16);
  const tag = encrypted.subarray(encrypted.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function listSourceFiles() {
  return fs.readdirSync(SOURCE).filter(f => !f.startsWith('.'));
}

function listEncryptedFiles() {
  return fs.readdirSync(DATA).filter(f => f.endsWith('.enc') && f !== 'index.json.enc');
}

// Identificador OPAC del blob xifrat. HMAC-SHA256 amb la clau derivada:
// no revela el nom (irreversible) ni permet endevinar-lo per confirmació
// (sense la contrasenya no es pot recalcular). Determinista: el mateix nom
// amb la mateixa contrasenya sempre dona el mateix id, així re-xifrar
// sobreescriu net. El nom real només viu dins de l'índex xifrat.
function idOf(filename, key) {
  return crypto.createHmac('sha256', key).update(filename, 'utf8').digest('hex').slice(0, 32);
}

function guessMime(ext) {
  const map = {
    '.pdf':  'application/pdf',
    '.txt':  'text/plain',
    '.md':   'text/markdown',
    '.html': 'text/html', '.htm': 'text/html',
    '.json': 'application/json',
    '.xml':  'application/xml',
    '.csv':  'text/csv',
    '.png':  'image/png',
    '.jpg':  'image/jpeg', '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.webp': 'image/webp',
    '.svg':  'image/svg+xml',
    '.doc':  'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls':  'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt':  'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.zip':  'application/zip',
    '.epub': 'application/epub+zip',
  };
  return map[ext.toLowerCase()] || 'application/octet-stream';
}

function buildIndex(key) {
  const files = listSourceFiles();
  const seen = new Set();
  for (const f of files) {
    const id = idOf(f, key);
    if (seen.has(id)) {
      throw new Error(`Dos fitxers comparteixen el mateix id "${id}". Canvia'ls el nom.`);
    }
    seen.add(id);
  }
  return {
    v: 1,
    title: 'Documents personals',
    created: new Date().toISOString(),
    files: files.map(f => {
      const stat = fs.statSync(path.join(SOURCE, f));
      return {
        id:   idOf(f, key),
        name: f,
        size: stat.size,
        mime: guessMime(path.extname(f)),
      };
    }),
  };
}

function promptPassword(label) {
  if (process.env.VAULT_PW) return Promise.resolve(process.env.VAULT_PW);
  if (!process.stdin.isTTY) {
    return new Promise((resolve, reject) => {
      const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout, terminal: false });
      rl.question(label, (answer) => { rl.close(); resolve(answer); });
    });
  }
  return new Promise((resolve) => {
    const stdin  = process.stdin;
    const stdout = process.stdout;
    stdout.write(label);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let pw = '';
    const onData = (ch) => {
      switch (ch) {
        case '\n': case '\r': case '\u0004':
          stdin.setRawMode(false);
          stdin.removeListener('data', onData);
          stdin.pause();
          stdout.write('\n');
          resolve(pw);
          break;
        case '\u0003':
          process.exit(130);
          break;
        case '\u007f':
        case '\b':
          if (pw.length > 0) { pw = pw.slice(0, -1); stdout.write('\b \b'); }
          break;
        default:
          pw += ch;
          stdout.write('*');
      }
    };
    stdin.on('data', onData);
  });
}

async function cmdInit() {
  ensureDirs();
  if (fs.existsSync(saltPath())) {
    console.log('Ja existeix data/salt.bin. Esborra\'l per regenerar-lo.');
    return;
  }
  writeSalt(crypto.randomBytes(SALT_BYTES));
  console.log(`Creat data/salt.bin (${SALT_BYTES} bytes).`);
}

async function cmdAdd(file) {
  ensureDirs();
  const src = path.join(SOURCE, file);
  if (!fs.existsSync(src)) { console.error('No existeix: ' + src); process.exit(1); }
  if (!fs.existsSync(saltPath())) { console.error('Falta data/salt.bin. Executa primer: node encrypt.js init'); process.exit(1); }
  const pwd   = await promptPassword('Contrasenya: ');
  const key   = deriveKey(pwd, loadSalt());
  const data  = fs.readFileSync(src);
  const enc   = encryptBuffer(data, key);
  const id    = idOf(file, key);
  fs.writeFileSync(path.join(DATA, id + '.enc'), enc);
  console.log(`Xifrat ${file} -> data/${id}.enc (${enc.length} bytes)`);
}

async function cmdRebuildIndex() {
  ensureDirs();
  if (!fs.existsSync(saltPath())) { console.error('Falta data/salt.bin. Executa primer: node encrypt.js init'); process.exit(1); }
  const pwd = await promptPassword('Contrasenya: ');
  const key = deriveKey(pwd, loadSalt());
  const index = buildIndex(key);
  const enc = encryptBuffer(Buffer.from(JSON.stringify(index), 'utf8'), key);
  fs.writeFileSync(path.join(DATA, 'index.json.enc'), enc);
  console.log(`Escrit data/index.json.enc amb ${index.files.length} fitxer(s).`);
}

async function cmdAll() {
  ensureDirs();
  if (!fs.existsSync(saltPath())) {
    writeSalt(crypto.randomBytes(SALT_BYTES));
    console.log(`Creat data/salt.bin (${SALT_BYTES} bytes).`);
  }
  const pwd   = await promptPassword('Contrasenya: ');
  const salt  = loadSalt();
  const key   = deriveKey(pwd, salt);
  const files = listSourceFiles();
  if (files.length === 0) {
    console.log('Cap fitxer a source/. Afegeix-ne algun abans de continuar.');
    return;
  }
  for (const f of files) {
    const data = fs.readFileSync(path.join(SOURCE, f));
    const enc  = encryptBuffer(data, key);
    const id   = idOf(f, key);
    fs.writeFileSync(path.join(DATA, id + '.enc'), enc);
    console.log(`  + ${f}  ->  ${id}.enc  (${enc.length} bytes)`);
  }
  const index = buildIndex(key);
  const encIdx = encryptBuffer(Buffer.from(JSON.stringify(index), 'utf8'), key);
  fs.writeFileSync(path.join(DATA, 'index.json.enc'), encIdx);
  console.log(`Fet. data/index.json.enc conté ${index.files.length} fitxer(s).`);
}

async function cmdPassword(newPwd) {
  if (!newPwd) { console.error('Falta la nova contrasenya.'); process.exit(1); }
  ensureDirs();
  if (!fs.existsSync(saltPath())) { console.error('Falta data/salt.bin.'); process.exit(1); }
  const oldPwd  = await promptPassword('Contrasenya actual: ');
  const oldSalt = loadSalt();
  const oldKey  = deriveKey(oldPwd, oldSalt);
  try {
    decryptBuffer(fs.readFileSync(path.join(DATA, 'index.json.enc')), oldKey);
  } catch {
    console.error('Contrasenya actual incorrecta (no es pot desxifrar l\'índex).');
    process.exit(1);
  }
  const newSalt = crypto.randomBytes(SALT_BYTES);
  writeSalt(newSalt);
  const newKey  = deriveKey(newPwd, newSalt);
  for (const f of listEncryptedFiles()) {
    const dec = decryptBuffer(fs.readFileSync(path.join(DATA, f)), oldKey);
    fs.writeFileSync(path.join(DATA, f), encryptBuffer(dec, newKey));
    console.log(`  re ${f}`);
  }
  const idxDec = decryptBuffer(fs.readFileSync(path.join(DATA, 'index.json.enc')), oldKey);
  fs.writeFileSync(path.join(DATA, 'index.json.enc'), encryptBuffer(idxDec, newKey));
  console.log('Contrasenya canviada. Salt nou generat.');
}

function usage() {
  console.log('Ús: node encrypt.js <init|add|rebuild-index|all|password> [arg]');
  console.log('Variable d\'entorn: VAULT_PW=contrasenya  (si no, es demana per stdin)');
}

(async () => {
  const cmd = process.argv[2];
  const arg = process.argv[3];
  try {
    switch (cmd) {
      case 'init':          await cmdInit(); break;
      case 'add':           await cmdAdd(arg); break;
      case 'rebuild-index': await cmdRebuildIndex(); break;
      case 'all':           await cmdAll(); break;
      case 'password':      await cmdPassword(arg); break;
      case undefined:       usage(); break;
      default:              usage(); process.exit(1);
    }
  } catch (e) {
    console.error('Error:', e.message);
    process.exit(1);
  }
})();
