// app.js — interfície del magatzem.
import { loadSalt, deriveKey, decryptBuffer, downloadBlob } from './crypto.js';

const $ = (sel) => document.querySelector(sel);

const els = {
  login:     $('#login'),
  vault:     $('#vault'),
  form:      $('#login-form'),
  pwd:       $('#password'),
  submit:    $('#submit'),
  error:     $('#error'),
  title:     $('#title'),
  meta:      $('#meta'),
  files:     $('#files'),
  status:    $('#status'),
  logout:    $('#logout'),
};

let cryptoKey = null;
let saltCache = null;

function showError(msg) {
  els.error.textContent = msg;
  els.error.hidden = false;
}
function clearError() {
  els.error.textContent = '';
  els.error.hidden = true;
}
function setStatus(msg) {
  els.status.textContent = msg || '';
}

function formatSize(bytes) {
  if (bytes == null) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatDate(iso) {
  try { return new Date(iso).toLocaleString('ca-ES'); }
  catch { return iso; }
}

async function loadAndDecryptIndex(key) {
  const r = await fetch('data/index.json.enc', { cache: 'no-store' });
  if (!r.ok) throw new Error(`No s'ha pogut carregar l'índex (HTTP ${r.status})`);
  const buf = new Uint8Array(await r.arrayBuffer());
  const dec = await decryptBuffer(buf, key);
  return JSON.parse(new TextDecoder().decode(dec));
}

function renderIndex(index) {
  els.title.textContent = index.title || 'Documents';
  els.meta.textContent = index.created
    ? `${index.files.length} fitxer(s) · índex ${formatDate(index.created)}`
    : `${index.files.length} fitxer(s)`;

  els.files.innerHTML = '';
  for (const f of index.files) {
    const li = document.createElement('li');

    const link = document.createElement('a');
    link.href = '#';
    link.textContent = f.name;
    link.title = f.mime || '';
    link.addEventListener('click', (e) => {
      e.preventDefault();
      downloadEncrypted(f);
    });

    const size = document.createElement('span');
    size.className = 'size';
    size.textContent = formatSize(f.size);

    li.appendChild(link);
    li.appendChild(size);
    els.files.appendChild(li);
  }

  els.login.hidden = true;
  els.vault.hidden = false;
}

async function downloadEncrypted(file) {
  setStatus(`Descarregant ${file.name}...`);
  try {
    const r = await fetch(`data/${encodeURIComponent(file.id)}.enc`, { cache: 'no-store' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const buf = new Uint8Array(await r.arrayBuffer());
    setStatus(`Desencriptant ${file.name}...`);
    const dec = await decryptBuffer(buf, cryptoKey);
    downloadBlob(dec, file.name, file.mime || 'application/octet-stream');
    setStatus(`Descarregat ${file.name}.`);
    setTimeout(() => setStatus(''), 3000);
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
}

function logout() {
  cryptoKey = null;
  els.vault.hidden = true;
  els.login.hidden = false;
  els.pwd.value = '';
  els.files.innerHTML = '';
  setStatus('');
  clearError();
  els.pwd.focus();
}

async function onSubmit(e) {
  e.preventDefault();
  const pwd = els.pwd.value;
  if (!pwd) return;
  clearError();
  els.submit.disabled = true;
  const original = els.submit.textContent;
  els.submit.textContent = 'Derivant clau...';
  try {
    if (!saltCache) saltCache = await loadSalt();
    cryptoKey = await deriveKey(pwd, saltCache);
    els.submit.textContent = 'Desxifrant índex...';
    const index = await loadAndDecryptIndex(cryptoKey);
    renderIndex(index);
  } catch {
    cryptoKey = null;
    showError('Contrasenya incorrecta o índex corrupte.');
    els.pwd.select();
  } finally {
    els.submit.disabled = false;
    els.submit.textContent = original;
  }
}

els.form.addEventListener('submit', onSubmit);
els.logout.addEventListener('click', logout);
els.pwd.focus();
