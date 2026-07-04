// crypto.js — primitives criptogràfiques sobre Web Crypto API.
// IMPORTANT: executar en un context segur (HTTPS o localhost).
//
// Paràmetres (han de coincidir amb encrypt.js):
//   KDF:        PBKDF2-HMAC-SHA256, 300.000 iteracions
//   Xifrat:     AES-256-GCM, IV de 12 bytes, tag de 16 bytes
//   Format:     [12 bytes IV] [ciphertext + 16 bytes tag]

const PBKDF2_ITER = 300_000;
const IV_BYTES    = 12;

export async function loadSalt(url = 'data/salt.bin') {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`No s'ha pogut carregar ${url} (HTTP ${r.status})`);
  return new Uint8Array(await r.arrayBuffer());
}

export async function deriveKey(password, salt, iterations = PBKDF2_ITER) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,                // no exportable
    ['encrypt', 'decrypt'],
  );
}

// Desxifra un buffer amb format [IV | ciphertext+tag].
// Fem copies explícites per compatibilitat entre ArrayBuffer i TypedArray views.
export async function decryptBuffer(buffer, key) {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const iv = new Uint8Array(view.subarray(0, IV_BYTES));
  const ct = new Uint8Array(view.subarray(IV_BYTES));
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
}

// Construeix un Blob amb el tipus MIME i dispara la descàrrega al navegador.
export function downloadBlob(data, filename, mime = 'application/octet-stream') {
  const blob = new Blob([data], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
