import { TRANSLATIONS } from '../i18n/translations';
import type {
  BookFolder,
  GroupFolder,
  Language,
  PasswordLockMeta,
} from '../types/archive';

export interface EncryptedArchiveHeader {
  format: 'data-management-encrypted-backup';
  version: 2;
  cipher: 'AES-256-GCM';
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltBase64: string;
  authIvBase64: string;
  authCipherBase64: string;
  exportedAt: number;
}

const FOLDER_PBKDF2_ITERATIONS = 100_000;
const BACKUP_PBKDF2_ITERATIONS = 120_000;
const ENCRYPTED_CHUNK_PLAIN_BYTES = 1024 * 1024; // 1 MB transient slice for memory safety
const FRAME_MAGIC = new Uint8Array([0x44, 0x4d, 0x45, 0x32]); // "DME2"
const BACKUP_AUTH_PLAINTEXT = 'DM_ARCHIVE_ENCRYPTED_V2_AUTH_OK';
const BACKUP_AUTH_AAD = 'dm-backup-header-auth-v2';

function bytesToBase64(bytes: Uint8Array): string {
  const step = 0x8000;
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += step) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + step)));
  }
  return btoa(parts.join(''));
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

function isObjectRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

/**
 * Checks whether a GroupFolder or BookFolder has a configured password lock.
 */
export function hasPasswordLock(
  item: { passwordLock?: PasswordLockMeta | null } | null | undefined
): boolean {
  return Boolean(
    item?.passwordLock &&
      item.passwordLock.algorithm === 'PBKDF2-SHA256' &&
      typeof item.passwordLock.saltBase64 === 'string' &&
      item.passwordLock.saltBase64.length >= 8 &&
      typeof item.passwordLock.hashBase64 === 'string' &&
      item.passwordLock.hashBase64.length >= 16
  );
}

/**
 * Determines whether a binder's contents/thumbnail should be protected from preview:
 * True if the binder itself has a password lock (and isn't currently open),
 * OR if its parent GroupFolder has a password lock (and that parent group isn't currently unlocked).
 */
export function isBinderLockedForPreview(
  folder: BookFolder,
  groups: GroupFolder[],
  unlockedGroupId: string | null,
  unlockedBinderId: string | null
): boolean {
  if (hasPasswordLock(folder) && unlockedBinderId !== folder.id) {
    return true;
  }
  if (folder.groupId) {
    const parent = groups.find((g) => g.id === folder.groupId);
    if (parent && hasPasswordLock(parent) && unlockedGroupId !== parent.id) {
      return true;
    }
  }
  return false;
}

/**
 * Safely validates and normalizes PasswordLockMeta from parsed JSON (e.g. manifest.json during Import).
 */
export function normalizePasswordLockMeta(raw: unknown): PasswordLockMeta | null {
  if (!isObjectRecord(raw)) return null;
  if (raw.algorithm !== 'PBKDF2-SHA256') return null;
  const saltBase64 = typeof raw.saltBase64 === 'string' ? raw.saltBase64.trim() : '';
  const hashBase64 = typeof raw.hashBase64 === 'string' ? raw.hashBase64.trim() : '';
  const iterations =
    typeof raw.iterations === 'number' &&
    Number.isFinite(raw.iterations) &&
    raw.iterations >= 1000 &&
    raw.iterations <= 2_000_000
      ? Math.round(raw.iterations)
      : FOLDER_PBKDF2_ITERATIONS;
  const lockedAt =
    typeof raw.lockedAt === 'number' && Number.isFinite(raw.lockedAt)
      ? raw.lockedAt
      : Date.now();

  if (!saltBase64 || !hashBase64) return null;
  try {
    const salt = base64ToBytes(saltBase64);
    const hash = base64ToBytes(hashBase64);
    if (salt.byteLength < 8 || hash.byteLength < 16) return null;
  } catch {
    return null;
  }

  return {
    algorithm: 'PBKDF2-SHA256',
    saltBase64,
    hashBase64,
    iterations,
    lockedAt,
  };
}

/**
 * Validates password & optional confirmation password for setting folder or backup passwords.
 */
export function validatePasswordInput(
  password: string,
  confirmPassword: string | undefined,
  lang: Language = 'my'
): string | null {
  const t = TRANSLATIONS[lang];
  if (!password) {
    return t.errEmptyPassword;
  }
  if (password.length < 4) {
    return t.errShortPassword;
  }
  if (password.length > 128) {
    return t.errLongPassword;
  }
  if (confirmPassword !== undefined && password !== confirmPassword) {
    return t.errPasswordMismatch;
  }
  return null;
}

async function derivePbkdf2Bits(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    toExactArrayBuffer(encoder.encode(password.normalize('NFC'))),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: toExactArrayBuffer(salt),
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

async function deriveAesGcmKey(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    toExactArrayBuffer(encoder.encode(password.normalize('NFC'))),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return globalThis.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toExactArrayBuffer(salt),
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Creates a salted PBKDF2-HMAC-SHA256 PasswordLockMeta record for locking a Folder or Binder.
 */
export async function createPasswordLockMeta(
  password: string,
  now = Date.now(),
  iterations = FOLDER_PBKDF2_ITERATIONS
): Promise<PasswordLockMeta> {
  const salt = new Uint8Array(16);
  globalThis.crypto.getRandomValues(salt);
  const derived = await derivePbkdf2Bits(password, salt, iterations);

  return {
    algorithm: 'PBKDF2-SHA256',
    saltBase64: bytesToBase64(salt),
    hashBase64: bytesToBase64(derived),
    iterations,
    lockedAt: now,
  };
}

/**
 * Verifies a candidate password against a stored PasswordLockMeta using constant-time byte comparison.
 */
export async function verifyPasswordLock(
  password: string,
  lock: PasswordLockMeta
): Promise<boolean> {
  if (!password || !hasPasswordLock({ passwordLock: lock })) {
    return false;
  }
  try {
    const salt = base64ToBytes(lock.saltBase64);
    const expectedHash = base64ToBytes(lock.hashBase64);
    const actualHash = await derivePbkdf2Bits(password, salt, lock.iterations);
    return constantTimeEqual(actualHash, expectedHash);
  } catch {
    return false;
  }
}

/**
 * Initializes an AES-256-GCM encryption session for exporting an encrypted backup .zip archive.
 */
export async function createBackupEncryptionSession(
  password: string,
  exportedAt = Date.now(),
  iterations = BACKUP_PBKDF2_ITERATIONS
): Promise<{ header: EncryptedArchiveHeader; masterKey: CryptoKey }> {
  const encoder = new TextEncoder();
  const salt = new Uint8Array(16);
  const authIv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(authIv);

  const masterKey = await deriveAesGcmKey(password, salt, iterations);
  const authCipher = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toExactArrayBuffer(authIv),
      additionalData: toExactArrayBuffer(encoder.encode(BACKUP_AUTH_AAD)),
    },
    masterKey,
    toExactArrayBuffer(encoder.encode(BACKUP_AUTH_PLAINTEXT))
  );

  return {
    masterKey,
    header: {
      format: 'data-management-encrypted-backup',
      version: 2,
      cipher: 'AES-256-GCM',
      kdf: 'PBKDF2-SHA256',
      iterations,
      saltBase64: bytesToBase64(salt),
      authIvBase64: bytesToBase64(authIv),
      authCipherBase64: bytesToBase64(new Uint8Array(authCipher)),
      exportedAt,
    },
  };
}

/**
 * Validates a parsed JSON object as an EncryptedArchiveHeader.
 */
export function validateEncryptedArchiveHeader(raw: unknown): EncryptedArchiveHeader | null {
  if (!isObjectRecord(raw)) return null;
  if (
    raw.format !== 'data-management-encrypted-backup' ||
    raw.version !== 2 ||
    raw.cipher !== 'AES-256-GCM' ||
    raw.kdf !== 'PBKDF2-SHA256'
  ) {
    return null;
  }
  const saltBase64 = typeof raw.saltBase64 === 'string' ? raw.saltBase64.trim() : '';
  const authIvBase64 = typeof raw.authIvBase64 === 'string' ? raw.authIvBase64.trim() : '';
  const authCipherBase64 =
    typeof raw.authCipherBase64 === 'string' ? raw.authCipherBase64.trim() : '';
  const iterations =
    typeof raw.iterations === 'number' &&
    Number.isFinite(raw.iterations) &&
    raw.iterations >= 1000 &&
    raw.iterations <= 2_000_000
      ? Math.round(raw.iterations)
      : BACKUP_PBKDF2_ITERATIONS;
  const exportedAt =
    typeof raw.exportedAt === 'number' && Number.isFinite(raw.exportedAt)
      ? raw.exportedAt
      : Date.now();

  if (!saltBase64 || !authIvBase64 || !authCipherBase64) return null;
  try {
    if (base64ToBytes(saltBase64).byteLength < 8) return null;
    if (base64ToBytes(authIvBase64).byteLength !== 12) return null;
    if (base64ToBytes(authCipherBase64).byteLength < 17) return null;
  } catch {
    return null;
  }

  return {
    format: 'data-management-encrypted-backup',
    version: 2,
    cipher: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations,
    saltBase64,
    authIvBase64,
    authCipherBase64,
    exportedAt,
  };
}

/**
 * Verifies the user's backup password against `header` in milliseconds before decrypting large payloads.
 */
export async function unlockBackupEncryptionSession(
  password: string,
  header: EncryptedArchiveHeader
): Promise<{ ok: true; masterKey: CryptoKey } | { ok: false }> {
  if (!password) return { ok: false };
  try {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const salt = base64ToBytes(header.saltBase64);
    const authIv = base64ToBytes(header.authIvBase64);
    const authCipher = base64ToBytes(header.authCipherBase64);

    const masterKey = await deriveAesGcmKey(password, salt, header.iterations);
    const plainBuf = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toExactArrayBuffer(authIv),
        additionalData: toExactArrayBuffer(encoder.encode(BACKUP_AUTH_AAD)),
      },
      masterKey,
      toExactArrayBuffer(authCipher)
    );

    const text = decoder.decode(plainBuf);
    if (text !== BACKUP_AUTH_PLAINTEXT) {
      return { ok: false };
    }
    return { ok: true, masterKey };
  } catch {
    return { ok: false };
  }
}

async function encryptSingleChunkFrame(
  plainSlice: ArrayBuffer,
  masterKey: CryptoKey,
  entryId: string,
  chunkIndex: number
): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const aad = encoder.encode(`${entryId}:${chunkIndex}`);

  const cipherBuf = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toExactArrayBuffer(iv),
      additionalData: toExactArrayBuffer(aad),
    },
    masterKey,
    plainSlice
  );

  const cipherBytes = new Uint8Array(cipherBuf);
  const frame = new ArrayBuffer(4 + 12 + cipherBytes.byteLength);
  const view = new DataView(frame);
  view.setUint32(0, cipherBytes.byteLength, true);
  const frameBytes = new Uint8Array(frame);
  frameBytes.set(iv, 4);
  frameBytes.set(cipherBytes, 16);
  return frame;
}

/**
 * Encrypts a Uint8Array (e.g. manifest JSON) into DME2 chunked AES-256-GCM binary format.
 */
export async function encryptBytesChunkedAesGcm(
  plainBytes: Uint8Array,
  masterKey: CryptoKey,
  entryId: string
): Promise<Uint8Array> {
  const frames: Uint8Array[] = [FRAME_MAGIC];
  let totalLength = FRAME_MAGIC.byteLength;

  if (plainBytes.byteLength === 0) {
    const emptyFrame = new Uint8Array(
      await encryptSingleChunkFrame(new ArrayBuffer(0), masterKey, entryId, 0)
    );
    frames.push(emptyFrame);
    totalLength += emptyFrame.byteLength;
  } else {
    let offset = 0;
    let chunkIndex = 0;
    while (offset < plainBytes.byteLength) {
      const end = Math.min(offset + ENCRYPTED_CHUNK_PLAIN_BYTES, plainBytes.byteLength);
      const sliceBuf = toExactArrayBuffer(plainBytes.subarray(offset, end));
      const frame = new Uint8Array(
        await encryptSingleChunkFrame(sliceBuf, masterKey, entryId, chunkIndex)
      );
      frames.push(frame);
      totalLength += frame.byteLength;
      offset = end;
      chunkIndex++;
    }
  }

  const out = new Uint8Array(totalLength);
  let pos = 0;
  for (const f of frames) {
    out.set(f, pos);
    pos += f.byteLength;
  }
  return out;
}

/**
 * Encrypts a potentially large photo Blob in 1 MB slices into a DME2 AES-256-GCM Blob
 * without materializing the entire unencrypted photo in a single contiguous buffer.
 */
export async function encryptBlobChunkedAesGcm(
  blob: Blob,
  masterKey: CryptoKey,
  entryId: string
): Promise<Blob> {
  const parts: BlobPart[] = [toExactArrayBuffer(FRAME_MAGIC)];

  if (blob.size === 0) {
    const emptyFrame = await encryptSingleChunkFrame(new ArrayBuffer(0), masterKey, entryId, 0);
    parts.push(emptyFrame);
    return new Blob(parts, { type: 'application/octet-stream' });
  }

  let offset = 0;
  let chunkIndex = 0;
  while (offset < blob.size) {
    const end = Math.min(offset + ENCRYPTED_CHUNK_PLAIN_BYTES, blob.size);
    const plainSlice = await blob.slice(offset, end).arrayBuffer();
    const encryptedFrame = await encryptSingleChunkFrame(
      plainSlice,
      masterKey,
      entryId,
      chunkIndex
    );
    parts.push(encryptedFrame);
    offset = end;
    chunkIndex++;
  }

  return new Blob(parts, { type: 'application/octet-stream' });
}

/**
 * Decrypts a DME2 chunked AES-256-GCM payload back into raw bytes, verifying AAD and auth tags on every chunk.
 */
export async function decryptBytesChunkedAesGcm(
  framedInput: ArrayBuffer | Uint8Array,
  masterKey: CryptoKey,
  entryId: string
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data =
    framedInput instanceof Uint8Array ? framedInput : new Uint8Array(framedInput);

  if (
    data.byteLength < 4 ||
    data[0] !== FRAME_MAGIC[0] ||
    data[1] !== FRAME_MAGIC[1] ||
    data[2] !== FRAME_MAGIC[2] ||
    data[3] !== FRAME_MAGIC[3]
  ) {
    throw new Error('Invalid DME2 encrypted frame header');
  }

  const plainChunks: Uint8Array[] = [];
  let totalPlainLength = 0;
  let offset = 4;
  let chunkIndex = 0;

  while (offset < data.byteLength) {
    if (offset + 16 > data.byteLength) {
      throw new Error('Truncated DME2 chunk header');
    }
    const view = new DataView(data.buffer, data.byteOffset + offset, 4);
    const cipherLen = view.getUint32(0, true);
    if (cipherLen < 16 || offset + 16 + cipherLen > data.byteLength) {
      throw new Error('Invalid DME2 chunk length');
    }

    const iv = data.subarray(offset + 4, offset + 16);
    const cipherBytes = data.subarray(offset + 16, offset + 16 + cipherLen);
    const aad = encoder.encode(`${entryId}:${chunkIndex}`);

    const plainBuf = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toExactArrayBuffer(iv),
        additionalData: toExactArrayBuffer(aad),
      },
      masterKey,
      toExactArrayBuffer(cipherBytes)
    );

    const chunkBytes = new Uint8Array(plainBuf);
    plainChunks.push(chunkBytes);
    totalPlainLength += chunkBytes.byteLength;

    offset += 16 + cipherLen;
    chunkIndex++;
  }

  if (chunkIndex === 0) {
    throw new Error('Empty DME2 frame body');
  }

  const result = new Uint8Array(totalPlainLength);
  let pos = 0;
  for (const chunk of plainChunks) {
    result.set(chunk, pos);
    pos += chunk.byteLength;
  }
  return result;
}

/**
 * Decrypts a DME2 chunked AES-256-GCM photo payload directly into a typed Blob.
 */
export async function decryptBlobChunkedAesGcm(
  framedInput: ArrayBuffer | Uint8Array,
  masterKey: CryptoKey,
  entryId: string,
  mimeType: string
): Promise<Blob> {
  const encoder = new TextEncoder();
  const data =
    framedInput instanceof Uint8Array ? framedInput : new Uint8Array(framedInput);

  if (
    data.byteLength < 4 ||
    data[0] !== FRAME_MAGIC[0] ||
    data[1] !== FRAME_MAGIC[1] ||
    data[2] !== FRAME_MAGIC[2] ||
    data[3] !== FRAME_MAGIC[3]
  ) {
    throw new Error('Invalid DME2 encrypted photo header');
  }

  const parts: BlobPart[] = [];
  let offset = 4;
  let chunkIndex = 0;

  while (offset < data.byteLength) {
    if (offset + 16 > data.byteLength) {
      throw new Error('Truncated DME2 photo chunk header');
    }
    const view = new DataView(data.buffer, data.byteOffset + offset, 4);
    const cipherLen = view.getUint32(0, true);
    if (cipherLen < 16 || offset + 16 + cipherLen > data.byteLength) {
      throw new Error('Invalid DME2 photo chunk length');
    }

    const iv = data.subarray(offset + 4, offset + 16);
    const cipherBytes = data.subarray(offset + 16, offset + 16 + cipherLen);
    const aad = encoder.encode(`${entryId}:${chunkIndex}`);

    const plainBuf = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toExactArrayBuffer(iv),
        additionalData: toExactArrayBuffer(aad),
      },
      masterKey,
      toExactArrayBuffer(cipherBytes)
    );

    parts.push(plainBuf);
    offset += 16 + cipherLen;
    chunkIndex++;
  }

  if (chunkIndex === 0) {
    throw new Error('Empty DME2 photo frame body');
  }

  return new Blob(parts, { type: mimeType || 'image/jpeg' });
}
