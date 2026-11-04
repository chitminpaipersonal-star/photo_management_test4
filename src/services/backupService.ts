import JSZip from 'jszip';
import type { BookFolder, GroupFolder, PhotoItem } from '../types/archive';
import { sanitizeExportFilename } from '../utils/archiveLogic';
import {
  buildBackupDateStamp,
  validateAndNormalizeBackupManifest,
  type ArchiveBackupManifest,
  type ArchiveSnapshot,
  type BackupPhotoEntry,
} from '../utils/backupLogic';
import {
  createBackupEncryptionSession,
  decryptBlobChunkedAesGcm,
  decryptBytesChunkedAesGcm,
  encryptBlobChunkedAesGcm,
  encryptBytesChunkedAesGcm,
  unlockBackupEncryptionSession,
  validateEncryptedArchiveHeader,
  type EncryptedArchiveHeader,
} from '../utils/securityCrypto';
import {
  createBrowserBlobSink,
  writeStreamingZip,
  type StreamingZipSourceEntry,
  type ZipWriteSink,
} from '../utils/streamingZip';
import { openSaveLocationSink, type SaveFileOutcome } from './nativeBridge';
import { resolvePhotoBlob } from './shareAndExport';

function inferExtension(photo: PhotoItem): string {
  const match = photo.name.match(/\.([a-zA-Z0-9]{2,5})$/);
  if (match) return match[1].toLowerCase();
  if (photo.mimeType.includes('png')) return 'png';
  if (photo.mimeType.includes('webp')) return 'webp';
  return 'jpg';
}

/**
 * Streams the entire Data Management archive into a ZipWriteSink.
 * - When `backupPassword` is provided, every photo (`vault/000001.enc`) and `manifest.enc`
 *   (including all folder/binder names, metadata, and per-folder passwordLock hashes)
 *   are encrypted in 1 MB chunks using AES-256-GCM + PBKDF2-SHA256 so external ZIP extraction
 *   exposes zero readable images or folder names.
 * - When `backupPassword` is omitted/null, writes a standard ZIP while still preserving
 *   all per-folder `passwordLock` hashes inside `manifest.json`.
 */
async function streamArchiveBackupToSink(
  snapshot: ArchiveSnapshot,
  sink: ZipWriteSink,
  exportedAt = Date.now(),
  onProgress?: (percent: number) => void,
  backupPassword?: string | null
): Promise<void> {
  const encoder = new TextEncoder();
  const photoEntries: BackupPhotoEntry[] = [];
  const entries: StreamingZipSourceEntry[] = [];

  const hasEncryptionPassword = Boolean(backupPassword && backupPassword.length > 0);

  if (hasEncryptionPassword && backupPassword) {
    const { header, masterKey } = await createBackupEncryptionSession(backupPassword, exportedAt);

    entries.push({
      path: 'encryption-header.json',
      modifiedAt: exportedAt,
      getData: () => encoder.encode(JSON.stringify(header, null, 2)),
    });

    for (let i = 0; i < snapshot.photos.length; i++) {
      const photo = snapshot.photos[i];
      const paddedIndex = String(i + 1).padStart(6, '0');
      const assetPath = `vault/${paddedIndex}.enc`;

      const entryRecord: BackupPhotoEntry = {
        id: photo.id,
        folderId: photo.folderId,
        name: photo.name,
        mimeType: photo.mimeType || 'image/jpeg',
        createdAt: photo.createdAt,
        ...(typeof photo.size === 'number' ? { size: photo.size } : {}),
        assetPath,
      };
      photoEntries.push(entryRecord);

      entries.push({
        path: assetPath,
        modifiedAt: exportedAt,
        getData: async () => {
          const blob = await resolvePhotoBlob(photo);
          entryRecord.size = blob.size;
          if (blob.type) {
            entryRecord.mimeType = blob.type;
          }
          return encryptBlobChunkedAesGcm(blob, masterKey, `photo:${photo.id}`);
        },
      });
    }

    entries.push({
      path: 'manifest.enc',
      modifiedAt: exportedAt,
      getData: async () => {
        const manifest: ArchiveBackupManifest = {
          format: 'data-management-backup',
          version: 2,
          exportedAt,
          groups: snapshot.groups,
          folders: snapshot.folders,
          photos: photoEntries,
        };
        const plainManifest = encoder.encode(JSON.stringify(manifest));
        return encryptBytesChunkedAesGcm(plainManifest, masterKey, 'manifest:v2');
      },
    });

    await writeStreamingZip(entries, sink, onProgress);
    return;
  }

  for (let i = 0; i < snapshot.photos.length; i++) {
    const photo = snapshot.photos[i];
    const ext = inferExtension(photo);
    const safeId = sanitizeExportFilename(photo.id, `photo-${i + 1}`);
    const assetPath = `photos/${safeId}.${ext}`;

    const entryRecord: BackupPhotoEntry = {
      id: photo.id,
      folderId: photo.folderId,
      name: photo.name,
      mimeType: photo.mimeType || 'image/jpeg',
      createdAt: photo.createdAt,
      ...(typeof photo.size === 'number' ? { size: photo.size } : {}),
      assetPath,
    };
    photoEntries.push(entryRecord);

    entries.push({
      path: assetPath,
      modifiedAt: photo.createdAt,
      getData: async () => {
        const blob = await resolvePhotoBlob(photo);
        entryRecord.size = blob.size;
        if (blob.type) {
          entryRecord.mimeType = blob.type;
        }
        return blob;
      },
    });
  }

  entries.push({
    path: 'manifest.json',
    modifiedAt: exportedAt,
    getData: () => {
      const manifest: ArchiveBackupManifest = {
        format: 'data-management-backup',
        version: 2,
        exportedAt,
        groups: snapshot.groups,
        folders: snapshot.folders,
        photos: photoEntries,
      };
      return encoder.encode(JSON.stringify(manifest, null, 2));
    },
  });

  await writeStreamingZip(entries, sink, onProgress);
}

/**
 * Packages the entire Data Management archive into a portable .zip Blob (encrypted when `backupPassword` is provided).
 */
export async function createArchiveBackupZipBlob(
  snapshot: ArchiveSnapshot,
  exportedAt = Date.now(),
  onProgress?: (percent: number) => void,
  backupPassword?: string | null
): Promise<{ zipBlob: Blob; filename: string }> {
  const sink = createBrowserBlobSink();
  await streamArchiveBackupToSink(snapshot, sink, exportedAt, onProgress, backupPassword);
  const filename = `data-management-backup-${buildBackupDateStamp(exportedAt)}.zip`;

  return {
    zipBlob: sink.toBlob(),
    filename,
  };
}

/**
 * Exports a complete .zip backup file (encrypted with AES-256-GCM when `backupPassword` is provided)
 * directly to a user-selected folder in the phone's local storage.
 */
export async function exportFullArchiveZip(
  snapshot: ArchiveSnapshot,
  onProgress?: (percent: number) => void,
  backupPassword?: string | null
): Promise<SaveFileOutcome> {
  const exportedAt = Date.now();
  const suggestedFilename = `data-management-backup-${buildBackupDateStamp(exportedAt)}.zip`;

  const session = await openSaveLocationSink(suggestedFilename, 'application/zip');
  if (session.status === 'cancelled') {
    return { status: 'cancelled' };
  }

  try {
    await streamArchiveBackupToSink(
      snapshot,
      session.sink,
      exportedAt,
      onProgress,
      backupPassword
    );
    await session.finalize();
    return {
      status: 'saved',
      filename: session.filename,
      displayPath: session.displayPath,
    };
  } catch (err) {
    await session.abort();
    throw err;
  }
}

export type BackupInspectionResult =
  | {
      status: 'encrypted';
      header: EncryptedArchiveHeader;
      rawZipBytes: ArrayBuffer;
    }
  | {
      status: 'ready';
      snapshot: ArchiveSnapshot;
      exportedAt: number;
    }
  | {
      status: 'invalid';
    };

export type EncryptedBackupDecryptResult =
  | {
      status: 'ready';
      snapshot: ArchiveSnapshot;
      exportedAt: number;
    }
  | {
      status: 'wrong_password';
    }
  | {
      status: 'corrupted';
    };

async function toArrayBufferInput(input: Blob | ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
  if (input instanceof Blob) {
    return input.arrayBuffer();
  }
  if (input instanceof Uint8Array) {
    const copy = new ArrayBuffer(input.byteLength);
    new Uint8Array(copy).set(input);
    return copy;
  }
  return input;
}

async function restorePlainManifestPhotos(
  zip: JSZip,
  manifest: ArchiveBackupManifest
): Promise<{ valid: true; snapshot: ArchiveSnapshot; exportedAt: number } | { valid: false }> {
  const restoredPhotos: PhotoItem[] = [];

  for (let i = 0; i < manifest.photos.length; i++) {
    const entry = manifest.photos[i];
    const zipAsset = zip.file(entry.assetPath);
    if (!zipAsset) {
      return { valid: false };
    }
    const rawBuffer = await zipAsset.async('arraybuffer');
    const typedBlob = new Blob([rawBuffer], { type: entry.mimeType || 'image/jpeg' });
    const previewUrl =
      typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function'
        ? URL.createObjectURL(typedBlob)
        : undefined;

    restoredPhotos.push({
      id: entry.id,
      folderId: entry.folderId,
      name: entry.name,
      mimeType: entry.mimeType,
      createdAt: entry.createdAt,
      size: typeof entry.size === 'number' ? entry.size : typedBlob.size,
      blob: typedBlob,
      previewUrl,
    });

    if (i % 8 === 7) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  return {
    valid: true,
    snapshot: {
      groups: manifest.groups as GroupFolder[],
      folders: manifest.folders as BookFolder[],
      photos: restoredPhotos,
    },
    exportedAt: manifest.exportedAt,
  };
}

/**
 * Inspects an imported .zip archive:
 * - Detects AES-256-GCM password-protected archives (`status: 'encrypted'`) so the UI can prompt for password
 * - Parses standard unencrypted v1/v2 archives immediately (`status: 'ready'`)
 */
export async function inspectArchiveBackupZip(
  input: Blob | ArrayBuffer | Uint8Array
): Promise<BackupInspectionResult> {
  try {
    const rawZipBytes = await toArrayBufferInput(input);
    const zip = await JSZip.loadAsync(rawZipBytes);

    const encHeaderFile = zip.file('encryption-header.json');
    const encManifestFile = zip.file('manifest.enc');
    if (encHeaderFile && encManifestFile) {
      const headerJson: unknown = JSON.parse(await encHeaderFile.async('string'));
      const validHeader = validateEncryptedArchiveHeader(headerJson);
      if (!validHeader) {
        return { status: 'invalid' };
      }
      return {
        status: 'encrypted',
        header: validHeader,
        rawZipBytes,
      };
    }

    const manifestFile = zip.file('manifest.json');
    if (!manifestFile) {
      return { status: 'invalid' };
    }

    const parsedJson: unknown = JSON.parse(await manifestFile.async('string'));
    const validation = validateAndNormalizeBackupManifest(parsedJson);
    if (!validation.valid) {
      return { status: 'invalid' };
    }

    const restored = await restorePlainManifestPhotos(zip, validation.manifest);
    if (!restored.valid) {
      return { status: 'invalid' };
    }

    return {
      status: 'ready',
      snapshot: restored.snapshot,
      exportedAt: restored.exportedAt,
    };
  } catch {
    return { status: 'invalid' };
  }
}

/**
 * Verifies `password` and decrypts all metadata, folder password locks, and binary photos
 * from an AES-256-GCM encrypted backup .zip archive.
 */
export async function decryptArchiveBackupZip(
  input: Blob | ArrayBuffer | Uint8Array,
  header: EncryptedArchiveHeader,
  password: string
): Promise<EncryptedBackupDecryptResult> {
  const auth = await unlockBackupEncryptionSession(password, header);
  if (!auth.ok) {
    return { status: 'wrong_password' };
  }

  const restoredPreviewUrls: string[] = [];
  try {
    const rawZipBytes = await toArrayBufferInput(input);
    const zip = await JSZip.loadAsync(rawZipBytes);
    const encManifestFile = zip.file('manifest.enc');
    if (!encManifestFile) {
      return { status: 'corrupted' };
    }

    const encManifestBytes = await encManifestFile.async('uint8array');
    const plainManifestBytes = await decryptBytesChunkedAesGcm(
      encManifestBytes,
      auth.masterKey,
      'manifest:v2'
    );
    const manifestJson: unknown = JSON.parse(new TextDecoder().decode(plainManifestBytes));
    const validation = validateAndNormalizeBackupManifest(manifestJson);
    if (!validation.valid) {
      return { status: 'corrupted' };
    }

    const { manifest } = validation;
    const restoredPhotos: PhotoItem[] = [];

    for (let i = 0; i < manifest.photos.length; i++) {
      const entry = manifest.photos[i];
      const zipAsset = zip.file(entry.assetPath);
      if (!zipAsset) {
        for (const u of restoredPreviewUrls) URL.revokeObjectURL(u);
        return { status: 'corrupted' };
      }

      const encryptedPhotoBuf = await zipAsset.async('arraybuffer');
      const typedBlob = await decryptBlobChunkedAesGcm(
        encryptedPhotoBuf,
        auth.masterKey,
        `photo:${entry.id}`,
        entry.mimeType || 'image/jpeg'
      );

      const previewUrl =
        typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function'
          ? URL.createObjectURL(typedBlob)
          : undefined;
      if (previewUrl) {
        restoredPreviewUrls.push(previewUrl);
      }

      restoredPhotos.push({
        id: entry.id,
        folderId: entry.folderId,
        name: entry.name,
        mimeType: entry.mimeType,
        createdAt: entry.createdAt,
        size: typeof entry.size === 'number' ? entry.size : typedBlob.size,
        blob: typedBlob,
        previewUrl,
      });

      if (i % 6 === 5) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    return {
      status: 'ready',
      snapshot: {
        groups: manifest.groups as GroupFolder[],
        folders: manifest.folders as BookFolder[],
        photos: restoredPhotos,
      },
      exportedAt: manifest.exportedAt,
    };
  } catch {
    for (const u of restoredPreviewUrls) URL.revokeObjectURL(u);
    return { status: 'corrupted' };
  }
}

/**
 * Parses and validates an uploaded .zip backup file (unencrypted, or encrypted when `password` is supplied).
 */
export async function parseArchiveBackupZip(
  input: Blob | ArrayBuffer | Uint8Array,
  password?: string
): Promise<{ valid: true; snapshot: ArchiveSnapshot; exportedAt: number } | { valid: false }> {
  const inspected = await inspectArchiveBackupZip(input);
  if (inspected.status === 'ready') {
    return {
      valid: true,
      snapshot: inspected.snapshot,
      exportedAt: inspected.exportedAt,
    };
  }
  if (inspected.status === 'encrypted' && password) {
    const decrypted = await decryptArchiveBackupZip(
      inspected.rawZipBytes,
      inspected.header,
      password
    );
    if (decrypted.status === 'ready') {
      return {
        valid: true,
        snapshot: decrypted.snapshot,
        exportedAt: decrypted.exportedAt,
      };
    }
  }
  return { valid: false };
}
