import type { BookFolder, GroupFolder, PhotoItem } from '../types/archive';
import { hasPasswordLock, normalizePasswordLockMeta } from './securityCrypto';

export interface BackupPhotoEntry {
  id: string;
  folderId: string;
  name: string;
  mimeType: string;
  createdAt: number;
  size?: number;
  assetPath: string;
}

export interface ArchiveBackupManifest {
  format: 'data-management-backup';
  version: 1 | 2;
  exportedAt: number;
  groups: GroupFolder[];
  folders: BookFolder[];
  photos: BackupPhotoEntry[];
}

export interface ArchiveSnapshot {
  groups: GroupFolder[];
  folders: BookFolder[];
  photos: PhotoItem[];
}

export function buildBackupDateStamp(timestamp = Date.now()): string {
  const d = new Date(timestamp);
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function isObjectRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

/**
 * Validates and normalizes a parsed JSON manifest from a backup ZIP archive.
 * Ensures referential integrity (no orphaned groupIds or orphaned photo folderIds).
 */
export function validateAndNormalizeBackupManifest(
  raw: unknown
): { valid: true; manifest: ArchiveBackupManifest } | { valid: false } {
  if (!isObjectRecord(raw)) {
    return { valid: false };
  }
  if (
    raw.format !== 'data-management-backup' ||
    (raw.version !== 1 && raw.version !== 2)
  ) {
    return { valid: false };
  }
  if (!Array.isArray(raw.groups) || !Array.isArray(raw.folders) || !Array.isArray(raw.photos)) {
    return { valid: false };
  }

  const now = Date.now();
  const groups: GroupFolder[] = [];
  const validGroupIds = new Set<string>();

  for (const item of raw.groups) {
    if (!isObjectRecord(item)) return { valid: false };
    const id = typeof item.id === 'string' ? item.id.trim() : '';
    const name = typeof item.name === 'string' ? item.name.normalize('NFC').trim() : '';
    if (!id || !name) return { valid: false };
    if (validGroupIds.has(id)) continue;

    const normalizedLock = normalizePasswordLockMeta(item.passwordLock);
    validGroupIds.add(id);
    groups.push({
      id,
      name,
      createdAt: typeof item.createdAt === 'number' && Number.isFinite(item.createdAt) ? item.createdAt : now,
      updatedAt: typeof item.updatedAt === 'number' && Number.isFinite(item.updatedAt) ? item.updatedAt : now,
      ...(normalizedLock ? { passwordLock: normalizedLock } : {}),
    });
  }

  const folders: BookFolder[] = [];
  const validFolderIds = new Set<string>();

  for (const item of raw.folders) {
    if (!isObjectRecord(item)) return { valid: false };
    const id = typeof item.id === 'string' ? item.id.trim() : '';
    const name = typeof item.name === 'string' ? item.name.normalize('NFC').trim() : '';
    if (!id || !name) return { valid: false };
    if (validFolderIds.has(id)) continue;

    const rawGroupId = typeof item.groupId === 'string' ? item.groupId.trim() : null;
    const safeGroupId = rawGroupId && validGroupIds.has(rawGroupId) ? rawGroupId : null;
    const normalizedLock = normalizePasswordLockMeta(item.passwordLock);

    validFolderIds.add(id);
    folders.push({
      id,
      name,
      createdAt: typeof item.createdAt === 'number' && Number.isFinite(item.createdAt) ? item.createdAt : now,
      updatedAt: typeof item.updatedAt === 'number' && Number.isFinite(item.updatedAt) ? item.updatedAt : now,
      groupId: safeGroupId,
      ...(normalizedLock ? { passwordLock: normalizedLock } : {}),
    });
  }

  const photos: BackupPhotoEntry[] = [];
  const seenPhotoIds = new Set<string>();

  for (const item of raw.photos) {
    if (!isObjectRecord(item)) return { valid: false };
    const id = typeof item.id === 'string' ? item.id.trim() : '';
    const folderId = typeof item.folderId === 'string' ? item.folderId.trim() : '';
    const name = typeof item.name === 'string' ? item.name.normalize('NFC').trim() : '';
    const mimeType = typeof item.mimeType === 'string' && item.mimeType ? item.mimeType : 'image/jpeg';
    const assetPath = typeof item.assetPath === 'string' ? item.assetPath.trim() : '';

    if (!id || !folderId || !name || !assetPath) {
      return { valid: false };
    }
    if (!validFolderIds.has(folderId)) {
      continue;
    }
    if (seenPhotoIds.has(id)) {
      continue;
    }

    seenPhotoIds.add(id);
    photos.push({
      id,
      folderId,
      name,
      mimeType,
      createdAt: typeof item.createdAt === 'number' && Number.isFinite(item.createdAt) ? item.createdAt : now,
      ...(typeof item.size === 'number' && item.size >= 0 ? { size: item.size } : {}),
      assetPath,
    });
  }

  return {
    valid: true,
    manifest: {
      format: 'data-management-backup',
      version: raw.version === 2 ? 2 : 1,
      exportedAt: typeof raw.exportedAt === 'number' && Number.isFinite(raw.exportedAt) ? raw.exportedAt : now,
      groups,
      folders,
      photos,
    },
  };
}

/**
 * Safely merges an imported backup archive into existing local data without deleting existing items.
 * Deduplicates by ID and normalized names so group/folder uniqueness and photo links remain intact.
 */
export function mergeArchiveData(
  current: ArchiveSnapshot,
  incoming: ArchiveSnapshot
): {
  merged: ArchiveSnapshot;
  addedGroups: number;
  addedFolders: number;
  addedPhotos: number;
} {
  const nextGroups = current.groups.map((g) => ({ ...g }));
  const groupIdMap = new Map<string, string>();
  let addedGroups = 0;

  for (const incGroup of incoming.groups) {
    const byIdIdx = nextGroups.findIndex((g) => g.id === incGroup.id);
    if (byIdIdx !== -1) {
      groupIdMap.set(incGroup.id, nextGroups[byIdIdx].id);
      if (!hasPasswordLock(nextGroups[byIdIdx]) && hasPasswordLock(incGroup)) {
        nextGroups[byIdIdx] = {
          ...nextGroups[byIdIdx],
          passwordLock: incGroup.passwordLock,
        };
      }
      continue;
    }
    const normName = incGroup.name.normalize('NFC').trim().toLowerCase();
    const byNameIdx = nextGroups.findIndex(
      (g) => g.name.normalize('NFC').trim().toLowerCase() === normName
    );
    if (byNameIdx !== -1) {
      groupIdMap.set(incGroup.id, nextGroups[byNameIdx].id);
      if (!hasPasswordLock(nextGroups[byNameIdx]) && hasPasswordLock(incGroup)) {
        nextGroups[byNameIdx] = {
          ...nextGroups[byNameIdx],
          passwordLock: incGroup.passwordLock,
        };
      }
      continue;
    }
    nextGroups.push({ ...incGroup });
    groupIdMap.set(incGroup.id, incGroup.id);
    addedGroups++;
  }

  const validGroupIds = new Set(nextGroups.map((g) => g.id));
  const nextFolders = current.folders.map((f) => ({ ...f }));
  const folderIdMap = new Map<string, string>();
  let addedFolders = 0;

  for (const incFolder of incoming.folders) {
    const mappedGroupId = incFolder.groupId ? groupIdMap.get(incFolder.groupId) ?? null : null;
    const safeGroupId = mappedGroupId && validGroupIds.has(mappedGroupId) ? mappedGroupId : null;

    const existingIdx = nextFolders.findIndex((f) => f.id === incFolder.id);
    if (existingIdx !== -1) {
      folderIdMap.set(incFolder.id, nextFolders[existingIdx].id);
      const updatedExisting: BookFolder = { ...nextFolders[existingIdx] };
      if (!updatedExisting.groupId && safeGroupId) {
        updatedExisting.groupId = safeGroupId;
      }
      if (!hasPasswordLock(updatedExisting) && hasPasswordLock(incFolder)) {
        updatedExisting.passwordLock = incFolder.passwordLock;
      }
      nextFolders[existingIdx] = updatedExisting;
      continue;
    }

    const normName = incFolder.name.normalize('NFC').trim().toLowerCase();
    const byNameIdx = nextFolders.findIndex(
      (f) => f.name.normalize('NFC').trim().toLowerCase() === normName
    );
    if (byNameIdx !== -1) {
      folderIdMap.set(incFolder.id, nextFolders[byNameIdx].id);
      if (!hasPasswordLock(nextFolders[byNameIdx]) && hasPasswordLock(incFolder)) {
        nextFolders[byNameIdx] = {
          ...nextFolders[byNameIdx],
          passwordLock: incFolder.passwordLock,
        };
      }
      continue;
    }

    const folderToInsert: BookFolder = {
      ...incFolder,
      groupId: safeGroupId,
    };
    nextFolders.push(folderToInsert);
    folderIdMap.set(incFolder.id, folderToInsert.id);
    addedFolders++;
  }

  const validFolderIds = new Set(nextFolders.map((f) => f.id));
  const nextPhotos = [...current.photos];
  const existingPhotoIds = new Set(nextPhotos.map((p) => p.id));
  let addedPhotos = 0;

  for (const incPhoto of incoming.photos) {
    const targetFolderId = folderIdMap.get(incPhoto.folderId) ?? incPhoto.folderId;
    if (!validFolderIds.has(targetFolderId)) {
      continue;
    }
    if (existingPhotoIds.has(incPhoto.id)) {
      continue;
    }
    existingPhotoIds.add(incPhoto.id);
    nextPhotos.push({
      ...incPhoto,
      folderId: targetFolderId,
    });
    addedPhotos++;
  }

  return {
    merged: {
      groups: nextGroups,
      folders: nextFolders,
      photos: nextPhotos,
    },
    addedGroups,
    addedFolders,
    addedPhotos,
  };
}
