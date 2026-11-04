/**
 * Memory-safe, zero-compression (PKZIP STORE) streaming ZIP writer.
 * Processes one file at a time in small slices (~512 KB) so exporting hundreds of MBs
 * of high-resolution photos never triggers OutOfMemory crashes on Android WebView or mobile browsers.
 */

export interface StreamingZipSourceEntry {
  /** Relative path inside the ZIP archive (UTF-8 supported, forward slashes) */
  path: string;
  /** Lazy provider or direct Blob/Uint8Array so callers don't materialize all files at once */
  getData: () => Promise<Blob | Uint8Array> | Blob | Uint8Array;
  /** Optional last-modified timestamp in ms */
  modifiedAt?: number;
}

export interface ZipWriteSink {
  writeBytes: (bytes: Uint8Array) => Promise<void> | void;
  writeBlob: (blob: Blob, onChunkProgress?: (writtenBytes: number) => void) => Promise<void>;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function updateCrc32(crc: number, bytes: Uint8Array): number {
  let c = crc ^ 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC32_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

const CRC_SLICE_BYTES = 512 * 1024; // 512 KB transient slice

export async function computeBlobCrc32(blob: Blob): Promise<{ crc32: number; size: number }> {
  const total = blob.size;
  let crc = 0;
  let offset = 0;

  while (offset < total) {
    const end = Math.min(offset + CRC_SLICE_BYTES, total);
    const buf = await blob.slice(offset, end).arrayBuffer();
    crc = updateCrc32(crc, new Uint8Array(buf));
    offset = end;
  }

  return { crc32: crc >>> 0, size: total };
}

function toDosDateTime(timestampMs = Date.now()): { dosTime: number; dosDate: number } {
  const d = new Date(timestampMs);
  const year = Math.max(1980, Math.min(2107, d.getFullYear()));
  const month = d.getMonth() + 1;
  const day = d.getDate();
  const hours = d.getHours();
  const minutes = d.getMinutes();
  const seconds = Math.floor(d.getSeconds() / 2);

  const dosTime = ((hours & 0x1f) << 11) | ((minutes & 0x3f) << 5) | (seconds & 0x1f);
  const dosDate = (((year - 1980) & 0x7f) << 9) | ((month & 0x0f) << 5) | (day & 0x1f);
  return { dosTime, dosDate };
}

interface CentralDirMeta {
  nameBytes: Uint8Array;
  dosTime: number;
  dosDate: number;
  crc32: number;
  size: number;
  localHeaderOffset: number;
}

function buildLocalFileHeader(
  nameBytes: Uint8Array,
  dosTime: number,
  dosDate: number,
  crc32: number,
  size: number
): Uint8Array {
  const header = new Uint8Array(30 + nameBytes.length);
  const view = new DataView(header.buffer);

  view.setUint32(0, 0x04034b50, true); // Local file header signature
  view.setUint16(4, 20, true); // Version needed to extract (2.0)
  view.setUint16(6, 0x0800, true); // General purpose bit flag: UTF-8 filename
  view.setUint16(8, 0, true); // Compression method: 0 = STORE
  view.setUint16(10, dosTime, true);
  view.setUint16(12, dosDate, true);
  view.setUint32(14, crc32 >>> 0, true);
  view.setUint32(18, size >>> 0, true); // Compressed size
  view.setUint32(22, size >>> 0, true); // Uncompressed size
  view.setUint16(26, nameBytes.length, true);
  view.setUint16(28, 0, true); // Extra field length
  header.set(nameBytes, 30);

  return header;
}

function buildCentralDirectoryHeader(meta: CentralDirMeta): Uint8Array {
  const header = new Uint8Array(46 + meta.nameBytes.length);
  const view = new DataView(header.buffer);

  view.setUint32(0, 0x02014b50, true); // Central directory file header signature
  view.setUint16(4, 20, true); // Version made by
  view.setUint16(6, 20, true); // Version needed to extract
  view.setUint16(8, 0x0800, true); // UTF-8 filename flag
  view.setUint16(10, 0, true); // Compression method: STORE
  view.setUint16(12, meta.dosTime, true);
  view.setUint16(14, meta.dosDate, true);
  view.setUint32(16, meta.crc32 >>> 0, true);
  view.setUint32(20, meta.size >>> 0, true);
  view.setUint32(24, meta.size >>> 0, true);
  view.setUint16(28, meta.nameBytes.length, true);
  view.setUint16(30, 0, true); // Extra field length
  view.setUint16(32, 0, true); // File comment length
  view.setUint16(34, 0, true); // Disk number start
  view.setUint16(36, 0, true); // Internal file attributes
  view.setUint32(38, 0, true); // External file attributes
  view.setUint32(42, meta.localHeaderOffset >>> 0, true);
  header.set(meta.nameBytes, 46);

  return header;
}

function buildEndOfCentralDirectory(
  entryCount: number,
  centralDirSize: number,
  centralDirOffset: number
): Uint8Array {
  const eocd = new Uint8Array(22);
  const view = new DataView(eocd.buffer);

  view.setUint32(0, 0x06054b50, true); // EOCD signature
  view.setUint16(4, 0, true); // Disk number
  view.setUint16(6, 0, true); // Disk with start of central directory
  view.setUint16(8, entryCount, true); // Entries on this disk
  view.setUint16(10, entryCount, true); // Total entries
  view.setUint32(12, centralDirSize >>> 0, true);
  view.setUint32(16, centralDirOffset >>> 0, true);
  view.setUint16(20, 0, true); // Comment length

  return eocd;
}

/**
 * Streams a list of entries into a ZipWriteSink one entry at a time.
 */
export async function writeStreamingZip(
  entries: StreamingZipSourceEntry[],
  sink: ZipWriteSink,
  onProgress?: (percent: number) => void
): Promise<void> {
  const encoder = new TextEncoder();
  const centralRecords: CentralDirMeta[] = [];
  let offset = 0;
  const totalEntries = Math.max(1, entries.length);

  onProgress?.(0);

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const cleanPath = entry.path.replace(/^\/+/, '').replace(/\\/g, '/');
    const nameBytes = encoder.encode(cleanPath);
    const { dosTime, dosDate } = toDosDateTime(entry.modifiedAt);
    const localHeaderOffset = offset;

    const payload = await entry.getData();

    if (payload instanceof Uint8Array) {
      const crc32 = updateCrc32(0, payload);
      const size = payload.byteLength;
      const localHeader = buildLocalFileHeader(nameBytes, dosTime, dosDate, crc32, size);

      await sink.writeBytes(localHeader);
      if (size > 0) {
        await sink.writeBytes(payload);
      }

      offset += localHeader.byteLength + size;
      centralRecords.push({
        nameBytes,
        dosTime,
        dosDate,
        crc32,
        size,
        localHeaderOffset,
      });
    } else {
      const { crc32, size } = await computeBlobCrc32(payload);
      const localHeader = buildLocalFileHeader(nameBytes, dosTime, dosDate, crc32, size);

      await sink.writeBytes(localHeader);
      if (size > 0) {
        await sink.writeBlob(payload, (writtenInBlob) => {
          if (onProgress && size > 0) {
            const frac = (i + writtenInBlob / size) / totalEntries;
            onProgress(Math.min(99, Math.round(frac * 100)));
          }
        });
      }

      offset += localHeader.byteLength + size;
      centralRecords.push({
        nameBytes,
        dosTime,
        dosDate,
        crc32,
        size,
        localHeaderOffset,
      });
    }

    onProgress?.(Math.min(99, Math.round(((i + 1) / totalEntries) * 100)));
    // Yield periodically so the UI stays responsive on mobile devices
    if (i % 3 === 2) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  const centralDirOffset = offset;
  let centralDirSize = 0;

  for (const meta of centralRecords) {
    const cdHeader = buildCentralDirectoryHeader(meta);
    await sink.writeBytes(cdHeader);
    centralDirSize += cdHeader.byteLength;
  }

  const eocd = buildEndOfCentralDirectory(
    centralRecords.length,
    centralDirSize,
    centralDirOffset
  );
  await sink.writeBytes(eocd);
  onProgress?.(100);
}

/**
 * Zero-copy browser Blob sink: keeps photo Blobs as lazy disk-backed Blob references
 * rather than copying hundreds of megabytes into JavaScript Uint8Arrays.
 */
export function createBrowserBlobSink(): ZipWriteSink & { toBlob: () => Blob } {
  const parts: BlobPart[] = [];

  return {
    writeBytes(bytes: Uint8Array) {
      const copy = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(copy).set(bytes);
      parts.push(copy);
    },
    async writeBlob(blob: Blob, onChunkProgress?: (writtenBytes: number) => void) {
      parts.push(blob);
      onChunkProgress?.(blob.size);
    },
    toBlob() {
      return new Blob(parts, { type: 'application/zip' });
    },
  };
}
