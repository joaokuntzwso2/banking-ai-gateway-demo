import crypto from 'node:crypto';
import path from 'node:path';
import { TextDecoder } from 'node:util';

export const DEFAULT_MAX_UPLOAD_BYTES = 1024 * 1024;

const ALLOWED_EXTENSIONS = new Map([
  ['.txt', new Set(['text/plain', 'application/octet-stream'])],
  ['.md', new Set(['text/markdown', 'text/plain', 'application/octet-stream'])],
  ['.json', new Set(['application/json', 'text/plain', 'application/octet-stream'])],
  ['.csv', new Set(['text/csv', 'text/plain', 'application/octet-stream'])],
]);

const ACTIVE_CONTENT = /<\s*(script|iframe|object|embed)\b|\bon(?:error|load|click)\s*=|javascript\s*:/i;
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

export function inspectUploadedFile({ buffer, fileName, contentType, maxBytes = DEFAULT_MAX_UPLOAD_BYTES }) {
  if (!Buffer.isBuffer(buffer)) return failure(400, 'INVALID_FILE_BODY', 'The uploaded file body must be binary data.');
  if (buffer.length === 0) return failure(400, 'EMPTY_FILE', 'The uploaded file is empty.');
  if (buffer.length > maxBytes) return failure(413, 'FILE_TOO_LARGE', `The uploaded file exceeds the ${maxBytes}-byte limit.`, { maximumBytes: maxBytes, actualBytes: buffer.length });

  const decodedName = decodeFileName(fileName);
  if (!decodedName.ok) return decodedName;
  const safeName = decodedName.fileName;
  const extension = path.extname(safeName).toLowerCase();
  const allowedContentTypes = ALLOWED_EXTENSIONS.get(extension);
  if (!allowedContentTypes) return failure(415, 'UNSUPPORTED_FILE_TYPE', `Files with extension ${extension || '(none)'} are not accepted by the demo parser.`, { allowedExtensions: [...ALLOWED_EXTENSIONS.keys()] });

  const normalizedContentType = String(contentType || 'application/octet-stream').split(';', 1)[0].trim().toLowerCase();
  if (!allowedContentTypes.has(normalizedContentType)) return failure(415, 'CONTENT_TYPE_MISMATCH', `Content type ${normalizedContentType || '(missing)'} is not allowed for ${extension}.`, { allowedContentTypes: [...allowedContentTypes] });

  const magic = detectUnsupportedMagic(buffer);
  if (magic) return failure(415, 'BINARY_OR_ARCHIVE_REJECTED', `${magic} files require a separately sandboxed parser, malware scanning, and content disarm/reconstruction before ingestion.`);
  if (buffer.includes(0)) return failure(415, 'BINARY_CONTENT_REJECTED', 'NUL bytes indicate binary content that is not accepted by the text ingestion path.');

  let content;
  try {
    content = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    return failure(415, 'INVALID_UTF8', 'The file is not valid UTF-8 text.');
  }
  content = content.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  if (!content.trim()) return failure(400, 'EMPTY_TEXT_CONTENT', 'The uploaded file contains no meaningful text.');
  if (extension === '.json') {
    try { JSON.parse(content); }
    catch (error) { return failure(400, 'INVALID_JSON_FILE', 'The uploaded JSON file is not syntactically valid.', { parserMessage: error instanceof Error ? error.message : String(error) }); }
  }

  const zeroWidthCount = (content.match(ZERO_WIDTH) ?? []).length;
  const controlCharacterCount = (content.match(CONTROL_CHARACTERS) ?? []).length;
  const preflightReasons = [];
  if (ACTIVE_CONTENT.test(content)) preflightReasons.push('FILE_ACTIVE_CONTENT');
  if (controlCharacterCount > 0) preflightReasons.push('FILE_CONTROL_CHARACTERS');

  return {
    ok: true,
    content,
    metadata: {
      originalFileName: safeName,
      extension,
      declaredContentType: normalizedContentType,
      sizeBytes: buffer.length,
      rawSha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      zeroWidthCharacterCount: zeroWidthCount,
      controlCharacterCount,
      parser: extension === '.json' ? 'strict-json-and-utf8-text' : 'strict-utf8-text',
      parserScope: 'txt, md, json, csv only',
    },
    preflightReasons,
  };
}

function decodeFileName(value) {
  let candidate = String(value || '').trim();
  try { candidate = decodeURIComponent(candidate); }
  catch { return failure(400, 'INVALID_FILE_NAME', 'The encoded file name is invalid.'); }
  if (!candidate || candidate.length > 180) return failure(400, 'INVALID_FILE_NAME', 'A file name between 1 and 180 characters is required.');
  if (candidate !== path.basename(candidate) || /[/\\]/.test(candidate) || candidate === '.' || candidate === '..') return failure(400, 'FILE_NAME_TRAVERSAL', 'Directory separators and traversal sequences are not allowed in uploaded file names.');
  if (/[\u0000-\u001F\u007F]/.test(candidate)) return failure(400, 'INVALID_FILE_NAME', 'Control characters are not allowed in file names.');
  return { ok: true, fileName: candidate };
}

function detectUnsupportedMagic(buffer) {
  if (buffer.subarray(0, 4).toString('ascii') === '%PDF') return 'PDF';
  if (buffer[0] === 0x50 && buffer[1] === 0x4b) return 'ZIP/Office Open XML';
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) return 'Windows executable';
  if (buffer[0] === 0x7f && buffer.subarray(1, 4).toString('ascii') === 'ELF') return 'ELF executable';
  if (buffer[0] === 0x1f && buffer[1] === 0x8b) return 'GZIP archive';
  return null;
}

function failure(status, code, message, details = {}) { return { ok: false, status, body: { error: code, message, ...details } }; }
