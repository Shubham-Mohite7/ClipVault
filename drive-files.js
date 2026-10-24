const MAX_FILE_SIZE = 4 * 1024 * 1024;
const ALLOWED_MIME_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "application/pdf",
]);

function uploadError(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function sanitizeFilename(name) {
  return String(name || "")
    .replace(/[\\/]/g, "")
    .replace(/[\x00-\x1f\x7f]/g, "")
    .trim()
    .slice(0, 100) || "file";
}

function hasValidMagicBytes(mime, body) {
  if (!Buffer.isBuffer(body)) return false;
  switch (mime) {
    case "image/png":
      return body.length >= 4 && body.subarray(0, 4).equals(Buffer.from("89504e47", "hex"));
    case "image/jpeg":
      return body.length >= 3 && body.subarray(0, 3).equals(Buffer.from("ffd8ff", "hex"));
    case "image/gif":
      return body.subarray(0, 6).toString("ascii") === "GIF87a"
        || body.subarray(0, 6).toString("ascii") === "GIF89a";
    case "image/webp":
      return body.length >= 12 && body.toString("ascii", 0, 4) === "RIFF"
        && body.toString("ascii", 8, 12) === "WEBP";
    case "application/pdf":
      return body.length >= 5 && body.subarray(0, 5).toString("ascii") === "%PDF-";
    default:
      return false;
  }
}

function validateUpload(mime, body, name) {
  if (!ALLOWED_MIME_TYPES.has(mime)) throw uploadError("Unsupported file type");
  if (!Buffer.isBuffer(body)) throw uploadError("Invalid file body");
  if (body.length > MAX_FILE_SIZE) throw uploadError("File exceeds 4 MB", 413);
  if (!hasValidMagicBytes(mime, body)) throw uploadError("File content does not match its type");
  return { mime, body, name: sanitizeFilename(name), size: body.length };
}

module.exports = { ALLOWED_MIME_TYPES, MAX_FILE_SIZE, hasValidMagicBytes, sanitizeFilename, validateUpload };
