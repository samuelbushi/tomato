import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
const MAX_SECRET_BYTES = 32768;
const MAX_ENVELOPE_CHARS = Math.ceil(MAX_SECRET_BYTES * 4 / 3) + 50;

/** Deployment-owned key. The key belongs to the app/backup bundle, never the prober.
 * Associated data binds ciphertext to its account, record and purpose.
 */
export class SecretCodec {
  private readonly key: Buffer;
  constructor(encodedKey: string) {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(encodedKey)) throw new Error("data_key_requires_32_bytes_base64");
    this.key = Buffer.from(encodedKey, "base64");
    if (this.key.byteLength !== 32) throw new Error("data_key_requires_32_bytes_base64");
  }
  seal(value: string, purpose: string): string {
    if (Buffer.byteLength(value) > MAX_SECRET_BYTES) throw new Error("stored_secret_too_large");
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(purpose));
    const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return `tomato:v1:${iv.toString("base64url")}:${cipher.getAuthTag().toString("base64url")}:${encrypted.toString("base64url")}`;
  }
  open(value: string, purpose: string): string {
    if (typeof value !== "string" || value.length > MAX_ENVELOPE_CHARS) throw new Error("stored_secret_invalid");
    const parts = value.split(":");
    if (parts.length !== 5 || parts[0] !== "tomato" || parts[1] !== "v1" || !/^[A-Za-z0-9_-]{16}$/.test(parts[2]!) || !/^[A-Za-z0-9_-]{22}$/.test(parts[3]!) || !/^[A-Za-z0-9_-]*$/.test(parts[4]!)) throw new Error("stored_secret_invalid");
    const decipher = createDecipheriv("aes-256-gcm", this.key, Buffer.from(parts[2]!, "base64url"));
    decipher.setAAD(Buffer.from(purpose));
    decipher.setAuthTag(Buffer.from(parts[3]!, "base64url"));
    try {
      return Buffer.concat([decipher.update(Buffer.from(parts[4]!, "base64url")), decipher.final()]).toString("utf8");
    } catch { throw new Error("stored_secret_authentication_failed"); }
  }
}
