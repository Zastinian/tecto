/**
 * TECTO Core — Encrypt & Decrypt
 *
 * Implements the TECTO token protocol using XChaCha20-Poly1305 (AEAD)
 * for authenticated encryption. Tokens are fully opaque — their payload
 * cannot be read without the 32-byte secret key.
 *
 * **Token format:** `tecto.v1.<kid>.<nonce_b64url>.<ciphertext_b64url>`
 *
 * @security
 * - A fresh 24-byte nonce is generated via CSPRNG for every encryption call.
 *   XChaCha20's 192-bit nonce space makes collision probability negligible
 *   (birthday bound at ~2^96 messages per key).
 * - Poly1305 provides authentication: any modification to the ciphertext
 *   or nonce causes decryption to fail.
 * - Decryption failures always throw a generic `InvalidSignatureError`
 *   to prevent oracle attacks.
 *
 * @module
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { base64url } from "@scure/base";

import {
  InvalidSignatureError,
  TectoError,
  TokenExpiredError,
  TokenNotActiveError,
} from "./errors.js";
import type { KeyStoreAdapter, SignOptions, TectoCoderOptions, TectoPayload } from "./types.js";

const TECTO_PREFIX = "tecto";
const TECTO_VERSION = "v1";
const NONCE_LENGTH = 24;
const SEGMENT_COUNT = 5;
const DEFAULT_MAX_PAYLOAD_SIZE = 1024 * 1024;
const VALID_KID_PATTERN = /^[a-zA-Z0-9._-]+$/;

/**
 * Parses a human-readable duration string into seconds.
 *
 * @param duration - A string like `"1h"`, `"30m"`, `"7d"`, `"120s"`.
 * @returns The duration in seconds.
 * @throws {TectoError} If the format is invalid or exceeds maximum allowed value.
 *
 * @security Strict regex prevents injection of unexpected values.
 * Duration is capped at 10 years to prevent overflow and unrealistic values.
 */
function parseDuration(duration: string): number {
  const match = /^(\d+)\s*(s|m|h|d)$/i.exec(duration);
  if (!match) {
    throw new TectoError(
      `Invalid duration format: "${duration}". Expected format: <number><unit> where unit is s, m, h, or d.`,
      "TECTO_INVALID_DURATION",
    );
  }

  const value = Number.parseInt(match[1]!, 10);
  const unit = match[2]!.toLowerCase();

  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
  };

  const multiplier = multipliers[unit];
  if (multiplier === undefined) {
    throw new TectoError(`Unknown duration unit: "${unit}"`, "TECTO_INVALID_DURATION");
  }

  const result = value * multiplier;
  const MAX_DURATION = 86400 * 365 * 10;
  if (result > MAX_DURATION) {
    throw new TectoError(
      `Duration exceeds maximum allowed value of 10 years: "${duration}"`,
      "TECTO_INVALID_DURATION",
    );
  }

  return result;
}

/**
 * Generates a v4-style random identifier for the `jti` claim.
 *
 * @returns A UUID v4 string without hyphens (32 hex characters = 128 bits).
 *
 * @security Uses CSPRNG via `crypto.randomUUID()`. The 128-bit space
 * provides sufficient collision resistance for JWT ID purposes (~2^64 birthday bound).
 */
function generateJti(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

/**
 * The main TECTO encoder/decoder. Encrypts payloads into opaque tokens
 * and decrypts them back, with automatic claim validation.
 *
 * @security
 * - Every `encrypt()` call generates a unique 24-byte nonce from CSPRNG.
 *   XChaCha20's 192-bit nonce space provides ~2^96 birthday bound per key.
 *   Rotate keys frequently (e.g., daily/weekly) to stay well below collision risk.
 * - Every `decrypt()` failure throws a generic `InvalidSignatureError`.
 * - `exp`, `nbf`, `iat` claims are validated for correct types (number) to prevent
 *   type confusion attacks. Custom field types are NOT validated.
 * - Registered claims (`exp`, `nbf`, `iat`, `jti`, `iss`, `aud`) are type-checked
 *   during deserialization.
 * - Plaintext buffers are zeroed after encryption and decryption.
 * - Payloads are limited to 1 MB to prevent DoS via oversized tokens.
 * - JTI is for token replay detection, not prevention. Use a separate
 *   blacklist/allowlist for robust replay protection.
 *
 * @example
 * ```ts
 * const store = new MemoryKeyStore();
 * store.addKey("k1", generateSecureKey());
 *
 * const coder = new TectoCoder(store);
 * const token = coder.encrypt({ userId: 42 }, { expiresIn: "1h" });
 * const payload = coder.decrypt(token);
 * ```
 */
export class TectoCoder {
  private readonly keyStore: KeyStoreAdapter;
  private readonly maxPayloadSize: number;

  /**
   * Creates a new `TectoCoder` bound to the given key store.
   *
   * @param keyStore - Any implementation of `KeyStoreAdapter`.
   * @param options - Optional configuration (e.g., custom maxPayloadSize).
   *
   * @example
   * ```ts
   * const coder = new TectoCoder(store, { maxPayloadSize: 10 * 1024 * 1024 });
   * ```
   */
  constructor(keyStore: KeyStoreAdapter, options?: TectoCoderOptions) {
    this.keyStore = keyStore;
    this.maxPayloadSize = options?.maxPayloadSize ?? DEFAULT_MAX_PAYLOAD_SIZE;

    if (!Number.isInteger(this.maxPayloadSize) || this.maxPayloadSize <= 0) {
      throw new TectoError("maxPayloadSize must be a positive integer", "TECTO_INVALID_CONFIG");
    }
  }

  /**
   * Encrypts a payload into an opaque TECTO token.
   *
   * @typeParam T - The shape of the custom payload fields.
   * @param payload - The data to encrypt. Must be JSON-serializable.
   * @param options - Optional signing options (expiration, issuer, etc.).
   * @returns An opaque token string in the format `tecto.v1.<kid>.<nonce>.<ciphertext>`.
   *
   * @security
   * - A fresh 24-byte nonce is generated for EVERY call via CSPRNG.
   *   Never reuse nonces — XChaCha20's security relies on nonce uniqueness.
   * - The `iat` claim is always set to the current time.
   * - If `expiresIn` is provided, `exp` is computed as `iat + duration`.
   */
  encrypt<T extends Record<string, unknown>>(payload: T, options?: SignOptions): string {
    const kid = this.keyStore.getCurrentKeyId();
    const key = this.keyStore.getKey(kid);

    const now = Math.floor(Date.now() / 1000);

    const claims: Record<string, unknown> = {
      ...payload,
      iat: now,
      jti: options?.jti ?? generateJti(),
    };

    if (options?.expiresIn) {
      claims.exp = now + parseDuration(options.expiresIn);
    }

    if (options?.notBefore) {
      claims.nbf = now + parseDuration(options.notBefore);
    }

    if (options?.issuer) {
      claims.iss = options.issuer;
    }

    if (options?.audience) {
      claims.aud = options.audience;
    }

    const plaintext = new TextEncoder().encode(JSON.stringify(claims));

    if (plaintext.byteLength > this.maxPayloadSize) {
      throw new TectoError(
        `Payload exceeds maximum size of ${this.maxPayloadSize} bytes`,
        "TECTO_PAYLOAD_TOO_LARGE",
      );
    }

    const nonce = new Uint8Array(NONCE_LENGTH);
    crypto.getRandomValues(nonce);

    const cipher = xchacha20poly1305(key, nonce);
    const ciphertext = cipher.encrypt(plaintext);

    plaintext.fill(0);

    const nonceB64 = base64url.encode(nonce).replace(/=+$/, "");
    const ciphertextB64 = base64url.encode(ciphertext).replace(/=+$/, "");

    return `${TECTO_PREFIX}.${TECTO_VERSION}.${kid}.${nonceB64}.${ciphertextB64}`;
  }

  /**
   * Decrypts and validates an opaque TECTO token.
   *
   * @typeParam T - The expected shape of the custom payload fields.
   * @param token - The opaque token string to decrypt.
   * @returns The decrypted and validated payload.
   * @throws {InvalidSignatureError} If the token structure is invalid,
   *   the key is wrong, or the ciphertext has been tampered with.
   * @throws {TokenExpiredError} If the `exp` claim is in the past.
   * @throws {TokenNotActiveError} If the `nbf` claim is in the future.
   *
   * @security
   * - All structural and cryptographic failures throw the same generic
   *   `InvalidSignatureError` to prevent oracle attacks.
   * - Time-based claim errors (`exp`, `nbf`) are thrown only AFTER
   *   successful decryption, so they cannot be used to probe ciphertext.
   */
  decrypt<T extends Record<string, unknown>>(token: string): TectoPayload<T> {
    let segments: string[];
    try {
      segments = token.split(".");
    } catch {
      throw new InvalidSignatureError();
    }

    if (segments.length !== SEGMENT_COUNT) {
      throw new InvalidSignatureError();
    }

    const [prefix, version, kid, nonceB64, ciphertextB64] = segments as [
      string,
      string,
      string,
      string,
      string,
    ];

    if (prefix !== TECTO_PREFIX || version !== TECTO_VERSION) {
      throw new InvalidSignatureError();
    }

    if (!kid || !VALID_KID_PATTERN.test(kid)) {
      throw new InvalidSignatureError();
    }

    let key: Uint8Array;
    try {
      key = this.keyStore.getKey(kid);
    } catch {
      throw new InvalidSignatureError();
    }

    let nonce: Uint8Array;
    let ciphertext: Uint8Array;
    try {
      const pad = (s: string) => s + "=".repeat((4 - (s.length % 4)) % 4);
      nonce = base64url.decode(pad(nonceB64));
      ciphertext = base64url.decode(pad(ciphertextB64));
    } catch {
      throw new InvalidSignatureError();
    }

    if (nonce.byteLength !== NONCE_LENGTH) {
      throw new InvalidSignatureError();
    }

    let plaintext: Uint8Array;
    try {
      const cipher = xchacha20poly1305(key, nonce);
      plaintext = cipher.decrypt(ciphertext);
    } catch {
      throw new InvalidSignatureError();
    }

    let payload: TectoPayload<T>;
    try {
      const decoded = new TextDecoder().decode(plaintext);
      payload = JSON.parse(decoded) as TectoPayload<T>;
    } catch {
      throw new InvalidSignatureError();
    } finally {
      plaintext.fill(0);
    }

    if (typeof payload.exp !== "undefined" && typeof payload.exp !== "number") {
      throw new InvalidSignatureError();
    }
    if (typeof payload.nbf !== "undefined" && typeof payload.nbf !== "number") {
      throw new InvalidSignatureError();
    }
    if (typeof payload.iat !== "undefined" && typeof payload.iat !== "number") {
      throw new InvalidSignatureError();
    }
    if (typeof payload.jti !== "undefined" && typeof payload.jti !== "string") {
      throw new InvalidSignatureError();
    }
    if (typeof payload.iss !== "undefined" && typeof payload.iss !== "string") {
      throw new InvalidSignatureError();
    }
    if (typeof payload.aud !== "undefined" && typeof payload.aud !== "string") {
      throw new InvalidSignatureError();
    }

    const now = Math.floor(Date.now() / 1000);

    if (typeof payload.exp === "number" && payload.exp <= now) {
      throw new TokenExpiredError(new Date(payload.exp * 1000));
    }

    if (typeof payload.nbf === "number" && payload.nbf > now) {
      throw new TokenNotActiveError(new Date(payload.nbf * 1000));
    }

    return payload;
  }
}
