# TECTO

**Transport Encrypted Compact Token Object**

An ultra-secure, opaque token protocol powered by **XChaCha20-Poly1305** authenticated encryption. Unlike JWTs, TECTO tokens are fully encrypted — their contents are mathematically unreadable without the 32-byte secret key.

## Why Not JWT?

| Property | JWT | TECTO |
|---|---|---|
| **Payload visibility** | Base64-encoded (readable by anyone) | Fully encrypted (opaque noise) |
| **Cipher** | None (signed, not encrypted) | XChaCha20-Poly1305 (AEAD) |
| **Nonce** | N/A | 24-byte CSPRNG per token |
| **Key size** | Variable | Exactly 256-bit (enforced) |
| **Tamper detection** | HMAC/RSA signature | Poly1305 authentication tag |
| **Error specificity** | Reveals failure reason | Generic "Invalid token" (prevents oracles) |

## Installation

```bash
bun add tecto
```

## Quick Start

```ts
import {
  generateSecureKey,
  MemoryKeyStore,
  TectoCoder,
} from "tecto";

// 1. Generate a 256-bit key
const key = generateSecureKey();

// 2. Set up the key store
const store = new MemoryKeyStore();
store.addKey("my-key-2026", key);

// 3. Create a coder (with optional custom maxPayloadSize)
const coder = new TectoCoder(store);
// or with custom config: new TectoCoder(store, { maxPayloadSize: 10 * 1024 * 1024 })

// 4. Encrypt a payload
const token = coder.encrypt(
  { userId: 42, role: "admin" },
  { expiresIn: "1h", issuer: "my-app" }
);

console.log(token);
// → tecto.v1.my-key-2026.base64url_nonce.base64url_ciphertext

// 5. Decrypt it
const payload = coder.decrypt(token);
console.log(payload.userId); // 42
```

## Token Format

```
tecto.v1.<kid>.<nonce>.<ciphertext>
```

| Segment | Description |
|---|---|
| `tecto` | Protocol identifier |
| `v1` | Protocol version |
| `<kid>` | Key identifier (for key rotation) |
| `<nonce>` | 24-byte Base64URL-encoded CSPRNG nonce |
| `<ciphertext>` | Base64URL-encoded XChaCha20-Poly1305 ciphertext + auth tag |

## API Reference

### Security Utilities

#### `generateSecureKey(): Uint8Array`

Generates a 32-byte cryptographically random key using the platform CSPRNG.

#### `constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean`

Constant-time byte comparison. Prevents timing side-channel attacks when comparing secrets.

#### `assertEntropy(key: Uint8Array): void`

Validates a key has sufficient entropy. Rejects all-zeros, repeating bytes, and keys with fewer than 8 unique byte values.

### `KeyStoreAdapter` (Interface)

The contract for all key store implementations. `TectoCoder` accepts any `KeyStoreAdapter`.

```ts
interface KeyStoreAdapter {
  addKey(id: string, secret: Uint8Array): void | Promise<void>;
  getKey(id: string): Uint8Array;
  rotate(newId: string, newSecret: Uint8Array): void | Promise<void>;
  removeKey(id: string): void | Promise<void>;
  getCurrentKeyId(): string;
  readonly size: number;
}
```

### `MemoryKeyStore`

Built-in adapter. Keys live in memory and are lost on restart.

```ts
const store = new MemoryKeyStore();
store.addKey("key-id", key);           // Add a key (first key becomes current)
store.getKey("key-id");                // Retrieve by ID
store.rotate("new-key-id", newKey);    // Add new key + set as current
store.removeKey("old-key-id");         // Revoke and zero memory
store.getCurrentKeyId();               // Get current key ID
```

### Custom Adapter

Implement `KeyStoreAdapter` to use any storage backend:

```ts
import { MemoryKeyStore, assertEntropy } from "tecto";
import type { KeyStoreAdapter } from "tecto";

class MyDatabaseKeyStore implements KeyStoreAdapter {
  private mem = new MemoryKeyStore();

  addKey(id: string, secret: Uint8Array): void {
    assertEntropy(secret);
    this.mem.addKey(id, secret);
    // persist to your DB here
  }

  getKey(id: string): Uint8Array { return this.mem.getKey(id); }
  rotate(newId: string, s: Uint8Array): void { this.mem.rotate(newId, s); }
  removeKey(id: string): void { this.mem.removeKey(id); }
  getCurrentKeyId(): string { return this.mem.getCurrentKeyId(); }
  get size(): number { return this.mem.size; }
}
```

### `TectoCoder`

```ts
const coder = new TectoCoder(store, options?); // any KeyStoreAdapter + optional config

// Encrypt
const token = coder.encrypt(payload, signOptions?);

// Decrypt
const payload = coder.decrypt<MyType>(token);
```

#### `TectoCoderOptions`

Configuration for the `TectoCoder` instance:

| Option | Type | Default | Description |
|---|---|---|---|
| `maxPayloadSize` | `number` | `1048576` (1 MB) | Maximum encrypted payload size in bytes. Prevents DoS via oversized tokens. |

```ts
// Custom 10 MB limit
const coder = new TectoCoder(store, { maxPayloadSize: 10 * 1024 * 1024 });
```

#### `SignOptions`

Options for individual token encryption:

| Option | Type | Default | Description |
|---|---|---|---|
| `expiresIn` | `string` | undefined | Duration string: `"1h"`, `"30m"`, `"7d"`, `"120s"`. If omitted, token never expires. |
| `issuer` | `string` | undefined | Sets the `iss` claim |
| `audience` | `string` | undefined | Sets the `aud` claim |
| `jti` | `string` | auto-generated | Custom token ID (128-bit random UUID if omitted) |
| `notBefore` | `string` | undefined | Duration string for `nbf` delay (token valid after N duration from `iat`) |

```ts
// Token that expires in 1 hour
coder.encrypt({ userId: 42 }, { expiresIn: "1h" });

// Token that never expires
coder.encrypt({ userId: 42 });

// Token that's valid 5 minutes from now
coder.encrypt({ userId: 42 }, { notBefore: "5m", expiresIn: "1h" });
```

### Error Classes

| Error | Code | When |
|---|---|---|
| `TectoError` | `TECTO_*` | Base class for all errors |
| `TokenExpiredError` | `TECTO_TOKEN_EXPIRED` | `exp` claim is in the past |
| `TokenNotActiveError` | `TECTO_TOKEN_NOT_ACTIVE` | `nbf` claim is in the future |
| `InvalidSignatureError` | `TECTO_INVALID_TOKEN` | Any decryption/auth failure (generic) |
| `KeyError` | `TECTO_KEY_ERROR` | Invalid or missing key |

## Security Properties

### Core Guarantees

- **Opacity:** Tokens are encrypted, not just signed. Without the key, the payload is indistinguishable from random noise.
- **Authenticated Encryption:** Poly1305 tag ensures integrity. Any modification to the ciphertext, nonce, or key ID causes immediate rejection.
- **Generic Errors:** All decryption failures produce the same `InvalidSignatureError` to prevent padding/authentication oracles.
- **Entropy Enforcement:** Keys are validated for length (32 bytes), non-zero, non-repeating, and minimum byte diversity.
- **Timing-Safe Comparison:** `constantTimeCompare()` prevents timing side-channels when comparing secrets.
- **Type Validation:** Registered claims (`exp`, `nbf`, `iat`, `jti`, `iss`, `aud`) are type-checked during deserialization to prevent type confusion attacks.
- **Payload Size Limits:** Configurable maximum payload size (default 1 MB) prevents DoS via oversized tokens.
- **Plaintext Cleanup:** Plaintext buffers are zeroed after encryption/decryption (best-effort).
- **Key Cloning:** `getKey()` returns defensive clones to prevent accidental mutation of stored keys.

### Nonce Collision Bounds

Every `encrypt()` call generates a fresh 24-byte nonce from CSPRNG. XChaCha20's 192-bit nonce space provides:

- **Birthday bound:** ~2^96 messages per key before collision becomes statistically likely
- **Recommendation:** Rotate keys before ~1 billion encryptions or at least daily (whichever comes first)
- Without rotation, nonce collision risk increases significantly after exceeding the birthday bound

### JTI & Replay Protection

The `jti` claim provides **detection**, not **prevention**, of token replay:

- Generated as 128-bit random UUID (~2^64 collision birthday bound)
- For robust replay protection, implement a separate blacklist/allowlist mechanism
- Track JTI values within the token's expiration window (`exp - iat`)

## Key Rotation

```ts
store.addKey("key-2026-01", key1);
// ... time passes ...
store.rotate("key-2026-06", key2);

// New tokens use key-2026-06, old tokens still decrypt via key-2026-01
store.removeKey("key-2026-01"); // after all old tokens expire
```

## Testing

```bash
bun test
```

## Examples

Each example implements `KeyStoreAdapter` with a different storage backend.

### Memory (Default)

```bash
bun run examples/memory/index.ts
```

### SQLite

```bash
bun run examples/sqlite/index.ts
```

### MariaDB / MySQL

```bash
bun add mysql2
bun run examples/mariadb/index.ts
```

### PostgreSQL

```bash
bun add pg @types/pg
bun run examples/postgres/index.ts
```

### Architecture

All adapters follow the same pattern — compose a `MemoryKeyStore` internally for runtime lookups and sync writes to your database:

```
┌──────────┐   load    ┌────────────────┐   encrypt/decrypt   ┌────────────┐
│ Database │ ───────→  │ KeyStoreAdapter│ ←────────────────→  │ TectoCoder │
│ (persist)│ ←───────  │   (runtime)    │                     │            │
└──────────┘   save    └────────────────┘                     └────────────┘
```

## License

MIT

