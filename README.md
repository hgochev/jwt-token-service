# JWT Token Service

## JWKS Fields (RFC 7517)

| Field | Full name | Value | Meaning |
|---|---|---|---|
| `kty` | Key Type | `"RSA"` | The cryptographic family — RSA in this case |
| `use` | Public Key Use | `"sig"` | What the key is for — `sig` (signing) or `enc` (encryption) |
| `kid` | Key ID | `"development-key-1"` | A label to identify this specific key, matched against the `kid` in the JWT header |
| `alg` | Algorithm | `"RS256"` | The exact algorithm — RSA with SHA-256 |
| `n` | Modulus | base64url bytes | The RSA public key modulus (2048-bit) |
| `e` | Exponent | base64url bytes | The RSA public exponent (typically 65537) |

`n` and `e` together fully define the RSA public key. A verifier decodes these two values and uses them to check the token signature.
