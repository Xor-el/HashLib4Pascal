# HashLib Test Data

External test vectors for HashLib4Pascal unit tests.

Cryptographic test corpora — especially multi-megabyte BLAKE2 known-answer JSON and
extensible KDF CSV tables — are kept here as data files rather than embedded in Pascal
source. Vector sets will continue to grow as more algorithms and standards land; keeping
them outside the codebase keeps the library and test sources readable, avoids bloating
builds with megabytes of string literals, and lets fixtures be updated or extended
without recompiling test code.

This folder holds the files the test suite loads at runtime (JSON KAT corpora, CSV test
vectors, and related fixtures). Layout and formats are documented below.

## Layout

All folders and files use **PascalCase** names.

```
Data/
└── Crypto/     Algorithm vectors (JSON, CSV)
```

### `Crypto/` subfolders

| Folder | Contents |
|--------|----------|
| `Blake2`, `Blake3` | Hash KAT JSON vectors |
| `Scrypt`, `Argon2`, `Pbkdf2` | Password-based KDF vectors |

## Vector formats

### Hash

| Path | Format |
|------|--------|
| `Crypto/Blake2/blake2-kat.json` | BLAKE2 KAT JSON: `[{hash,in,key,out},…]` |
| `Crypto/Blake3/test_vectors.json` | BLAKE3 test vectors: `{"cases":[{input_len,hash,keyed_hash,derive_key},…]}` |

### KDF, digest, and MAC

| Path | Format |
|------|--------|
| `Crypto/Scrypt/TestVectors.csv` | RFC 7914: `Enabled,Password,Salt,Cost,BlockSize,Parallelism,OutputLenBytes,ExpectedHex` |
| `Crypto/Argon2/TestVectors.csv` | Argon2 test vectors |
| `Crypto/Pbkdf2/TestVectors.csv` | RFC 6070-style: `Algorithm,PasswordHex,SaltHex,Iterations,OutputLenBytes,ExpectedHex` |
