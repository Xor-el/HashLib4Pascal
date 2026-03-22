# HashLib4Pascal

[![Build Status](https://github.com/Xor-el/HashLib4Pascal/actions/workflows/make.yml/badge.svg)](https://github.com/Xor-el/HashLib4Pascal/actions/workflows/make.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Xor-el/HashLib4Pascal/blob/master/LICENSE)
[![Delphi](https://img.shields.io/badge/Delphi-2010%2B-red.svg)](https://www.embarcadero.com/products/delphi)
[![FreePascal](https://img.shields.io/badge/FreePascal-3.2.2%2B-blue.svg)](https://www.freepascal.org/)

HashLib4Pascal is a comprehensive hashing library for Object Pascal, providing an easy-to-use interface for computing hashes, checksums, MACs, KDFs, and XOFs with support for state-based (incremental) hashing, released under the permissive [MIT License](LICENSE).

## Table of Contents

- [Features](#features)
- [Available Algorithms](#available-algorithms)
- [Getting Started](#getting-started)
- [Quick Examples](#quick-examples)
- [Running Tests](#running-tests)
- [Contributing](#contributing)
- [Other Implementations](#other-implementations)
- [Tip Jar](#tip-jar)
- [License](#license)

## Features

- **Extensive hash coverage** -- CRC (all standard variants from CRC3 to CRC64), non-cryptographic (Murmur, XXHash, SipHash, etc.), and cryptographic (SHA-2, SHA-3, Blake2, Blake3, and more)
- **State-based (incremental) hashing** -- feed data in chunks via `TransformBytes` / `TransformString`, then finalize with `TransformFinal`
- **One-shot convenience** -- `ComputeString`, `ComputeBytes`, `ComputeFile`, `ComputeStream` for single-call hashing
- **Password hashing / KDFs** -- Argon2 (2i/2d/2id), Scrypt, PBKDF2-HMAC
- **MACs** -- HMAC (all supported hashes), KMAC (128/256), Blake2BMAC, Blake2SMAC
- **Extendable output functions (XOFs)** -- Shake, CShake, Blake2X, KMACXOF, Blake3XOF
- **Cloneable state** -- clone any hash instance mid-computation for parallel/divergent processing
- **Cross-platform** -- Delphi and FreePascal on Windows, Linux, macOS, and more

## Available Algorithms

<details>
<summary>Checksums</summary>

#### CRC
`All CRC variants from CRC3 to CRC64`

#### Other
`Adler32`

</details>

<details>
<summary>Non-Cryptographic Hash Functions</summary>

#### 32-bit
`AP` | `BKDR` | `Bernstein` | `Bernstein1` | `DEK` | `DJB` | `ELF` | `FNV` | `FNV1a` | `Jenkins3` | `JS` | `Murmur2` | `MurmurHash3_x86_32` | `OneAtTime` | `PJW` | `Rotating` | `RS` | `SDBM` | `ShiftAndXor` | `SuperFast` | `XXHash32`

#### 64-bit
`FNV64` | `FNV1a64` | `Murmur2_64` | `SipHash2_4` | `XXHash64`

#### 128-bit
`SipHash128_2_4` | `MurmurHash3_x86_128` | `MurmurHash3_x64_128`

</details>

<details>
<summary>Cryptographic Hash Functions</summary>

| Family | Variants |
|---|---|
| MD | MD2, MD4, MD5 |
| SHA-0 | SHA-0 |
| SHA-1 | SHA-1 |
| SHA-2 | 224, 256, 384, 512, 512-224, 512-256 |
| SHA-3 | 224, 256, 384, 512 |
| Keccak | 224, 256, 288, 384, 512 |
| Blake2B | 160, 256, 384, 512 |
| Blake2S | 128, 160, 224, 256 |
| Blake2BP | Blake2BP |
| Blake2SP | Blake2SP |
| Blake3 | Blake3 |
| GOST | 34.11-94, R 34.11-2012 (256, 512) |
| Grindahl | 256, 512 |
| HAS160 | HAS160 |
| RIPEMD | 128, 160, 256, 320 |
| Tiger | 128, 160, 192 (Rounds 3, 4, 5) |
| Tiger2 | 128, 160, 192 (Rounds 3, 4, 5) |
| Snefru | 128, 256 |
| Haval | 128, 160, 192, 224, 256 (Rounds 3, 4, 5) |
| Panama | Panama |
| RadioGatun | RadioGatun32, RadioGatun64 |
| WhirlPool | WhirlPool |

</details>

<details>
<summary>Key Derivation Functions</summary>

#### Password Hashing
`PBKDF2-HMAC` | `Argon2 (2i, 2d, 2id)` | `Scrypt`

</details>

<details>
<summary>MACs</summary>

`HMAC (all supported hashes)` | `KMAC (128, 256)` | `Blake2BMAC` | `Blake2SMAC`

</details>

<details>
<summary>XOF (Extendable Output Functions)</summary>

`Shake (128, 256)` | `CShake (128, 256)` | `Blake2XS` | `Blake2XB` | `KMAC128XOF` | `KMAC256XOF` | `Blake3XOF`

</details>

## Getting Started

### Prerequisites

| Compiler | Minimum Version |
|---|---|
| Delphi | 2010 or later |
| FreePascal | 3.2.2 or later |

### Installation

#### Delphi

1. Open and install the package: `HashLib/src/Packages/Delphi/HashLib4PascalPackage.dpk`
2. Add the `HashLib/src` subdirectories to your project's search path.

#### FreePascal / Lazarus

1. Open and install the package: `HashLib/src/Packages/FPC/HashLib4PascalPackage.lpk`

## Quick Examples

### SHA-256 Hash

```pascal
uses
  SysUtils, HlpHashFactory;

var
  LHash: String;
begin
  LHash := THashFactory.TCrypto.CreateSHA2_256()
    .ComputeString('Hello HashLib4Pascal', TEncoding.UTF8)
    .ToString();

  WriteLn(LHash);
end;
```

### Incremental (Streaming) Hash

```pascal
uses
  SysUtils, HlpIHash, HlpHashFactory;

var
  LHashInstance: IHash;
begin
  LHashInstance := THashFactory.TCrypto.CreateBlake2B_256();
  LHashInstance.Initialize();

  LHashInstance.TransformString('chunk one', TEncoding.UTF8);
  LHashInstance.TransformString('chunk two', TEncoding.UTF8);
  LHashInstance.TransformString('chunk three', TEncoding.UTF8);

  WriteLn(LHashInstance.TransformFinal().ToString());
end;
```

### HMAC

```pascal
uses
  SysUtils, HlpIHashInfo, HlpHashFactory, HlpConverters;

var
  LHMAC: IHMAC;
begin
  LHMAC := THashFactory.THMAC.CreateHMAC(
    THashFactory.TCrypto.CreateSHA2_256(),
    TConverters.ConvertStringToBytes('secret key', TEncoding.UTF8));

  WriteLn(LHMAC.ComputeString('message', TEncoding.UTF8).ToString());
end;
```

### Scrypt KDF

```pascal
uses
  SysUtils, HlpHashFactory, HlpConverters;

var
  LDerivedKey: TBytes;
begin
  LDerivedKey := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(
    TConverters.ConvertStringToBytes('password', TEncoding.UTF8),
    TConverters.ConvertStringToBytes('salt', TEncoding.UTF8),
    1024, 8, 1)
    .GetBytes(32);

  WriteLn(TConverters.ConvertBytesToHexString(LDerivedKey));
end;
```

## Running Tests

Tests use **DUnit** (Delphi) and **FPCUnit** (FreePascal).

- **Delphi:** Open `HashLib.Tests/Delphi.Tests/HashLib.Tests.dpr` in the IDE and run.
- **FreePascal / Lazarus:** Open `HashLib.Tests/FreePascal.Tests/HashLib.Tests.lpi` in the IDE and run.

## Contributing

Contributions are welcome. Please open an [issue](https://github.com/Xor-el/HashLib4Pascal/issues) for bug reports or feature requests, and submit pull requests.

## Other Implementations

If you want implementations in other languages, you can check out these:

- [HashLib4CPP](https://github.com/ron4fun/HashLib4CPP) by Mbadiwe Nnaemeka Ronald

## Tip Jar

If you find this library useful and would like to support its continued development, tips are greatly appreciated! 🙏

| Cryptocurrency | Wallet Address |
|---|---|
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/btc.png" width="20" alt="Bitcoin" /> **Bitcoin (BTC)** | `bc1quqhe342vw4ml909g334w9ygade64szqupqulmu` |
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/eth.png" width="20" alt="Ethereum" /> **Ethereum (ETH)** | `0x53651185b7467c27facab542da5868bfebe2bb69` |
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/sol.png" width="20" alt="Solana" /> **Solana (SOL)** | `BPZHjY1eYCdQjLecumvrTJRi5TXj3Yz1vAWcmyEB9Miu` |

## License

HashLib4Pascal is released under the [MIT License](LICENSE).
