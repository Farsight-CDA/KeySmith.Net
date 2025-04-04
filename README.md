# Keysmith.Net

Modern .NET9 library implementing common cryptographic standards used by various cryptocurrencies like BIP32/SLIP10, BIP39 and BIP44.

The intention of this library is to provide minimal no boilerplate implemenations of these cryptographic primitives while maintaining the best possible performance using the latest language features.

## Installation

### Base Package: `Keysmith.Net`

The base package is always required.

### Optional curve packages:

Installing a curve package will provide a singleton instance of that specific curve to be used in SLIP10 derivations.

#### `Keysmith.Net.Secp256k1`

Requires the [secp256k1 c library](https://github.com/bitcoin-core/secp256k1) in the same directory as your binary to work.
Consider building it from source or installing the `Secp256k1.Native` package which bundles it for you.

#### `Keysmith.Net.ED25519`

Uses [NSec](https://nsec.rocks/) behind the scenes for curve math which is also MIT licensed.

## Features

### BIP39

Converts mnemonic words to the seed used for deriving private keys.

> [!NOTE]  
> Only supports the english wordlist.

#### Usage

```cs
byte[] seed = BIP39.MnemonicToSeed("[mnemonics]");
//Or using spans
Span<byte> seed = stackalloc byte[256];
BIP39.TryMnemonicToSeed(seed, "[mnemonics]")
```

#### Performance

<img src="./img/bip39_bench.png" />

### BIP32/SLIP10

Takes the seed calculated using BIP39 and derives the master private key and child keys using BIP44 derivation paths.

#### Usage

```cs
(byte[] key, byte[] chainCode) = Slip10.DerivePath(
    Secp256k1.Instance,
    seed,
    "m/44'/60'/0'/0/0"
);
//Or using spans
Span<byte> key = stackalloc byte[32];
Span<byte> chainCode = stackalloc byte[32];
Span<uint> path = stackalloc uint[5];
BIP44.Ethereum(path);
Slip10.TryDerivePath(
    Secp256k1.Instance,
    seed,
    key,
    chainCode,
    path
);
```

#### Performance

<img src="./img/slip10_bench.png" />

### BIP44

Defines the format for derivation paths used for Bitcoin and a lot of other chains following the same spec.

This library defines helper methods to construct these paths to be used for BIP32 derivation.

#### Usage

```cs
string path = BIP44.Ethereum(5);
//     ^ "m/44'/60'/0'/0/5"
// Or using spans
Span<uint> path = stackalloc uint[5];
BIP44.Ethereum(path, 5);
```
