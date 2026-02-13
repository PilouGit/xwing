# X-Wing KEM

Implementation of the [X-Wing](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html) hybrid Key Encapsulation Mechanism (KEM) in Kotlin, combining ML-KEM-768 and X25519 for post-quantum/classical hybrid security.

Exposes both a low-level API (`XWing` object) and a standard JCA/JCE integration via `javax.crypto.KEM` (JEP 452, Java 21+).
A pure Kotlin implementation of the X-Wing hybrid post-quantum key encapsulation mechanism, integrated as a JCE (Java Cryptography Extension) Provider.

## Overview
X-Wing is a "general-purpose" hybrid KEM that combines:

* X25519: A classical Elliptic Curve Diffie-Hellman (ECDH) primitive.
* ML-KEM-768: A post-quantum secure KEM (formerly Kyber).

This implementation provides a seamless integration for JVM-based applications through the standard Java Security APIs, ensuring compatibility with existing cryptographic workflows.

## Features

* JCE Provider: Registered via Security.addProvider().
* Hybrid Security: Follows the draft-connolly-cfrg-xwing-kem specifications.
* Kotlin Native: Leverages Kotlin's type safety and modern syntax.
* Standards Compliant: Designed to be compatible with FIPS 203 (ML-KEM) and RFC 7748 (X25519).

## Requirements

- Java 21+
- Kotlin 2.1+
- Bouncy Castle 1.83+

## Installation

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.github.pilougit.security.crypto:xwing:1.0.0-SNAPSHOT")
}
```

## Quick start — JCA/JCE API

```kotlin


// Register the provider
Security.addProvider(XWingProvider())

// Generate a key pair
val kpg = KeyPairGenerator.getInstance("X-Wing")
val kp = kpg.generateKeyPair()

// Encapsulate an AES-256 key
val kem = KEM.getInstance("X-Wing")
val encapsulated = kem.newEncapsulator(kp.public).encapsulate(0, 32, "AES")
val aesKey = encapsulated.key()            // AES-256 SecretKey
val ciphertext = encapsulated.encapsulation() // 1120 bytes to send to the peer

// Decapsulate to recover the same AES-256 key
val decapsulated = kem.newDecapsulator(kp.private)
    .decapsulate(ciphertext, 0, 32, "AES")

// aesKey.encoded == decapsulated.encoded
```

### TLS-like usage with AES-256-GCM

```kotlin
// Server encapsulates using client's public key
val enc = kem.newEncapsulator(clientPublicKey).encapsulate(0, 32, "AES")

// Server encrypts a message
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, enc.key())
val iv = cipher.iv
val encrypted = cipher.doFinal(plaintext)

// Client decapsulates and decrypts
val aesKey = kem.newDecapsulator(clientPrivateKey)
    .decapsulate(enc.encapsulation(), 0, 32, "AES")
cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
val decrypted = cipher.doFinal(encrypted)
```

### Derived seed mode

By default, ML-KEM-768 key generation uses the raw seed (`d || z`). You can opt in to HKDF-based seed derivation via `XWingParameterSpec`:

```kotlin

val kpg = KeyPairGenerator.getInstance("X-Wing")
kpg.initialize(XWingParameterSpec(useDerivedSeed = true))
val kp = kpg.generateKeyPair()
```

## Low-level API

```kotlin

// Key generation
val keyPair = XWing.generateKeyPair()      // keyPair.sk (32 bytes), keyPair.pk (1216 bytes)

// Encapsulation
val result = XWing.encapsulate(keyPair.pk)  // result.secret (32 bytes), result.encapsulation (1120 bytes)

// Decapsulation
val sharedSecret = XWing.decapsulate(result.encapsulation, keyPair.sk)

// Deterministic variants (for testing / reproducibility)
val keyPair2 = XWing.generateKeyPairDerand(seed)           // seed: 32 bytes
val result2 = XWing.encapsulateDeRand(keyPair2.pk, eseed)  // eseed: 64 bytes
```

## Key sizes

| Parameter | Size (bytes) |
|---|---|
| Private key (seed) | 32 |
| Public key | 1216 |
| Ciphertext | 1120 |
| Shared secret | 32 |

## Testing

```bash
./gradlew test
```

Tests include:
- Deterministic key generation, encapsulation, and decapsulation against [draft test vectors](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html)
- Round-trip encapsulate/decapsulate
- JCA/JCE integration (KeyPairGenerator, KEM)
- TLS-like handshake with AES-256-GCM encryption/decryption

