package io.github.pilougit.security.crypto.xwing.primitive

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.prng.FixedSecureRandom
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom
/**
 * SHAKE256(message, outlen): The extendable-output function (XOF)
 *          with that name defined in Section 6.2 of [FIPS202].  Note that
 *          outlen counts bits.
 */
object Primitives {
    private val XWingLabel = byteArrayOf(
        '\\'.code.toByte(),
        '.'.code.toByte(),
        '/'.code.toByte(),
        '/'.code.toByte(),
        '^'.code.toByte(),
        '\\'.code.toByte()
    )
    val X25519_BASE: ByteArray = ByteArray(32).apply {
        this[0] = 0x09
    }
    fun combiner(
        ssM: ByteArray,
        ssX: ByteArray,
        ctX: ByteArray,
        pkX: ByteArray
    ): ByteArray {

        val digest = MessageDigest.getInstance("SHA3-256")

        digest.update(ssM)
        digest.update(ssX)
        digest.update(ctX)
        digest.update(pkX)
        digest.update(XWingLabel)

        return digest.digest()
    }
    fun mlkem768Encaps(
        pkM: ByteArray,
        random: SecureRandom = SecureRandom()
    ): SecretWithEncapsulation {

        val publicKey = MLKEMPublicKeyParameters(
            MLKEMParameters.ml_kem_768,
            pkM
        )

        val generator = MLKEMGenerator(random)

        val secretWithEncapsulation: SecretWithEncapsulation =
            generator.generateEncapsulated(publicKey)


        return secretWithEncapsulation
    }
    fun mlkem768Decap(
        ctM: ByteArray,
        skM: ByteArray
    ): ByteArray {

        val privateKey = MLKEMPrivateKeyParameters(
            MLKEMParameters.ml_kem_768,
            skM
        )

        val extractor = MLKEMExtractor(privateKey)

        return extractor.extractSecret(ctM)
    }
     fun shake256(input: ByteArray, outputLength: Int): ByteArray {
        val shake = SHAKEDigest(256)
        shake.update(input, 0, input.size)
        val output = ByteArray(outputLength)
        shake.doFinal(output, 0, outputLength)
        return output
    }
    fun x25519(k: ByteArray, u:ByteArray): ByteArray {

       val result = ByteArray(32)

        X25519.scalarMult(
            k, 0,
            u, 0,
            result, 0
        )
        return result
    }

    /**
     * Send back HKDF (d||z)
     */
    fun deriveSeed(d: ByteArray, z: ByteArray): ByteArray {

        val input = ByteArray(64)
        System.arraycopy(d, 0, input, 0, 32)
        System.arraycopy(z, 0, input, 32, 32)

        val hkdf =
            HKDFBytesGenerator(SHA256Digest())

        hkdf.init(HKDFParameters(input, null, "MLKEM".toByteArray()))

        val seed = ByteArray(64)
        hkdf.generateBytes(seed, 0, seed.size)

        return seed
    }
    fun keyGen(d: ByteArray, z: ByteArray, useDerivedSeed: Boolean = false): AsymmetricCipherKeyPair {

        val seed = if (useDerivedSeed) deriveSeed(d, z) else d + z
        val deterministicRandom =
            FixedSecureRandom(seed)

        val gen = MLKEMKeyPairGenerator()

        gen.init(
            MLKEMKeyGenerationParameters(
                deterministicRandom,
                MLKEMParameters.ml_kem_768
            )
        )

        return gen.generateKeyPair()
    }
}