package io.github.pilougit.security.crypto.xwing.primitive

import org.bouncycastle.crypto.digests.SHAKEDigest

/**
 * SHAKE256(message, outlen): The extendable-output function (XOF)
 *          with that name defined in Section 6.2 of [FIPS202].  Note that
 *          outlen counts bits.
 */
object Shake256 {
    private fun shake256(input: ByteArray, outputLength: Int): ByteArray {
        val shake: SHAKEDigest = SHAKEDigest(256)
        shake.update(input, 0, input.size)
        val output = ByteArray(outputLength)
        shake.doFinal(output, 0, outputLength)
        return output
    }
}