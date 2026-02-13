package io.github.pilougit.security.crypto.xwing.jce

import java.security.PublicKey

class XWingPublicKey(private val pk: ByteArray) : PublicKey {

    init {
        require(pk.size == 1216) { "X-Wing public key must be 1216 bytes, got ${pk.size}" }
    }

    override fun getAlgorithm(): String = "X-Wing"

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray = pk.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is XWingPublicKey) return false
        return pk.contentEquals(other.pk)
    }

    override fun hashCode(): Int = pk.contentHashCode()
}
