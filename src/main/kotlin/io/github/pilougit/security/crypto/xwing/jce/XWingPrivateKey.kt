package io.github.pilougit.security.crypto.xwing.jce

import java.security.PrivateKey

class XWingPrivateKey(private val sk: ByteArray) : PrivateKey {

    init {
        require(sk.size == 32) { "X-Wing private key (seed) must be 32 bytes, got ${sk.size}" }
    }

    override fun getAlgorithm(): String = "X-Wing"

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray = sk.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is XWingPrivateKey) return false
        return sk.contentEquals(other.sk)
    }

    override fun hashCode(): Int = sk.contentHashCode()
}
