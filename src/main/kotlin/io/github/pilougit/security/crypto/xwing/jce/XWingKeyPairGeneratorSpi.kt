package io.github.pilougit.security.crypto.xwing.jce

import io.github.pilougit.security.crypto.xwing.XWing
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPair
import java.security.KeyPairGeneratorSpi
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec

class XWingKeyPairGeneratorSpi : KeyPairGeneratorSpi() {

    private var secureRandom: SecureRandom? = null
    private var useDerivedSeed: Boolean = false

    override fun initialize(keysize: Int, random: SecureRandom) {
        this.secureRandom = random
    }

    override fun initialize(params: AlgorithmParameterSpec, random: SecureRandom) {
        if (params !is XWingParameterSpec) {
            throw InvalidAlgorithmParameterException(
                "Expected XWingParameterSpec, got ${params.javaClass.name}"
            )
        }
        this.useDerivedSeed = params.useDerivedSeed
        this.secureRandom = random
    }

    override fun generateKeyPair(): KeyPair {
        val random = secureRandom ?: SecureRandom.getInstanceStrong()
        val seed = ByteArray(32)
        random.nextBytes(seed)
        val kp = XWing.generateKeyPairDerand(seed, useDerivedSeed)
        return KeyPair(XWingPublicKey(kp.pk), XWingPrivateKey(kp.sk))
    }
}
