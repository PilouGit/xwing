package io.github.pilougit.security.crypto.xwing.jce

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KEMSpi

class XWingKEMSpi : KEMSpi {

    override fun engineNewEncapsulator(
        publicKey: PublicKey,
        spec: AlgorithmParameterSpec?,
        secureRandom: SecureRandom?
    ): KEMSpi.EncapsulatorSpi {
        if (spec != null) {
            throw InvalidAlgorithmParameterException("X-Wing does not accept algorithm parameters")
        }
        if (publicKey !is XWingPublicKey) {
            throw InvalidKeyException("Expected XWingPublicKey, got ${publicKey.javaClass.name}")
        }
        return XWingEncapsulatorSpi(publicKey.encoded, secureRandom)
    }

    override fun engineNewDecapsulator(
        privateKey: PrivateKey,
        spec: AlgorithmParameterSpec?
    ): KEMSpi.DecapsulatorSpi {
        if (spec != null) {
            throw InvalidAlgorithmParameterException("X-Wing does not accept algorithm parameters")
        }
        if (privateKey !is XWingPrivateKey) {
            throw InvalidKeyException("Expected XWingPrivateKey, got ${privateKey.javaClass.name}")
        }
        return XWingDecapsulatorSpi(privateKey.encoded)
    }
}
