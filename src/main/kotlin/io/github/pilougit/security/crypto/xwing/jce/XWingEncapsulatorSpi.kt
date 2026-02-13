package io.github.pilougit.security.crypto.xwing.jce

import io.github.pilougit.security.crypto.xwing.XWing
import java.security.SecureRandom
import javax.crypto.KEM
import javax.crypto.KEMSpi
import javax.crypto.spec.SecretKeySpec

class XWingEncapsulatorSpi(
    private val pk: ByteArray,
    private val secureRandom: SecureRandom?
) : KEMSpi.EncapsulatorSpi {

    override fun engineSecretSize(): Int = 32

    override fun engineEncapsulationSize(): Int = 1120

    override fun engineEncapsulate(from: Int, to: Int, algorithm: String?): KEM.Encapsulated {
        val random = secureRandom ?: SecureRandom.getInstanceStrong()
        val eseed = ByteArray(64)
        random.nextBytes(eseed)
        val result = XWing.encapsulateDeRand(pk, eseed)
        val algo = algorithm ?: "Generic"
        return KEM.Encapsulated(
            SecretKeySpec(result.secret, from, to - from, algo),
            result.encapsulation,
            null
        )
    }
}
