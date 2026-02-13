package io.github.pilougit.security.crypto.xwing.jce

import io.github.pilougit.security.crypto.xwing.XWing
import javax.crypto.KEMSpi
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class XWingDecapsulatorSpi(
    private val sk: ByteArray
) : KEMSpi.DecapsulatorSpi {

    override fun engineSecretSize(): Int = 32

    override fun engineEncapsulationSize(): Int = 1120

    override fun engineDecapsulate(encapsulation: ByteArray, from: Int, to: Int, algorithm: String?): SecretKey {
        require(encapsulation.size == 1120) {
            "X-Wing ciphertext must be 1120 bytes, got ${encapsulation.size}"
        }
        val ss = XWing.decapsulate(encapsulation, sk)
        val algo = algorithm ?: "Generic"
        return SecretKeySpec(ss, from, to - from, algo)
    }
}
