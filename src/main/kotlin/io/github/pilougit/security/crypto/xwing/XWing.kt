package io.github.pilougit.security.crypto.xwing

import io.github.pilougit.security.crypto.xwing.primitive.Primitives
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

object XWing {

    /**
     * def expandDecapsulationKey(sk):
     *   expanded = SHAKE256(sk, 96*8) # expand sk to 96 bytes using SHAKE256
     *   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
     *   sk_X = expanded[64:96]
     *   pk_X = X25519(sk_X, X25519_BASE)
     *   return (sk_M, sk_X, pk_M, pk_X)
     */
    fun expandDecapsulationKey(sk:ByteArray): ExpandedDecapsulationKey {
        val expanded=Primitives.shake256(sk,96)
        val asymmetricKeyPair=Primitives.keyGen(expanded.copyOfRange(0, 32),
            expanded.copyOfRange(32, 64))
        val skX = expanded.copyOfRange(64,96)

        val pkX = Primitives.x25519(skX, Primitives.X25519_BASE)
        val pkM = asymmetricKeyPair.public as MLKEMPublicKeyParameters
        val skM = asymmetricKeyPair.private as MLKEMPrivateKeyParameters

        return ExpandedDecapsulationKey(skM.encoded,
            skX, pkM.encoded,pkX)
    }
    /**
     * def GenerateKeyPair():
     *   sk = random(32)
     *   (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
     *   return sk, concat(pk_M, pk_X)
     */
    fun generateKeyPair(): XWingKeyPair {
        val secureRandom= SecureRandom.getInstanceStrong()
        val sk= ByteArray(32);
        secureRandom.nextBytes(sk);
        val expandedDecapsulationKey=expandDecapsulationKey(sk);
        return XWingKeyPair(sk,expandedDecapsulationKey.pkM+expandedDecapsulationKey.pkX));


    }
}